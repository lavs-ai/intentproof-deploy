"""Trusted Linux staging runner. A signed approval is required before Docker mutation."""

import fcntl
import hashlib
import json
import os
import re
import subprocess  # nosec B404

# Only fixed Docker commands with signed allowlisted images; no shell/model commands.
import time
from pathlib import Path
from urllib.parse import urlparse, quote
import shutil
import httpx

import jwt


def github(path):
    with httpx.stream(
        "GET",
        "https://api.github.com" + path,
        timeout=10,
        follow_redirects=False,
        headers={
            "Authorization": "Bearer " + os.environ["IP_EVIDENCE_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    ) as response:
        if response.status_code != 200:
            raise ValueError("GitHub metadata unavailable")
        raw = bytearray()
        for chunk in response.iter_bytes():
            raw.extend(chunk)
            if len(raw) > 1024 * 1024:
                raise ValueError("GitHub response limit")
        return json.loads(raw)


def evidence(repository, sha, provenance, workflow, required_jobs, artifacts):
    root = "/repos/" + repository
    run = github(f"{root}/actions/runs/{provenance['run_id']}")
    if (
        run["head_sha"] != sha
        or run["run_attempt"] != provenance["attempt"]
        or run["status"] != "completed"
        or run["conclusion"] != "success"
    ):
        raise ValueError("Evidence changed")
    runs = github(
        f"{root}/actions/workflows/{workflow}/runs?head_sha={sha}&event=push&per_page=100"
    )["workflow_runs"]
    if (
        max((r["id"] for r in runs if r["head_sha"] == sha and r["event"] == "push"), default=0)
        != run["id"]
    ):
        raise ValueError("Evidence superseded")
    jobs = github(f"{root}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
    for name in required_jobs:
        selected = [j for j in jobs if j["name"] == name]
        if len(selected) != 1 or selected[0]["conclusion"] != "success":
            raise ValueError("Required verification failed")
    for item in artifacts:
        a = github(f"{root}/actions/artifacts/{item['artifact_id']}")
        if (
            a["expired"]
            or a["digest"] != item["archive_digest"]
            or a["workflow_run"]["id"] != run["id"]
            or a["workflow_run"]["head_sha"] != sha
        ):
            raise ValueError("Artifact changed or unavailable")


def docker(*args, check=True):
    # Docker argv comes from trusted code; digest/name/port are validated before execution.
    result = subprocess.run(
        [shutil.which("docker") or "/usr/bin/docker", *args],
        capture_output=True,
        timeout=120,
        check=False,
    )  # nosec B603
    if check and result.returncode:
        raise ValueError("Docker operation failed")
    return result


def healthy(url, sha):
    target = urlparse(url)
    if target.scheme != "https" or not target.hostname or target.username or target.password:
        return False
    try:
        with httpx.stream("GET", url, timeout=5, follow_redirects=False) as response:
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > 8192:
                    return False
            value = json.loads(raw)
            return (
                response.status_code == 200
                and isinstance(value, dict)
                and value.get("status") == "ok"
                and value.get("commit_sha") == sha
            )
    except Exception:
        return False


def main():
    report = {
        "release_id": os.environ["IP_RELEASE_ID"],
        "attempt": int(os.environ["IP_ATTEMPT"]),
        "action": os.environ["IP_ACTION"],
        "applied": False,
        "healthy": False,
    }
    try:
        token = jwt.decode(
            os.environ["IP_AUTHORIZATION"],
            os.environ["IP_PUBLIC_KEY"],
            algorithms=["EdDSA"],
            issuer="intentproof-delivery",
            audience="intentproof-staging",
            options={
                "require": [
                    "exp",
                    "iat",
                    "iss",
                    "aud",
                    "manifest",
                    "release_id",
                    "attempt",
                    "action",
                ]
            },
        )
        if any(token[k] != report[k] for k in ("release_id", "attempt", "action")) or report[
            "action"
        ] not in ("deploy", "rollback"):
            raise ValueError("Attempt binding mismatch")
        if not re.fullmatch(r"[0-9a-f-]{36}", report["release_id"]):
            raise ValueError("Invalid release identity")
        control_repo, control_sha = token["control_repository"], token["control_sha"]
        if (
            control_repo != os.environ["IP_CONTROL_REPOSITORY"]
            or control_sha != os.environ["IP_CONTROL_SHA"]
        ):
            raise ValueError("Control workflow binding mismatch")
        env = github("/repos/" + control_repo + "/environments/" + os.environ["IP_ENVIRONMENT"])
        reviewers = [
            r for r in env.get("protection_rules", []) if r.get("type") == "required_reviewers"
        ]
        if (
            len(reviewers) != 1
            or not reviewers[0].get("reviewers")
            or not reviewers[0].get("prevent_self_review")
            or env.get("can_admins_bypass", True)
            or not env.get("deployment_branch_policy", {}).get("protected_branches")
        ):
            raise ValueError("Environment protection changed")
        repo = github("/repos/" + control_repo)
        branch = github(
            "/repos/" + control_repo + "/branches/" + quote(repo["default_branch"], safe="")
        )
        if not branch.get("protected") or branch["commit"]["sha"] != control_sha:
            raise ValueError("Protected control branch changed")
        manifest = token["manifest"]
        if (
            hashlib.sha256(
                json.dumps(
                    manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
            ).hexdigest()
            != token["manifest_digest"]
        ):
            raise ValueError("Manifest digest mismatch")
        if manifest["environment"] != os.environ["IP_ENVIRONMENT"] or not re.fullmatch(
            r"[a-z][a-z0-9-]{0,39}", manifest["environment"]
        ):
            raise ValueError("Environment binding mismatch")
        selected = manifest if report["action"] == "deploy" else token["previous"]
        image, sha = selected["image"], selected["commit_sha"]
        report.update(image=image, commit_sha=sha)
        if not re.fullmatch(
            r"ghcr.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}", image
        ) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("Immutable image required")
        if report["action"] == "deploy":
            evidence(
                manifest["repository"],
                sha,
                token["ci"],
                "intentproof-evidence.yml",
                ["sample-tests", "sample-security"],
                token["artifacts"],
            )
            evidence(
                manifest["repository"],
                sha,
                token["image_provenance"],
                "intentproof-image.yml",
                ["sample-image"],
                [token["image_provenance"]],
            )
        elif not manifest["automatic_rollback"] or not token["previous"]:
            raise ValueError("Rollback was not preauthorised")
        root = Path(os.environ["IP_STATE_DIR"])
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("Fixed isolated state directory required")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (root / "delivery.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            receipt = root / f"{report['release_id']}-{report['action']}-{report['attempt']}.json"
            if receipt.exists():
                raise ValueError("Attempt already consumed; reconcile instead of rerunning")
            # Re-check expiry after slow evidence collection and lock acquisition.
            if token["exp"] <= time.time():
                raise ValueError("Approval expired before mutation")
            port = int(os.environ["IP_BIND_PORT"])
            if not 1024 <= port <= 65535:
                raise ValueError("Invalid staging port")
            name = "intentproof-" + manifest["environment"]
            current = docker("inspect", name, "--format", "{{.Config.Image}}", check=False)
            expected = (
                token["previous"].get("image", "")
                if report["action"] == "deploy"
                else manifest["image"]
            )
            if current.returncode == 0 and current.stdout.decode().strip() != expected:
                raise ValueError("Host baseline differs from authorised previous release")
            if current.returncode != 0 and report["action"] == "rollback":
                raise ValueError("Ambiguous host state; manual recovery required")
            envfile = os.getenv("IP_RUNTIME_ENV_FILE", "")
            if envfile and not Path(envfile).is_absolute():
                raise ValueError("Runtime environment file must be operator configured")
            receipt.write_text(json.dumps({"consumed": True}))
            docker("pull", image)
            report["applied"] = True  # Any subsequent failure may have changed the running service.
            if current.returncode == 0:
                docker("rm", "--force", name)
            args = [
                "run",
                "-d",
                "--name",
                name,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user=65534:65534",
                "--pids-limit=64",
                "--memory=256m",
                "--cpus=1",
                "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
                "-p",
                f"127.0.0.1:{port}:8080",
            ]
            if envfile:
                args += ["--env-file", envfile]
            docker(*args, image)
            for _ in range(3):
                if healthy(token["health_url"], sha):
                    report["healthy"] = True
                    break
                time.sleep(5)
            receipt.write_text(json.dumps(report))
    except Exception as exc:
        report["error"] = type(exc).__name__  # No tokens, signed URLs or exception bodies in logs.
    print(json.dumps(report))
    return 0 if report["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
