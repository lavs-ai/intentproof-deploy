# IntentProof staging control

Public deployment templates only. Application and sample repositories remain private.

This workflow runs only on manual dispatch and requires a signed, unexpired IntentProof approval before Docker mutation. Configure a protected staging environment, protected main branch, separate reviewer, and dedicated Linux runner before use. No public pull-request execution is configured. Do not commit secrets or customer code.

Provisioning is incomplete until host, OIDC identities, signing/registry credentials and required reviewer are configured. No deployment has been run.
