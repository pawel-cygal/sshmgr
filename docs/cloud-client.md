# sshmgr Cloud client

The public `sshmgr` repository contains the local CLI/TUI and its Cloud client.
The hosted API, WebPanel, database, browser authentication and deployment are a
separate service and are not distributed from this repository.

## Trust boundary

`sshmgr` scans and changes SSH access from the operator-controlled machine. The
hosted service receives only an explicitly prepared, validated evidence bundle.
It never receives SSH private keys, passwords, agent sockets, keyring values or
usable host connection credentials.

Human sessions and project runners use separate credentials:

- `sshmgr login` uses a browser-approved device code and stores the resulting
  short-lived human session in the operating-system keyring;
- a project runner token is created in the WebPanel and stored in a separate
  keyring entry;
- profile files contain the service origin, organization/project and keyring
  reference, never the bearer token itself.

Plain HTTP is rejected except for an explicitly enabled literal loopback
address used by local tests. Redirects are disabled so bearer tokens cannot be
forwarded to a different origin.

## Connect the CLI

For a human operator on a fresh installation, authorize the device in a browser.
No runner token or pre-existing profile is required:

```bash
sshmgr login
sshmgr whoami
```

The default service is `https://sshmgr.systeam.pl`. One accessible project is
selected automatically; a terminal offers a numbered choice for multiple
projects (`q` cancels). A new profile is saved only after selection and successful
keyring storage. Accounts without projects must create one in the panel or ask
an administrator for access, then retry.

Use `--profile NAME --endpoint https://cloud.example.com` for a separate service.
Without a terminal, select explicitly with `--organization ORG --project PROJECT`.
`--no-browser` prints the approval link without launching a browser; browser
approval is still required. Use runner credentials for unattended CI.

An existing active profile retains its endpoint and project. You can log in to
a specific existing profile with `sshmgr login --profile production`. Missing
project access produces a warning; the CLI never switches a runner's project
automatically. Human `whoami` remains usable independently of project access.

Shell completion for `login`, `logout` and `whoami` offers flags and existing
Cloud profile names, without loading SSH inventory or accessing the keyring.

For a project runner, copy the one-time token from the WebPanel and create a
profile. The token is read from stdin and stored in the OS keyring:

```bash
printf '%s\n' "$SSHMGR_NEW_CLOUD_TOKEN" | sshmgr cloud login production \
  --endpoint https://cloud.example.com \
  --organization example --project production --token-stdin

sshmgr cloud status --profile production
```

Use `--token-env NAME` for a value already held in an environment variable or
`--token-keyring NAME` to reference an existing keyring entry. Environment
tokens are intended for controlled CI; command-line token arguments are not
supported.

## Audit and synchronize

```bash
sshmgr audit --group production
sshmgr audit show
sshmgr audit push

sshmgr access invite contractor@example.com \
  --group production --account deploy --ttl 7d
sshmgr access status contractor@example.com
sshmgr access approve INVITATION_ID
sshmgr access sync --group production
```

`audit` remains local unless a push is explicit. `access sync` refreshes the
read-only baseline, displays an immutable plan, requires confirmation, applies
through the customer-controlled SSH connection and performs a post-scan.

The low-level `sshmgr cloud upload-plan`, history, bundle and dashboard
commands remain available for offline evidence inspection and automation. Run
`sshmgr help --all` for the complete command surface.

## Compatibility contract

The [`cloudcontract`](../cloudcontract) Go package owns the versioned request,
response and evidence types shared with compatible Cloud services. It is data
and validation code only; it contains no server, database or browser UI.

The frozen access artifact and privacy guarantees are documented in
[`access-schema-v1.md`](access-schema-v1.md).
