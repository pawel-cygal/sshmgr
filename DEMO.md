# sshmgr — 10-minute product demo

This walkthrough demonstrates the product without using production hosts or
secrets. Start with an isolated SSH server (the repository's integration test
does this automatically with Docker) or substitute a disposable VM.

## 1. Prove what is running

```bash
sshmgr version
sshmgr version --json | jq .
```

The version, commit, build timestamp, Go version, and target platform are part
of every official release-archive build.

## 2. Build a small inventory

Use a separate demo file so the live inventory is never touched:

```bash
export SSHMGR_CONFIG=$(mktemp)
chmod 600 "$SSHMGR_CONFIG"
${EDITOR:-vi} "$SSHMGR_CONFIG"
```

```yaml
groups:
  demo:
    user: demo
    key: ~/.ssh/id_ed25519
    snippets:
      - name: health
        command: "uname -a; uptime"

hosts:
  demo-1:
    host: 127.0.0.1
    port: 2222
    groups: [demo]
    auto_accept_host_key: true
```

```bash
sshmgr lint
sshmgr list --group demo
sshmgr info demo-1 | jq .
```

Point out that inherited group settings are resolved once for CLI, TUI,
transfers, forwards, snippets, and Ansible export.

## 3. Run safely at one-host and fleet scale

```bash
sshmgr demo-1 'printf "connected: "; hostname'
sshmgr demo-1 :health
sshmgr exec --group demo --dry-run 'uname -r'
sshmgr exec --group demo --json 'uname -r' | jq .
```

The saved snippet is available from the same inventory in the TUI (`c`) and
from the CLI. Fleet execution has bounded parallelism, timeouts, retries,
fail-fast, JSON output, and output-diff grouping.

## 4. Show transfers, forwards, and the TUI

```bash
printf 'demo payload\n' >/tmp/sshmgr-demo.txt
sshmgr scp /tmp/sshmgr-demo.txt demo-1:/tmp/sshmgr-demo.txt
sshmgr fwd demo-1 -L 18080:127.0.0.1:80 -d
sshmgr fwd active
sshmgr ui
```

Uploads and downloads are staged then renamed, detached forward startup is
verified, and active tunnels have PID-identity protection before stop signals
are sent.

## 5. Show operations integration

```bash
sshmgr export ansible --format yaml --group demo
sshmgr rotate-key --host demo-1 --new-key ~/.ssh/id_ed25519.next --dry-run
```

Key rotation stays enabled but is transactional: add, authenticate with only
the new key, persist config, reconnect, and only then remove the old key. The
Docker integration test proves the old key stops authenticating after a
successful `--remove-old` rotation.

## Automated proof

```bash
go test ./...
go test -race ./...
go vet ./...
./integration/openssh/test.sh
./integration/rotate/test.sh
```

The OpenSSH scenario exercises version output, strict config lint, a saved
snippet, one-shot and fleet execution, upload/download, and a detached local
forward against an isolated real SSH server.
