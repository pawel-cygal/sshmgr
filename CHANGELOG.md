# Changelog

All notable changes to sshmgr are documented here. The project follows
[Semantic Versioning](https://semver.org/) once release tags are published.

## Unreleased

### Security and reliability

- Harden SSH key rotation with key-only verification, rollback, config-before-
  removal ordering, encrypted-key agent support, per-target serialization, and
  a real OpenSSH Docker integration test.
- Split runtime history from inventory and add atomic, locked, conflict-aware
  config writes with strict YAML validation.
- Make uploads/downloads atomic, reject symlink traversal, validate forward and
  KVM endpoints, fix X11 cookie substitution, and protect process-registry kills
  from recycled PIDs.
- Bound fleet-output and diff memory, add SSH handshake deadlines, and remove
  abandoned prompt-reader and agent-socket paths.

### Product and operations

- Add Linux/macOS CI builds, race detection, vulnerability scanning, and the
  rotate-key integration job.
- Add embedded build metadata, reproducible release archives with checksums,
  and a non-destructive versioned installer with an explicit rollback target.
- Add a real-OpenSSH product smoke test and a repeatable ten-minute demo that
  includes existing CLI/TUI snippets, transfers, forwarding, and fleet exec.
- Improve ssh_config and Ansible imports, lint coverage, transactional TUI
  edits, detached-forward readiness, password-command cache expiry, and live
  host probing.
- Set the canonical Go module path to `github.com/systeampl/sshmgr`.
