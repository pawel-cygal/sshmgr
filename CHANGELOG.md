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
- Surface the in-session escalation hotkey in the UI: an "Inside an SSH session"
  section in the `?` overlay, the resolved hotkey next to `login_steps` in the
  host details pane, and a hint at connect when the chain is set to manual. The
  details pane also names keyring/command/prompt password backends instead of
  showing an empty `pass:` field.

### TUI

- Five new colour palettes — `catppuccin`, `tokyonight`, `nord`, `rosepine`
  and `gruvbox` — alongside the existing `default`, `hacker` and `cyberpunk`,
  selectable with `theme:` in the config or `SSHMGR_THEME`. The default
  theme and every existing colour are unchanged; the new palettes are
  opt-in.
- About screen with the SysTeam wolf, rendered as half-block cells: `F1` in
  the TUI, or `sshmgr about` from the shell. Shows version, commit, config
  path, host count and license. In the TUI the logo is skipped on
  terminals with fewer than 256 colours or narrower than 100 columns;
  `sshmgr about` skips it whenever stdout is not a terminal.
- Panes now have rounded borders. Focus is signalled by border colour
  rather than a heavier line.
- The banner adapts to the terminal: the six-row ASCII art only when there
  are at least 30 rows and 80 columns, otherwise a one-row line carrying
  version, config path, theme, host count and active forwards. It follows
  a resize without a restart.
- The footer drops to a single row below 24 terminal rows. The full keymap
  remains in the `?` overlay.
- The details panel is grouped into labelled sections — CONNECTION,
  MEMBERSHIP, LOGIN STEPS, KVM, COMMANDS, ACTIVE FORWARDS, ACTIONS — and
  shows the host as a connection string you could paste into `ssh`.
