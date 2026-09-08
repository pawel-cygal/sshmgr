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

### Cloud client and access lifecycle

- Complete account-command flags and Cloud profile names without reading SSH
  inventory or credentials; align CLI help and the Cloud guide with first login.
- Show project-access status after human login and in `whoami`, with recovery
  hints for inaccessible projects and legacy workspaces; never automatically
  change an existing runner's project context.
- Support first-run `sshmgr login` without a runner profile, with hosted-service
  defaults, interactive project selection and explicit project flags for scripts.
- Coordinate new human profile creation with OS-keyring storage: abort on
  keyring failure and roll back the credential when profile publication fails.
  SSH inventory and runner credentials remain separate and unchanged.
- Add organization/project Cloud profiles, authenticated bundle upload and
  one-command evidence push while keeping preparation and inspection offline.
- Add browser-approved device login for human operators and separate OS-keyring
  credentials for human sessions and project runners.
- Add task-oriented `audit` and `access` workflows for invitation, possession
  status, approval, desired-state planning, synchronization and revocation.
- Publish the versioned `cloudcontract` transport/evidence boundary used by a
  separately maintained hosted service; no WebPanel, database or SaaS server
  implementation is distributed in this repository.

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
- The flat host view is now a table — alias, host, tags and last-used
  columns, each with its own colour — and the left pane widens from 36
  to 58 columns to fit it. The status indicator becomes a coloured glyph
  rather than an emoji: one column wide, and no longer dependent on the
  terminal's emoji width.
- Per-host availability: the last ten probe rounds render as a sparkline
  with an uptime percentage in the details panel, under AVAILABILITY,
  shown only once a host has history. The round count there is now
  followed by the wall-clock span it covers (e.g. "10 rounds · 1h40m").
- `probe_interval` (default `10m`, floor `30s`) configures how often the
  TUI's probe round repeats, overridable with `SSHMGR_PROBE_INTERVAL`
  (same env/config/default precedence as `theme:`/`animations:`). The
  previous hardcoded 60-second interval dialed a 388-host fleet far more
  often than a convenience readout needs; ten minutes across ten rounds of
  history also gives the availability sparkline a useful span (roughly
  1h40m) instead of ten minutes. Values below the floor are clamped up
  rather than honoured,
  since this dials every host in the fleet each round.
- `animations: off | informative | full` (default `informative`),
  overridable with `SSHMGR_ANIM` and cycled live with `m`; the level
  persists across restarts. `informative` moves only while work is
  happening — in steady state the TUI repaints nothing. `full` adds a
  breathing focus border and demotes itself to `informative` inside an
  SSH session unless `full` was set explicitly in the config.
- A probe round now shows `n/m` progress with a braille spinner. The
  forced 500ms pause per round is gone — it only existed to make the old
  all-at-once flash visible.
