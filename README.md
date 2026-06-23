# sshmgr

A modern SSH connection manager for the terminal — full CLI + TUI for
DevOps and SRE workflows: jump hosts, Duo MFA, password vaults, port
forwarding, file transfer, parallel fleet command execution, and Ansible
integration — all from one config and one binary.

```
███████╗███████╗██╗  ██╗███╗   ███╗ ██████╗ ██████╗      /\___/\
██╔════╝██╔════╝██║  ██║████╗ ████║██╔════╝ ██╔══██╗    ( o . o )
███████╗███████╗███████║██╔████╔██║██║  ███╗██████╔╝     \  v  /
╚════██║╚════██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗      \___/
███████║███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝     modern SSH mgr
```

## Why sshmgr

Existing managers fall into two buckets: enterprise GUIs (Termius, mRemoteNG)
and minimal TUIs that wrap `~/.ssh/config`. `sshmgr` sits in the middle —
**terminal-native** like the latter, but with **rich features** the former
have:

- Groups with inheritable defaults (one place for `user`, `key`, `proxy_command`).
- Multi-step login chains (`su - deployer` then `sudo su -`) with passwords
  pulled from the **OS keyring**, env vars, custom commands, or interactive
  prompts.
- Built-in **SCP / SFTP / 2-pane file manager** sharing the same connect
  chain (proxy_jump, proxy_command, all auth backends).
- **Port forwarding** (-L / -R / -D SOCKS5) + **X11** + **agent forwarding**.
- **Real-time host status** in the TUI (🟢 / 🔴 / 🟡 / ⚫).
- Three colour **themes** — default (aqua), hacker (matrix), cyberpunk
  (neon).
- **Parallel command execution** across a group or tag — `sshmgr exec --group fleet 'uptime'`
  runs across N hosts with bounded parallelism, prefixed output, and a
  pass/fail summary.
- **Snippets** — saved one-liner commands per host (inherited from groups,
  or from reusable file-based libraries), picked from a TUI menu or run
  from the CLI as `sshmgr <alias> :<name>`.
- **Session recording** — opt-in tee of the remote shell to a per-session
  log file for audit / replay.
- **`sshmgr lint`** — finds broken proxy_jump refs, missing key files,
  undefined groups, snippet collisions before you hit them at connect time.
- **Ansible integration** — `export ansible` turns the fleet into an
  inventory (resolving bastion chains and proxy hops for you); `playbook`
  runs `ansible-playbook` against any selector.
- Single Go binary, no external services, no daemons.

## Install

```bash
git clone https://github.com/pawel-cygal/sshmgr.git
cd sshmgr
go build -o sshmgr .
sudo install -m 0755 sshmgr /usr/local/bin/sshmgr
```

Requirements: Go 1.26+, Linux or macOS. Windows works in theory (uses
`golang.org/x/crypto/ssh` and `tview`) but isn't tested.

## Quick start

1. Edit the config (auto-created on first run):

   ```bash
   sshmgr edit
   ```

   Add one host:

   ```yaml
   hosts:
     myserver:
       host: 10.0.0.5
       user: ubuntu
       key: ~/.ssh/id_ed25519
   ```

2. Connect:

   ```bash
   sshmgr myserver
   ```

3. Launch the TUI to browse / add / edit visually:

   ```bash
   sshmgr ui
   ```

## CLI reference

```text
sshmgr [-t] <alias> [cmd…]  shell, or run one command (-t forces a TTY)
sshmgr <alias> :<snippet>   run a saved snippet by name
sshmgr ui                   launch the TUI
sshmgr list [--group G] [--tag T]
                            list aliases, optionally filtered
sshmgr groups               list groups with host counts
sshmgr info <alias>         print resolved host as JSON (jq-friendly)
sshmgr add <alias>          add a new host (interactive prompt)
sshmgr edit                 open the config in $EDITOR
sshmgr rm <alias>           remove a host
sshmgr trust <alias>        drop stale known_hosts entry (after key rotation)
sshmgr theme [<name>]       list / set UI theme (default | hacker | cyberpunk)
sshmgr keyring set <key>    store password in OS keyring
sshmgr keyring rm  <key>    remove from OS keyring
sshmgr keyring ls           list keyring entries referenced from config
sshmgr scp [-r] <src> <dst> copy files (one side is alias:/path)
sshmgr sftp <alias>         interactive SFTP REPL
sshmgr files <alias>        2-pane MC-style file manager
sshmgr fwd <alias> -L/-R/-D <spec>
                            port forwarding: -L local, -R remote, -D SOCKS5
sshmgr fwd ls / run NAME / add NAME / rm NAME / active / stop ID
                            manage saved forward profiles; `active` lists
                            tunnels currently live, `stop` terminates one
                            by ID (full or short prefix)
sshmgr exec [--group G | --tag T | --host a,b | --all] [-p N] [--diff] <cmd…>
                            run a command across many hosts; --diff groups
                            identical output (drift), --dry-run lists targets,
                            --timeout D / --retry N / --fail-fast control the
                            run, --json emits machine-readable output
sshmgr watch [-n SECS] <alias> <cmd…>
                            re-run a command on a host with change highlight
sshmgr rotate-key --new-key PATH [--group G | --tag T | --host a,b | --all]
                  [--remove-old] [--dry-run]
                            safely roll a new SSH key across a fleet
sshmgr import (ssh-config [path] | ansible <inv> | hosts <file>) [--group G] [--only glob] [--dry-run]
                            import hosts from ssh_config / Ansible / etc-hosts
sshmgr export ansible [--format yaml|ini] [selectors] [--out path]
                            generate an Ansible inventory from the fleet
sshmgr playbook <file> [selectors] [--check] [--diff] [--limit E] [--extra-vars V]
                            run an Ansible playbook against selected hosts
sshmgr lint [--json]        validate config (groups, refs, keys, snippets)
sshmgr history [transfers|forwards|logins]
                            show recent activity
sshmgr completion <shell>   emit shell completion (bash | zsh | fish)
sshmgr help                 show help
```

### Shell completion

```bash
echo 'source <(sshmgr completion bash)' >> ~/.bashrc        # bash
echo 'source <(sshmgr completion zsh)'  >> ~/.zshrc         # zsh
sshmgr completion fish > ~/.config/fish/completions/sshmgr.fish  # fish
```

`sshmgr <TAB>` then completes host aliases live from the config.

## TUI

Launch with `sshmgr ui`. Default view is the **tree** view, grouped by
each host's primary group. `Tab` switches to a flat alphabetical list.

```
┌── hosts (tree) ──────────────────┐┌── details ───────────────────────────────┐
│ 🟢  ▼ fleet (365)                ││ web-eu-01                                │
│ 🟢      bastion-eu  [jumphost]   ││                                          │
│ 🟢      web-eu-01                ││ host:            web-eu-01               │
│ 🟢      web-eu-02                ││ port:            12344                   │
│ 🟢  ▶ home (8)                   ││ user:            gn                      │
│ ⚫  ▶ (ungrouped) (0)            ││ key:             ~/.ssh/id_ed25519       │
│                                  ││ groups:          fleet                   │
│                                  ││ tags:            fleet                   │
│                                  ││ auto_duo_push:   true                    │
│                                  ││ proxy_command:   ssh bastion-eu -W %h:%p │
│                                  ││ last connect:    2026-05-19T13:24:18Z    │
└──────────────────────────────────┘└──────────────────────────────────────────┘
 tree · sort name · 373 hosts
 Enter/s/f/p/c shell/sftp/files/fwd/snippet  x exec  w watch  P playbook
 Space mark  Tab tree  S sort  a/e/d host  A/R/D group  / filter  ? help  q quit
```

A status line (view mode, sort, active filter, selection count, host
count) sits above the two-line key footer.

### Key bindings

#### Host list

| Key | Action |
|---|---|
| `Enter` | open interactive shell |
| `s` | open SFTP REPL |
| `f` | open 2-pane file manager |
| `p` | forward-manager menu (new / saved / recent / active) |
| `c` | snippet picker — pick a saved command to run |
| `i` | inspect resolved config — shows which group each inherited field comes from |
| `Space` | toggle multi-select on the highlighted host (marker `* `) |
| `x` | run a command across the selection (or the host / group under the cursor) |
| `w` | watch a command on the highlighted host (re-run on an interval) |
| `P` | run an Ansible playbook against the selection / host / group |
| `Tab` | toggle flat / tree view |
| `S` | toggle sort: by name ↔ most recently used |
| `*` | pin / unpin the host — pinned hosts float to the top of the list |
| `/` | filter — plain text, or `tag:`/`group:`/`backend:` queries |
| `j`/`k` or arrows | navigate |
| `g` / `G` | jump to top / bottom |
| `a` / `e` / `d` | add / edit / delete **host** |
| `A` / `R` / `D` | add / rename / delete **group** |
| `K` | stop the host's active forward (asks the `p` menu when there are several) |
| `?` | show the full key list (cheatsheet overlay) |
| `Esc` | clear filter, or quit |
| `q` | quit |

#### 2-pane file manager (`f` on a host)

| Key | Action |
|---|---|
| `Tab` | switch active panel (local ↔ remote) |
| `Enter` | enter directory |
| `Bksp` / `h` | parent directory |
| `j`/`k` | navigate |
| `F5` / `c` | copy selected file/dir to the inactive panel |
| `F7` / `m` | create directory |
| `F8` / `d` | delete (file or empty dir) |
| `F6` / `S` | directory sync (active panel → inactive panel, recursive, with preview) |
| `r` | refresh both panels |
| `q` / `Esc` / `F10` | back to host list |

A transfers pane at the bottom shows the 5 most recent transfers for the
host.

#### Snippet picker (`c` on a host)

| Key | Action |
|---|---|
| `Enter` | run the highlighted snippet |
| `a` | add a new host-level snippet |
| `d` | delete a host snippet (group / file snippets show where they're defined instead) |
| `/` | focus the filter — type to narrow the list by name / description / command / source; `↑`/`↓` still drive the list and `Enter` runs the highlighted entry |
| `Esc` | clear the filter (when focused on it) or close the picker |

#### Exec result viewer

Opens after `x` (run a command across hosts) when launched from the TUI.

| Key | Action |
|---|---|
| `j`/`k` or arrows | scroll |
| `PgUp` / `PgDn` | page up / down |
| `g` / `G` | jump to top / bottom |
| `o` | cycle the filter: all → ok → failed |
| `n` / `p` | jump to the next / previous host block |
| `w` | save the full output to a timestamped file |
| `q` | back to the host list |
| `x` | exit to the shell |

The `?` overlay (from the host list) shows this whole keymap in-app.

#### Drift viewer (`exec --diff`)

Opens after a `--diff` exec launched from the TUI. The overview lists
the output groups (largest = baseline by default, marked `[baseline]`);
`Enter` opens the colored unified diff of the selected group against
the baseline.

| Key | Action |
|---|---|
| `Enter` | open the diff of the selected group against the baseline |
| `b` | set the highlighted group as the new baseline |
| `j` / `k` or arrows | move selection |
| `q` / `Esc` | back to the host list |

In the diff detail:

| Key | Action |
|---|---|
| `j` / `k` or arrows | scroll |
| `g` / `G` | jump to top / bottom |
| `n` / `p` | next / previous group (recompute the diff) |
| `w` | save the current diff (plain text) to a timestamped file |
| `q` / `Esc` | back to the overview |
| `x` | exit to the shell |

Selecting the baseline itself shows a friendly `(this is the baseline
group)` message with the group's representative output — no diff
against itself.

#### Status indicators

| Icon | Meaning |
|---|---|
| 🟢 | online (TCP connect succeeded, or jump host's `ssh -O check` was alive) |
| 🟡 | currently checking (refreshed every 60 s) |
| 🔴 | offline / unreachable |
| ⚫ | unknown (e.g. proxy-only host with no active ControlMaster) |

#### Filtering

`/` opens the filter. Plain text matches a substring of the alias,
host, user, tags or groups. A `key:` prefix narrows it structurally:

```
tag:web              hosts with a tag matching "web"
group:prod           hosts in a group matching "prod"
backend:external     hosts on the external (system-ssh) backend
backend:native       hosts on the native Go-SSH backend
```

Anything that isn't a recognised prefix (a bare word, or an unknown
`foo:bar`) falls back to plain-text matching — so the filter never
errors. The active query shows in the status bar.

## Configuration

Config is plain YAML, located by this resolution order:

1. `$SSHMGR_CONFIG` if set
2. `$XDG_CONFIG_HOME/sshmgr/config.yaml`
3. `~/.config/sshmgr/config.yaml`

Every save snapshots the previous file into `<dir>/backups/` (keeps 10
most recent).

### Schema

```yaml
theme: default              # default | hacker | cyberpunk
playbooks_dir: ~/.config/sshmgr/playbooks  # where `sshmgr playbook` resolves bare names
snippets_dir: ~/.config/sshmgr/snippets    # reusable snippet libraries (see Snippets)
snippet_glob: "*.yaml"                     # which files in snippets_dir to load
groups:                     # group defaults inherited by hosts that list them
  prod:
    user: deploy
    key: ~/.ssh/id_ed25519
    auto_duo_push: true
    auto_accept_host_key: true
    proxy_jump: bastion
    forward_agent: true
    server_alive_interval: 30
    tags: [prod]

hosts:
  bastion:
    host: bastion.example.com
    user: ubuntu
    key: ~/.ssh/id_ed25519
    auto_duo_push: true

  web01:
    host: web01.internal
    groups: [prod]          # inherits user, key, proxy_jump, etc.
    tags: [web]
```

### Host fields

| Field | Type | Description |
|---|---|---|
| `host` | string | hostname or IP |
| `port` | int | SSH port (default 22) |
| `user` | string | SSH username |
| `key` | string | path to private key file |
| `auto_duo_push` | bool | auto-select Duo Push option (sends "1" to keyboard-interactive challenge) |
| `auto_accept_host_key` | bool | skip TOFU prompt; auto-append unknown host keys to `~/.ssh/known_hosts` |
| `external` | bool | drive this host through the system OpenSSH tools (`ssh`/`scp`/`sftp`) instead of the native Go SSH client — for hosts needing OpenSSH-only features (knock-proxy, ControlMaster, `Match` blocks). See [External hosts](#external-hosts) |
| `proxy_jump` | string | alias of another configured host to tunnel through |
| `proxy_command` | string | shell command whose stdio is the SSH transport (`%h`/`%p` substituted); takes priority over `proxy_jump` |
| `groups` | list | groups this host belongs to (defaults inherited from the first) |
| `tags` | list | free-form labels for filtering |
| `pinned` | bool | float this host to the top of the TUI host list |
| `commands` | list | one-shot commands; runs them and exits instead of opening a shell |
| `become` | map | `{method: sudo\|su, user: name}` — runs commands wrapped in sudo/su |
| `login_steps` | list | post-login chain (see below); inheritable from a group |
| `login_steps_none` | bool | opt this host out of a group-inherited `login_steps` chain |
| `login_steps_auto` | bool | run `login_steps` at connect (default true); set false to use the `~r` hotkey instead |
| `escalate_key` | string | escape character for the in-session escalation hotkey (default `~`) |
| `x11_forward` | bool | request X11 forwarding so remote GUI apps render locally |
| `forward_agent` | bool | forward local ssh-agent into the session |
| `persistent` | string | wraps the remote shell in `tmux` (or `screen`) named `sshmgr-<alias>` so it survives disconnects |
| `connect_timeout` | int | TCP dial timeout, seconds |
| `server_alive_interval` | int | keepalive period, seconds |
| `server_alive_count_max` | int | drop the session after N consecutive missed keepalives (default 3) |
| `ssh_options` | list | extra `-o KEY=VAL` args; honored only by `external: true` hosts |

### External hosts

A host marked `external: true` is driven by the system OpenSSH tools
(`ssh` / `scp` / `sftp`) instead of sshmgr's native Go SSH client. Use it
for hosts that need OpenSSH-only behaviour the Go library can't reproduce —
a knock-proxy `ProxyCommand`, `ControlMaster`, `Match` blocks, and so on.

For an external host the `host:` field is the **ssh connection target**:
sshmgr passes it straight to OpenSSH (and `export ansible` emits it as
`ansible_host`). If your OpenSSH-only behaviour lives on a `Host` alias
in `~/.ssh/config`, set `host:` to **that alias** — otherwise ssh won't
match the `Host` block. (The sshmgr alias, i.e. the YAML key, is never
used as the connection name.)

sshmgr derives the rest of the connection options from the resolved host
config, so groups and inheritance work exactly as for native hosts:

- `key` → `-i`
- `port` → `-p` (ssh) / `-P` (scp, sftp), omitted when 22
- `proxy_jump` → `-J`
- `proxy_command` → `-o ProxyCommand=…` (takes precedence over `proxy_jump`)
- `ssh_options` → `-o KEY=VAL`
- `user` → `user@host`

| Workflow | External host |
|---|---|
| interactive shell — `sshmgr <alias>` | system `ssh` |
| one-shot command — `sshmgr <alias> <cmd>` | system `ssh` |
| snippet — `sshmgr <alias> :<name>` | system `ssh` |
| `sshmgr scp` | system `scp` |
| `sshmgr sftp` | system `sftp` |
| `sshmgr fwd -L/-R/-D` | system `ssh -N` |
| `sshmgr exec` / `sshmgr watch` | system `ssh` (per host; `BatchMode` is forced, so key auth) |
| `sshmgr files` (2-pane manager) | **not supported** — needs the native backend; use `sshmgr sftp` |
| `sshmgr rotate-key` | **not supported** — native backend only |

`files` and `rotate-key` need the native Go SSH backend; running them
against an external host fails fast with a clear error rather than
silently misbehaving. Because `exec`/`watch` force `BatchMode`, external
hosts in a fleet run must use key (or agent) auth — a password-only
external host will fail fast instead of hanging the run.

### Password backends

Any of the following auth fields can resolve a password. Resolution order:
**Password → PasswordEnv → PasswordKeyring → PasswordCmd → PasswordPrompt**.

```yaml
hosts:
  qnap:
    host: 192.168.1.10
    user: admin
    password_keyring: nas-admin          # store via: sshmgr keyring set nas-admin

  vault-backed:
    host: secure-host.example.com
    user: ubuntu
    password_cmd: "vault kv get -field=password kv/ssh/secure-host"

  prompt-each-time:
    host: paranoid.example.com
    user: root
    password_prompt: true                # asks at connect time
```

Use the OS keyring whenever possible — it's encrypted at rest by GNOME
Keyring / KWallet / macOS Keychain and unlocked once per session.

#### Password managers

There's no per-vendor code — any password manager with a CLI plugs in
through `password_cmd`. sshmgr runs the command and takes the first
line of stdout (most secret CLIs add a trailing newline or print extra
metadata):

| Manager | `password_cmd` example |
|---|---|
| 1Password | `op read "op://Private/{{alias}}/password"` |
| Bitwarden | `bw get password {{alias}}` |
| LastPass | `lpass show --password {{alias}}` |
| Keeper | `ksm secret notation keeper://{{alias}}/field/password` |
| HashiCorp Vault | `vault kv get -field=password kv/ssh/{{alias}}` |
| pass | `pass ssh/{{alias}}` |

You manage the CLI's unlocked session yourself (`bw unlock` →
`BW_SESSION`, `op signin`, `lpass login`, …) — sshmgr only shells out.

**Placeholders.** `password_cmd` and `password_keyring` expand
`{{alias}}`, `{{host}}`, `{{user}}` and `{{port}}`. Put one
`password_cmd` on a **group** and every host resolves its own per-host
vault entry — no line per host:

```yaml
groups:
  prod:
    password_cmd: 'op read "op://Infra/{{alias}}/password"'
```

**Caching.** A `password_cmd` result is memoised for the lifetime of
the process: a fleet `exec` — or a long TUI session — invokes the
secret CLI (and any biometric prompt) only once per distinct resolved
command line. Concurrent hosts sharing one command line share a single
run.

### Login steps

For hosts that need a chain after SSH auth (e.g. `su - deployer` then
`sudo su -`, each with its own password prompt):

```yaml
hosts:
  appserver:
    host: app.example.com
    user: gn
    login_steps:
      - command: "su - deployer"
        expect: "Password:"
        password_keyring: deployer-pass
      - command: "sudo su -"
        expect: "password for"           # substring; matches "[sudo] password for deployer:"
        password_keyring: deployer-pass
```

Each step sends `command\n`, waits up to `timeout_ms` (default 30000) for
the `expect` substring in the output, then sends the resolved password.
Each step's password resolves through the same backends as the host
password — same `{{alias}}`/`{{host}}`/`{{user}}`/`{{port}}` placeholders
and the same process-wide cache.

**Group-level chains.** `login_steps` can live on a group, so a whole fleet
shares one escalation chain. A host inherits the group's `login_steps` unless
it defines its own (host-level wins, full replacement — steps are not merged).
To opt a single host out entirely, set `login_steps_none: true` on it (a bare
`login_steps: []` would be dropped on the next config save and silently
re-inherit, so use the explicit flag).

**Auto at connect vs. on-demand hotkey.** By default the chain runs automatically
right after the shell opens. On hosts gated by an interactive MFA prompt (DUO,
Okta, OTP) that races the prompt — the chain would type `su` into the MFA prompt
before you approve it. Set **`login_steps_auto: false`** (host or group) so the
chain does *not* fire at connect; instead you trigger it yourself once you can see
the shell prompt, with the in-session escalation hotkey:

- **`~r`** — at the start of a line (OpenSSH-style `~` escape), runs the host's
  `login_steps` against the live session and lands you as root in place. `~~`
  sends a literal `~`; `~` mid-line is untouched. Override the escape character
  with `escalate_key` (e.g. `` escalate_key: "`" ``).

The hotkey works the same whether you launched via `sshmgr <alias>` or picked the
host in the TUI, and it's MFA-agnostic — it injects nothing until you press it, so
you decide the safe moment. If a step's `expect` never arrives within `timeout_ms`,
the chain aborts cleanly and leaves you at the shell (it never sends the password
into the wrong prompt). The hotkey also re-escalates after you `exit` back down.

```yaml
groups:
  sbs:
    login_steps_auto: false           # MFA-gated → don't auto-fire; use ~r instead
    login_steps:
      - command: "su - sbsadmin"
        expect: "assword"            # matches su's "Password:" and sudo's "password for"
        password_keyring: sbs-root
        timeout_ms: 90000             # generous: you may pause at the MFA prompt
      - command: "sudo su -"
        expect: "assword"
        password_keyring: sbs-root
        timeout_ms: 90000

hosts:
  cm00101:
    host: cm00101
    groups: [sbs]                     # inherits the chain; press ~r to escalate
  jumphost:
    host: jumphost
    groups: [sbs]
    login_steps_none: true            # opt out — opens a plain shell, no chain
```

On non-MFA hosts you can leave `login_steps_auto` unset (default true) to keep the
old auto-at-connect behavior; `~r` still works there as a manual re-trigger.

### Examples

**Jumphost behind port-knocking** — let OpenSSH (with your existing
`~/.ssh/config` knock-proxy setup) own the jump, sshmgr drives the inner SSH:

```yaml
groups:
  fleet:                      # shared by every fleet host, the jump host included
    port: 12344
    key: ~/.ssh/id_ed25519
    auto_duo_push: true
    auto_accept_host_key: true
    tags: [fleet]
  fleet-behind:               # only the hosts *behind* the jump host
    proxy_command: "ssh bastion-eu -W %h:%p"

hosts:
  bastion-eu:
    host: bastion-eu        # ssh-config alias — its connection lives in ~/.ssh/config
    external: true          # driven via the system ssh/scp/sftp tools
    groups: [fleet]           # NOT fleet-behind — a host can't tunnel through itself
    tags: [jumphost]

  web-eu-01:
    host: web-eu-01
    user: gn
    groups: [fleet, fleet-behind]
```

`sshmgr web-eu-01` → ssh tunnel via bastion-eu (with knock-proxy + Duo handled
by OpenSSH) → sshmgr's native SSH handshake to web-eu-01 → auto-Duo on
web-eu-01 → shell.

Keep the jump host **out of** the group that carries `proxy_command` — a
host can't tunnel through itself. If a `proxy_command` / `proxy_jump` ever
resolves to route a host through itself, sshmgr drops it (the host connects
directly, and an `external` host falls back to its `~/.ssh/config` entry)
and `sshmgr lint` flags the config.

**Home lab** — mix of key auth and password-auth (NAS/switch):

```yaml
groups:
  home:
    user: destine
    key: ~/.ssh/id_ed25519
    auto_accept_host_key: true
    tags: [home]

hosts:
  rpi1:
    host: 192.168.1.101
    groups: [home]
    tags: [rpi]
  nas:
    host: 192.168.1.200
    user: admin
    password_keyring: nas-pass
    groups: [home]
    tags: [qnap]
  switch:
    host: 192.168.1.1
    user: admin
    password_keyring: switch-pass
    groups: [home]
    tags: [switch]
```

## Workflows

### Run one command and exit

```bash
sshmgr web01 uptime
sshmgr web01 'tail -n 100 /var/log/nginx/access.log' | grep 404
sshmgr -t web01 sudo systemctl restart nginx     # -t allocates a PTY
```

Exit code from the remote propagates to the local shell.

### Copy files

```bash
# upload
sshmgr scp ./build.tar.gz web01:/tmp/

# download
sshmgr scp web01:/var/log/syslog ./

# recursive
sshmgr scp -r ./mydir web01:/srv/
```

### SFTP REPL

```bash
sshmgr sftp web01
sftp [/home/ubuntu]> ls
sftp [/home/ubuntu]> cd /var/log
sftp [/var/log]> get syslog
sftp [/var/log]> exit
```

Commands: `ls`, `lls`, `cd`, `lcd`, `pwd`, `lpwd`, `get`, `put`, `rm`,
`mkdir`, `rmdir`, `help`, `exit`.

### Port forwarding

```bash
# local: forward localhost:3307 -> remote:3306 (e.g., access remote MariaDB)
sshmgr fwd web01 -L 3307:localhost:3306

# remote: expose local :3000 on the server's :9000
sshmgr fwd web01 -R 9000:localhost:3000

# SOCKS5 proxy (set browser to socks5://localhost:1080)
sshmgr fwd bastion -D 1080
```

`Ctrl-C` ends the forward. Each successful invocation is appended to
`forward_history`. For local-listening forwards (`-L` / `-D`) sshmgr
preflights the bind, so a busy port fails fast with `local bind X is
busy: …` instead of racing the SSH handshake.

#### Background mode (`-d` / `--detach`)

Add `-d` to a direct forward (or to `sshmgr fwd run`) and sshmgr spawns
itself in a new session, redirects stdio to a log file, prints the PID
and returns immediately:

```bash
sshmgr fwd bastion -D 1080 -d
# [sshmgr] forward backgrounded — pid 12345, log /home/you/.local/state/sshmgr/fwd-logs/fwd-20260523-141530.log

sshmgr fwd run grafana -d
```

Logs land under `$XDG_STATE_HOME/sshmgr/fwd-logs/` (default
`~/.local/state/sshmgr/fwd-logs/`). Use `sshmgr fwd active` to list
live tunnels and `kill <pid>` to stop one. **Forwards fired from the
TUI** (`p` menu, saved / recent rows, or the setup form) detach
automatically — the manager terminal isn't held hostage by the tunnel,
and `fwd active` plus the host details panel surface what's running.

#### Saved profiles & manager subcommands

Name reusable forwards in config (inline `forwards:` map, or as YAML
files under `forwards_dir` — same folder model as `snippets_dir` and
`playbooks_dir`):

```yaml
forwards:
  grafana:
    alias: bastion
    type: L
    spec: 3000:grafana.internal:3000
    description: Grafana through bastion
  pg-prod:
    alias: db-bastion
    type: L
    spec: 15432:prod-db.internal:5432
  socks-prod:
    alias: bastion
    type: D
    spec: 1080
```

Manager subcommands keep the direct form working:

```bash
sshmgr fwd ls                                 # list saved profiles + source
sshmgr fwd run grafana                        # run a saved profile by name
sshmgr fwd add jenkins --alias bastion \
    --type L --spec 8080:jenkins.internal:8080
sshmgr fwd rm jenkins                         # remove an inline profile
sshmgr fwd active                             # list tunnels currently live
sshmgr fwd stop a3f9b1c2                      # SIGTERM (then SIGKILL) by ID
```

`fwd ls` shows each profile's `SOURCE` (inline or `file:<lib.yaml>`).
The inline layer always wins on a name collision with a file library;
`fwd rm` only removes inline profiles — file-library entries must be
edited in the YAML.

#### Active forwards

Every live forward writes one JSON entry under `$XDG_RUNTIME_DIR/sshmgr/forwards/`
(falling back to a per-UID directory under the OS temp dir). The entry
is removed on graceful Ctrl-C; `sshmgr fwd active` sweeps stale entries
whose owning PID is gone so `kill -9` doesn't leave the registry dirty.

```
ID        ALIAS    TYPE  SPEC                       PID    AGE  SOURCE
a3f9b1c2  bastion  L     3000:grafana.internal:3000 12345  5m   saved:grafana
```

In the TUI, `p` on a host now opens a small forward-manager menu:

  - **new forward** — opens the existing setup form,
  - `[saved]` rows — every profile whose alias matches this host,
  - `[recent]` rows — entries from `forward_history` for this host,
  - `[active]` rows — currently live tunnels for this host. Enter on
    an active row asks `Stop forward -L … (pid X)?` — confirm and
    sshmgr sends SIGTERM (escalating to SIGKILL after a short grace).

When a host has live tunnels the details panel grows an `active
forwards` section listing each `-L/-R/-D <spec>` with PID, age, source
(`direct` / `tui` / `saved:<name>`) and backend. From the host list,
`K` stops the host's active forward when there's exactly one — when
there are several it points you at the `p` menu to pick which one.
`sshmgr fwd stop <id>` is the equivalent CLI hook.

### History

```bash
sshmgr history transfers     # last 200 scp/sftp copies
sshmgr history forwards      # recent port forwards
sshmgr history logins        # recent connects / sftp / files / fwd / exec
```

### Run a command across many hosts

```bash
sshmgr exec --group fleet 'uptime'
sshmgr exec --tag prod 'systemctl is-active nginx'
sshmgr exec --host web-eu-01,web-eu-02 'date'
sshmgr exec --all -p 16 'cat /etc/os-release | head -1'
```

Each host's output is prefixed `[alias]` and streamed live. A coloured
summary at the end lists exit codes per host. Exit non-zero if any host
failed.

#### From the TUI

In `sshmgr ui`:

1. Press `Space` on each host you want — a `*` mark appears next to it.
2. Press `x`. A form opens with:
   - **snippet (optional)** — dropdown of snippets shared by every
     selected host (intersection by name, post-group-merge).
   - **commands (one per line)** — textarea. Multiple lines are joined
     with `;` and sent as one shell command.
3. **group identical output (drift detection)** — checkbox; tick it to
   get the drift report (hosts bucketed by identical output) instead of
   per-host blocks.
4. **Run** drops to live streaming, then opens a scrollable result
   viewer. Keys: `j`/`k`/`PgUp`/`PgDn`/`g`/`G` scroll, `o` cycles the
   filter (all / ok / failed), `n`/`p` jump between hosts, `w` saves the
   full output to a file, `q` returns to the host list, `x` exits to
   the shell.

Press `w` on a host to open the **watch** dialog (command + interval) —
it re-execs `sshmgr watch` so you get the live change-highlighted view.

If no host is multi-selected, `x` scopes the command to the host under
the cursor — or to every host in the group if the cursor is on a group
node in tree view.

#### Drift detection (`--diff`)

Run a command across a fleet and let sshmgr group identical output —
the fast way to spot the handful of hosts that drifted:

```bash
sshmgr exec --group fleet --diff 'nginx -v 2>&1'
```

```
=== drift report ===  365 host(s) · 3 distinct result(s)

═══ 360 host(s) ═══  nginx/1.24.0
    web-eu-01  web-eu-03  ...

═══ 4 host(s) ═══  nginx/1.22.1   ⚠ drift
    web-us-01  web-us-02  web-us-03  web-eu-04

═══ 1 host(s) ═══  FAILED: connect ...   ⚠ failed
    web-eu-09
```

The biggest group is assumed to be the norm; everything else is flagged
`⚠ drift` (or `⚠ failed`). `sshmgr exec --diff` exits non-zero whenever
there's more than one group, or whenever any host failed, so it doubles
as a CI consistency gate.

Launched from the TUI (`x` with the drift checkbox), the report opens
as a two-level viewer: a list of groups with the baseline visibly
marked, and `Enter` on a row opens the colored unified diff of that
group against the baseline. `b` reassigns the baseline to the
highlighted group. See the [Drift viewer](#drift-viewer-exec---diff)
key table for the full keymap.

#### Dry run (`--dry-run`)

Before running something destructive on a 300-host group, see exactly
which hosts the selector resolves to — without connecting:

```bash
sshmgr exec --group fleet --dry-run 'rm /tmp/old.lock'
```

#### Run controls (`--timeout` / `--retry` / `--fail-fast`)

```bash
sshmgr exec --group fleet --timeout 20s 'systemctl is-active nginx'
sshmgr exec --group fleet --retry 2 'apt-get update'
sshmgr exec --group fleet --fail-fast './migrate.sh'
```

- `--timeout D` — per-host limit. A host that overruns is marked failed
  with a `timeout` stage and its attempt is stopped: the external backend
  kills the `ssh` process, the native backend closes the SSH connection
  (which unblocks the in-flight command). The remote process may still
  finish on the server — SSH does not guarantee a remote kill.
- `--retry N` — retry each *failed* host up to `N` more times (connect
  failures, non-zero exits and timeouts all count). The result reports how
  many `attempts` it took. Note retries re-run the command: combine
  `--retry` with `--timeout` carefully on non-idempotent / side-effecting
  commands, since a timed-out attempt that actually completed on the
  server will be run again.
- `--fail-fast` — once any host fails, stop launching new ones. Hosts
  already running are left to finish; not-yet-started hosts are reported
  with a `skipped` stage. Bounded concurrency means up to `-p` hosts may
  already be in flight when the first failure lands.

#### Machine-readable output (`--json`)

`--json` swaps the live stream and coloured summary for a JSON document
on stdout (nothing else is printed), so `exec` slots into scripts and CI:

```bash
sshmgr exec --group fleet --json 'uptime' | jq -r '.[] | select(.exit_code != 0) | .alias'
```

Each entry: `alias`, `exit_code`, `duration_ms`, `output`, `error`,
`attempts`, `timed_out`, `failed_stage` (`connect` / `command` /
`timeout` / `skipped`). With `--diff --json` the output is instead a
drift document — `total_hosts`, `distinct_groups`, and `groups[]` with
`aliases` / `failed` / `label` / `output`. Exit code is non-zero if any
host failed — and, with `--diff`, also if the fleet drifted into more than
one output group (a fleet that fails *identically* is one group but still
exits non-zero).

`sshmgr lint --json` emits `{findings:[{severity,scope,message}], errors,
warnings, infos}` and still exits non-zero when there are errors.
`sshmgr info <alias>` already prints the resolved host as JSON; that
shape is stable.

### Importing hosts

`sshmgr import` pulls hosts into the config from external sources so you
don't hand-write YAML for an existing fleet. All imports are **additive** —
an alias that already exists is reported and left untouched.

```bash
# From your OpenSSH client config (default ~/.ssh/config)
sshmgr import ssh-config
sshmgr import ssh-config /etc/ssh/ssh_config --group infra

# From an Ansible INI inventory — [section] becomes a group,
# [section:vars] becomes that group's defaults
sshmgr import ansible ./inventory.ini

# From an /etc/hosts-style file
sshmgr import hosts /etc/hosts --group lan
```

Field mapping:

| ssh_config | Ansible inventory | → sshmgr |
|---|---|---|
| `HostName` | `ansible_host` | `host` |
| `User` | `ansible_user` | `user` |
| `Port` | `ansible_port` | `port` |
| `IdentityFile` | `ansible_ssh_private_key_file` | `key` |
| `ProxyJump` | — | `proxy_jump` |
| `ProxyCommand` | — | `proxy_command` |

`--group <name>` assigns every imported host to a group; `--dry-run`
prints the plan without writing. Wildcard `Host *` blocks in ssh_config
are skipped (they're patterns, not hosts).

`--only <glob,glob,…>` imports just the ssh-config aliases matching a
comma-separated glob list — handy for fanning one config into several
groups in separate passes:

```bash
sshmgr import ssh-config --only 'edge-*,api-*'        --group edge
sshmgr import ssh-config --only 'web-*'               --group fleet
```

### Ansible integration

sshmgr is not a replacement for Ansible — it owns the *inventory and
targeting*, Ansible owns *playbook execution*. The win: sshmgr already
knows the awkward parts (bastion chains, `proxy_command`, per-host
quirks), so it can hand Ansible an inventory where hard-to-reach hosts
just work, with no second hand-maintained inventory file.

#### Export an inventory

```bash
sshmgr export ansible --group prod                 # YAML to stdout
sshmgr export ansible --tag web --format ini       # INI
sshmgr export ansible --all --out hosts.yml        # write a file
```

Selectors are the same as `exec` (`--group` / `--tag` / `--host` /
`--all`). Field mapping:

- `host` → `ansible_host`, `user` → `ansible_user`, `port` →
  `ansible_port`, `key` → `ansible_ssh_private_key_file`
- `proxy_jump` is **resolved**: a native jump host is expanded to a
  concrete `ansible_ssh_common_args='-o ProxyJump=user@host:port,...'`.
  An **external** jump host (or an alias that isn't a configured host)
  is kept as its ssh-config alias rather than expanded, so its
  ssh-config semantics — `Match`, `ControlMaster`, a custom
  `ProxyCommand` — survive in the middle of a chain. A `proxy_jump`
  cycle is reported as an error, not silently dropped.
- `proxy_command` becomes `-o ProxyCommand="…"` and wins over
  `proxy_jump`; `ssh_options` are appended as `-o KEY=VAL`.
- sshmgr groups become inventory groups; tags become `tag_<name>` groups.
- **External hosts** (`external: true`) are emitted with plain
  `ansible_host` / `ansible_user` / `ansible_port` only — their
  connection is deliberately left to your `~/.ssh/config` (`Match`,
  `ControlMaster`, custom `ProxyCommand` are not translated). The
  generated file notes this. `ansible_host` is the host's `host:`
  value — exactly what sshmgr's own external backend connects to — so
  set `host:` to the name your `~/.ssh/config` matches (see
  [External hosts](#external-hosts)).

#### Run a playbook

```bash
sshmgr playbook deploy.yml --group prod
sshmgr playbook site.yml --tag web --check --diff
sshmgr playbook site.yml --host web01 --extra-vars env=stage --extra-vars ver=2
```

`playbook` resolves the target hosts, generates a temporary inventory
(the same exporter as `export ansible`), and shells out to the system
`ansible-playbook`, streaming its output and preserving its exit code.
It fails clearly if `ansible-playbook` is not installed.

- the playbook argument is a path, or a bare name looked up under
  `playbooks_dir` (config key; defaults to
  `$XDG_CONFIG_HOME/sshmgr/playbooks`)
- `--check` / `--diff` / `--limit` / `--extra-vars` (repeatable) pass
  through to `ansible-playbook`
- `--inventory-debug` prints the generated inventory and exits, without
  running anything

In the TUI, `P` opens a two-step launcher scoped to the multi-selected
hosts (or the host / group under the cursor): step 1 is a filterable
playbook list — `/` focuses the filter, `↑`/`↓` drive the list, `Enter`
continues — step 2 is the small form for `--check` / `--diff` /
`--extra-vars`. `Esc` on the form returns to the picker so you can pick
a different playbook without leaving the manager flow.

### SSH key rotation

`sshmgr rotate-key` rolls a new SSH key across a fleet **without any risk
of locking yourself out**. The safety contract: an old key is never
removed from a host until a brand-new, independent connection — using
**only the new key** — has been proven to work.

```bash
# Phase 1 — append the new key everywhere + verify it works.
# The old key is left in place; nothing destructive happens.
sshmgr rotate-key --group fleet --new-key ~/.ssh/new_ed25519

# (confirm everything's fine over the next hours/days)

# Phase 2 — re-verify, then drop the old key.
sshmgr rotate-key --group fleet --new-key ~/.ssh/new_ed25519 --remove-old
```

Per host, in order:

1. Connect with the host's current credentials.
2. Append the new public key to `~/.ssh/authorized_keys` — idempotent
   (skipped if already there), atomic (temp file → `chmod 600` →
   rename).
3. **Verify**: open a *fresh, separate* connection through the host's
   normal proxy chain, authenticating with **only** the new key — no
   password, no keyboard-interactive, no fallback to the old key. Run
   `true`.
4. Only if verification passed *and* `--remove-old` is set: reconnect
   and remove the old key line (matched on the key blob, so a differing
   comment doesn't matter).

If **any** step fails — append, permissions, verification — that host
is left exactly as it was, old key intact, and the failure is reported.
`rotate-key` exits non-zero if any host failed.

```
=== key rotation (append + verify) ===  365 ok  0 failed
  ✓  web-eu-01  new key added + verified (old key kept — re-run with --remove-old to drop it)
  ✓  web-eu-03  new key added + verified (old key kept ...)
  ...
```

Always do a `--dry-run` first to see the plan:

```bash
sshmgr rotate-key --group fleet --new-key ~/.ssh/new_ed25519 --remove-old --dry-run
```

`--new-key` takes the **private** key path — sshmgr derives the public
key from it (and needs the private key anyway to run the verification
connection).

### Watch a command

`sshmgr watch` re-runs a command on one host on an interval, clearing
and redrawing each time, with lines that changed since the previous run
highlighted in the theme accent:

```bash
sshmgr watch web01 'systemctl is-active nginx; ss -tln | grep :443'
sshmgr watch -n 5 db01 'SELECT count(*) FROM jobs WHERE state = ''running'';'
```

`Ctrl-C` stops. Handy during a deploy or while waiting for a queue to
drain.

### Snippets

Snippets are named one-liners attached to a host or a group. Group
snippets are inherited by every host in the group; host snippets win on
duplicate `name`.

Each snippet has these fields:

| Field | Required | Notes |
|---|---|---|
| `name` | yes | shows in the TUI picker; doubles as the lookup key |
| `command` | yes | the shell command to run; chains with `;` / `&&` are fine |
| `description` | no | one-line context shown below the name in the picker |
| `tags` | no | free-form labels (used by file-based libraries) |

#### Adding snippets via the TUI

In the host list, navigate to a host and press `c`:

```
┌── snippets · web01   (a=add  d=del  Enter=run  Esc) ──┐
│ load                                                  │
│   uptime                                              │
│ nginx-logs                                            │
│   Recent web traffic                                  │
│ deploy                                                │
│   /srv/scripts/deploy.sh --restart                    │
└───────────────────────────────────────────────────────┘
```

The picker lists snippets from all three layers — host, group and file
libraries — each row tagged with its source (`[host]`, `[group:web]`,
`[file:linux.yaml]`).

- `Enter` — run the selected snippet (exits the TUI, executes
  `sshmgr <alias> <command>`, returns to the shell).
- `a` — open a small form (name / command / description) that saves the
  new entry under the **current host** in the config file. Group-level
  and file-library snippets aren't editable from the UI — edit the YAML
  directly.
- `d` — delete the highlighted snippet. Only host-level entries can be
  removed here; for a group- or file-sourced snippet sshmgr shows a note
  pointing at where it's defined.
- `Esc` — close the picker.

#### Adding snippets via the config file

`sshmgr edit` opens the config in your `$EDITOR`. Add a `snippets:` list
to a host (or to a group's defaults). Examples:

```yaml
# Group-level: every host that lists `[fleet]` gets these by default.
groups:
  fleet:
    snippets:
      - name: uptime
        command: "uptime"
        description: "Quick load + boot time check"

      - name: who
        command: "w; last -n 5"
        description: "Logged-in users + last logins"

      - name: disk
        command: "df -h --output=target,size,used,avail,pcent | head -20"
        description: "Disk usage summary"

      - name: cpu-top
        command: "ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -15"
        description: "Top 15 processes by CPU"

      - name: tail-syslog
        command: "sudo tail -n 200 /var/log/syslog"
        description: "Recent system messages"

      - name: net-listen
        command: "ss -tlnp 2>/dev/null || netstat -tlnp"
        description: "TCP listeners (with PID)"

  home:
    snippets:
      - name: temp
        command: "vcgencmd measure_temp 2>/dev/null || sensors 2>/dev/null | head -10"
        description: "Pi temperature / lm-sensors"

# Per-host: overrides the group snippet of the same name.
hosts:
  web01:
    host: web01.example.com
    groups: [fleet]
    snippets:
      - name: deploy
        command: "/srv/scripts/deploy.sh --restart && sudo systemctl status nginx"
        description: "Pull + restart"

      - name: nginx-logs
        command: "tail -n 100 /var/log/nginx/access.log"

  db01:
    host: db01.example.com
    groups: [fleet]
    snippets:
      - name: pg-active
        command: "sudo -u postgres psql -c 'SELECT pid, usename, application_name, state, query_start FROM pg_stat_activity WHERE state != ''idle'' ORDER BY query_start;'"
        description: "Active PostgreSQL queries"

      - name: pg-locks
        command: "sudo -u postgres psql -c 'SELECT pid, locktype, mode, granted FROM pg_locks WHERE NOT granted;'"
        description: "Blocked locks"

      - name: tail-pg
        command: "sudo tail -n 200 /var/log/postgresql/*.log"

  rpi1:
    host: 192.168.1.101
    groups: [home]
    snippets:
      - name: pihole-stats
        command: "pihole -c -j"
        description: "Pi-hole DNS stats JSON"

      - name: pihole-restart
        command: "sudo systemctl restart pihole-FTL"

  k8s-bastion:
    host: bastion.cluster.local
    snippets:
      - name: pods-restart-count
        command: "kubectl get pods -A --sort-by='.status.containerStatuses[0].restartCount' | tail -20"
        description: "Top 20 most-restarted pods"

      - name: nodes-pressure
        command: "kubectl describe nodes | grep -A 5 Conditions"
        description: "Node pressure conditions"
```

After saving, `sshmgr lint` checks for snippet name collisions across
host and groups (host wins, but a warning helps you notice the override).

#### File-based snippet libraries

Host and group snippets live inline in the config; **file-based
libraries** keep reusable snippet sets in their own YAML files, so a
common toolkit can be shared and version-controlled separately. Drop
files into `snippets_dir` (default `$XDG_CONFIG_HOME/sshmgr/snippets`,
override with the `snippets_dir` config key; `snippet_glob` — default
`*.yaml` — limits which files load):

```yaml
# ~/.config/sshmgr/snippets/linux.yaml
snippets:
  - name: uptime
    command: uptime
    description: Quick load + boot time check
    tags: [common, linux]
  - name: disk
    command: "df -h --output=target,size,used,avail,pcent | head -20"
    description: Disk usage summary
```

Snippets resolve in three layers, **host > group > file** — a host or
group snippet of the same `name` overrides the file one, so file
libraries act as the shared base. `sshmgr lint` flags malformed library
files, names duplicated across libraries, and an explicitly configured
`snippets_dir` that doesn't exist.

#### Running snippets from the CLI

Run a saved snippet by name with the `:<name>` syntax:

```bash
sshmgr web01 :nginx-logs
```

The name is resolved across all three layers (file libraries, the
host's groups, the host itself — host wins). List what's available
inline on a host:

```bash
sshmgr info web01 | jq -r '.host.snippets[].name'
```

Ad-hoc commands still work the usual way — anything not prefixed with
`:` is run verbatim:

```bash
sshmgr web01 'tail -n 100 /var/log/nginx/access.log'
```

To run the same command across many hosts at once, use `exec`:

```bash
sshmgr exec --group fleet 'uptime'
sshmgr exec --tag prod 'df -h | tail -5'
```

### Persistent sessions

Set `persistent: tmux` (or `screen`) on a host or group and sshmgr wraps
the remote shell in a multiplexer named `sshmgr-<alias>` instead of
opening a plain login shell:

```yaml
groups:
  prod:
    persistent: tmux
```

If the named session already exists, sshmgr attaches to it (`tmux
new-session -A -s ...` / `screen -DR`). The remote shell survives
network drops, laptop sleep, and even sshmgr itself crashing — your
next connect picks up exactly where you left off.

Requires `tmux` (or `screen`) to be installed on the remote.

### Directory sync

In the 2-pane file manager (`f` on a host), press `F6` or `S` (uppercase)
to sync the active panel's directory to the inactive panel — recursively
and one-way. sshmgr first builds a plan (entries missing on the
destination, plus entries with different size) and shows it in a modal:

```
Sync /home/me/build → /srv/app
12 entries will copy:

+ assets/
+ assets/logo.png
+ index.html
~ config.json
+ static/main.css
...
```

`+` is new on the destination, `~` is size-differs. Confirm with **Run**
to start; transfers happen in the background so you can keep navigating.
The running counter in the transfers pane reflects the in-flight ops.

mtime isn't compared (SFTP returns coarse / sometimes timezone-shifted
mtimes), so files modified without a size change are skipped — same
caveat as `rsync --size-only`.

### Session recording

Set `session_log: true` on a host or group and every interactive shell
session writes its output to:

```
$SSHMGR_SESSION_DIR/<alias>-YYYYMMDD-HHMMSS.log
  (or $XDG_DATA_HOME/sshmgr/sessions/  if SSHMGR_SESSION_DIR is unset)
```

Useful for audit trails and for going back over a debugging session you
forgot to capture. Logs are append-only; sshmgr prefixes each session
with a `--- sshmgr session <RFC3339> ---` line.

### Lint

```bash
sshmgr lint
```

Reports:

- **errors**: broken `proxy_jump` references, missing key files when no
  password backend is set
- **warnings**: undefined groups referenced by hosts, snippet name
  collisions, missing key files with password fallback, a
  `proxy_command` / `proxy_jump` that routes a host through itself
- **info**: defined-but-unused groups, dead `auto_duo_push` on external
  hosts, `proxy_command` ssh targets not configured as sshmgr aliases
  (probably fine if they live in `~/.ssh/config`)

Exits with code 1 on any **error** so it's safe to use in CI.

## Security model

- **No MFA bypass.** Auto-Duo-Push only selects the "push" option of an
  interactive challenge; you still have to approve on your phone.
- **Host key verification** uses your normal `~/.ssh/known_hosts`. First
  contact prompts to accept (TOFU); mismatches are fatal with a clear
  `ssh-keygen -R <host>` hint (or `sshmgr trust <alias>`). Group default
  `auto_accept_host_key: true` skips the prompt — use it for trusted
  network segments only.
- **Passwords** live in the OS keyring, in environment variables, or come
  from external commands (`pass`, `bw`, `op`, `vault`). Plaintext
  `password:` field is supported but actively discouraged.
- **No long-running daemon.** sshmgr is single-shot by default — ping
  rounds run inside the TUI process and stop when you quit. The one
  exception is `sshmgr fwd -d` (and the TUI's auto-detach for
  forwards): the detached child is a regular sshmgr process you can see
  with `sshmgr fwd active` and stop with `kill <pid>`. No persistent
  supervisor, no auto-reconnect, no cross-restart state.

## Themes

```bash
sshmgr theme                    # show current + list available
sshmgr theme cyberpunk          # persist in config
SSHMGR_THEME=hacker sshmgr ui   # per-session override
```

Selection highlight is always bright yellow with black text — readable on
any terminal background regardless of theme.

## Debugging

`SSHMGR_DEBUG=1` enables verbose output:

- shows the resolved `proxy_command` line being executed
- adds `-v` to `ssh` calls inside `proxy_command`
- logs each `cmdConn` read/write during SSH handshake (hex dump)
- logs host-key callback decisions

Useful when a connect hangs and you need to know whether it's in the
tunnel, KEX, host-key check, or auth.

## Project layout

```
internal/
  ansible/        Ansible inventory export + ansible-playbook launcher
  banner/         ASCII banner shown at the top of the TUI
  completion/     bash / zsh / fish completion scripts + suggester
  config/         YAML schema, atomic save, ResolveHost (group merge)
  exec/           parallel command execution + drift detection + watch
  external/       system ssh / scp / sftp backend for external: true hosts
  fwd/            port forwarding (-L / -R / -D) + X11 channel handler
  importer/       host import from ssh_config / Ansible / etc-hosts
  lint/           config validator (groups, refs, keys, snippets)
  rotate/         safe fleet-wide SSH key rotation (append → verify → remove)
  secret/         password backends (env / keyring / cmd / prompt)
  snippets/       file-based snippet libraries + host/group/file merge
  sshc/           SSH client: connect chain, auth, host key TOFU, PTY,
                  login_steps expect/response, ad-hoc command execution
  theme/          colour palettes (default / hacker / cyberpunk) + ANSI helpers
  transfer/       SCP one-shot, SFTP REPL, file-transfer logger
  tui/            host list (flat + tree), 2-pane file manager,
                  port-forward dialog, live ping
main.go           CLI dispatcher
```

## Roadmap

- [x] Persistent sessions (auto-wrap in tmux/screen with reattach support).
- [x] Directory sync (WinSCP-style: make local match remote with diff preview).
- [x] Drift detection (`exec --diff`) — group identical output across a fleet.
- [x] Safe fleet-wide SSH key rotation (`rotate-key`, verify-before-remove).
- [x] Host import from ssh_config / Ansible inventory / etc-hosts.
- [x] External host backend — drive hosts through the system ssh/scp/sftp.
- [x] Structured output — `exec --json`, `lint --json`, drift JSON.
- [x] Fleet exec controls — `--timeout`, `--retry`, `--fail-fast`.
- [x] Ansible integration — inventory export + `ansible-playbook` launcher.
- [ ] Git-backed config sync across machines.
- [ ] SSH certificate authentication (Vault SSH / step-ca / Teleport CA).
- [x] TUI bulk-select (`Space` to toggle, `x` to run a command across the
  selection — paired with `sshmgr exec`).
- [x] Scrollable per-host exec result viewer when launched from the TUI
  (`q` to return to the host list, `x` to exit).
- [ ] Config encryption at rest (age-based, unlock with a master password).
- [ ] Auto-update check from GitHub releases.
- [ ] Generic `-o KEY=VAL` mapping for native Go-SSH hosts (today: external only).
- [ ] Bitwarden / 1Password / Vault first-class integrations (today: via
  `password_cmd`).
- [ ] Windows testing & packaging.

## License

[MIT](LICENSE) © Pawel Cygal
