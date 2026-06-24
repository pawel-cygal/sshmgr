package main

import (
	"fmt"
	"os"
	"syscall"

	"sshmgr/internal/completion"
	"sshmgr/internal/config"
	"sshmgr/internal/theme"
	"sshmgr/internal/transfer"
	"sshmgr/internal/tui"


)

func main() {
	args := os.Args[1:]
	// Pick theme from env/config once at startup so every TUI subcommand
	// (Run, RunFiles) starts with the same palette regardless of which
	// process re-exec'd into us.
	if cfg, _, err := config.Load(); err == nil {
		name := os.Getenv("SSHMGR_THEME")
		if name == "" {
			name = cfg.Theme
		}
		theme.Set(name)
	}
	transfer.Log = persistTransferLog
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(os.Stdout)
	case "ui":
		cmdUI()
	case "list", "ls":
		cmdList(args[1:])
	case "groups":
		cmdGroups()
	case "info":
		cmdInfo(args[1:])
	case "add":
		cmdAdd(args[1:])
	case "rm", "remove", "delete":
		cmdRm(args[1:])
	case "edit":
		cmdEdit(args[1:])
	case "keyring":
		cmdKeyring(args[1:])
	case "scp":
		cmdSCP(args[1:])
	case "sftp":
		cmdSFTP(args[1:])
	case "files":
		cmdFiles(args[1:])
	case "trust":
		cmdTrust(args[1:])
	case "theme":
		cmdTheme(args[1:])
	case "fwd", "forward":
		cmdFwd(args[1:])
	case "kvm":
		cmdKVM(args[1:])
	case "history":
		cmdHistory(args[1:])
	case "completion":
		cmdCompletion(args[1:])
	case "exec":
		cmdExec(args[1:])
	case "watch":
		cmdWatch(args[1:])
	case "rotate-key":
		cmdRotateKey(args[1:])
	case "import":
		cmdImport(args[1:])
	case "export":
		cmdExport(args[1:])
	case "playbook":
		cmdPlaybook(args[1:])
	case "lint", "check":
		cmdLint(args[1:])
	case "__complete":
		// Internal: invoked by shell completion scripts.
		passed, word := parseCompleteArgs(args[1:])
		_ = completion.Suggest(os.Stdout, passed, word)
	default:
		// Allow `sshmgr [-t] <alias> [command...]`. -t forces PTY allocation.
		alias, command, forceTTY := parseConnectArgs(args)
		if command != "" {
			cmdRunOneShot(alias, command, forceTTY)
		} else {
			cmdConnect(alias)
		}
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "sshmgr — SSH connection manager")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sshmgr [-t] <alias> [cmd…]  shell, or run one command (-t forces a TTY)")
	fmt.Fprintln(w, "  sshmgr <alias> :<snippet>   run a saved snippet by name")
	fmt.Fprintln(w, "  sshmgr ui                   launch the TUI (manage hosts visually)")
	fmt.Fprintln(w, "  sshmgr list [--group G] [--tag T]")
	fmt.Fprintln(w, "                              list aliases, optionally filtered")
	fmt.Fprintln(w, "  sshmgr groups               list groups with host counts")
	fmt.Fprintln(w, "  sshmgr info <alias>         print resolved host as JSON")
	fmt.Fprintln(w, "  sshmgr add <alias>          add a new host (interactive prompt)")
	fmt.Fprintln(w, "  sshmgr edit                 open config in $EDITOR")
	fmt.Fprintln(w, "  sshmgr rm <alias>           remove a host")
	fmt.Fprintln(w, "  sshmgr keyring set <key>    store password in OS keyring (libsecret on Linux)")
	fmt.Fprintln(w, "  sshmgr keyring rm  <key>    remove from OS keyring")
	fmt.Fprintln(w, "  sshmgr keyring ls           list keyring entries referenced from config")
	fmt.Fprintln(w, "  sshmgr scp [-r] <src> <dst> copy files (one side is alias:/path)")
	fmt.Fprintln(w, "  sshmgr sftp <alias>         interactive SFTP REPL")
	fmt.Fprintln(w, "  sshmgr files <alias>        2-pane MC-style file manager (TUI)")
	fmt.Fprintln(w, "  sshmgr trust <alias>        drop stale known_hosts entry (after key rotation)")
	fmt.Fprintln(w, "  sshmgr theme [<name>]       list / set UI theme (default | hacker | cyberpunk)")
	fmt.Fprintln(w, "  sshmgr fwd <alias> -L/-R/-D <spec>")
	fmt.Fprintln(w, "                              port forwarding: -L local, -R remote, -D SOCKS5")
	fmt.Fprintln(w, "  sshmgr history [transfers|forwards|logins]")
	fmt.Fprintln(w, "                              show recent activity")
    fmt.Fprintln(w, "  sshmgr exec [--group G|--tag T|--host a,b|--all] [-p N] [--diff] [--json] <cmd…>")
    fmt.Fprintln(w, "                              run a command across many hosts; also --timeout D,")
    fmt.Fprintln(w, "                              --retry N, --fail-fast, --dry-run")
    fmt.Fprintln(w, "  sshmgr watch [-n SECS] <alias> <cmd…>")
    fmt.Fprintln(w, "                              re-run a command on a host with change highlighting")
    fmt.Fprintln(w, "  sshmgr rotate-key --new-key PATH [--group G|--tag T|--host a,b|--all] [--remove-old] [--dry-run]")
    fmt.Fprintln(w, "                              safely roll a new SSH key across a fleet")
    fmt.Fprintln(w, "  sshmgr import (ssh-config [path] | ansible <inv> | hosts <file>) [--group G] [--only glob] [--dry-run]")
    fmt.Fprintln(w, "                              import hosts from ssh_config / Ansible inventory / etc-hosts")
    fmt.Fprintln(w, "  sshmgr export ansible [--format yaml|ini] [selectors] [--out path]")
    fmt.Fprintln(w, "                              generate an Ansible inventory from the fleet")
    fmt.Fprintln(w, "  sshmgr playbook <file> [selectors] [--check] [--diff] [--limit E] [--extra-vars V]")
    fmt.Fprintln(w, "                              run an Ansible playbook against selected hosts")
    fmt.Fprintln(w, "  sshmgr lint [--json]        validate config (groups, refs, keys, snippets)")
	fmt.Fprintln(w, "  sshmgr completion <shell>   emit shell completion (bash|zsh|fish)")
	fmt.Fprintln(w, "  sshmgr help                 show this help")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Config: $SSHMGR_CONFIG > $XDG_CONFIG_HOME/sshmgr/config.yaml > ~/.config/sshmgr/config.yaml")
}

func cmdUI() {
	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	alias, action, extraArgs, err := tui.Run(cfg, path)
	if err != nil {
		fatal(err.Error())
	}
	if action == tui.ActionNone {
		return
	}
	// ActionExec and ActionPlaybook scope hosts via extraArgs (--host a,b,c
	// or --group g), so they legitimately have an empty alias.
	if alias == "" && action != tui.ActionExec && action != tui.ActionPlaybook {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fatal("cannot resolve own path: " + err.Error())
	}
	env := append(os.Environ(), "SSHMGR_FROM_UI=1")
	var argv []string
	switch action {
	case tui.ActionSFTP:
		argv = []string{"sshmgr", "sftp", alias}
	case tui.ActionFiles:
		argv = []string{"sshmgr", "files", alias}
	case tui.ActionForward:
		// Background by default when fired from the TUI — a foreground
		// forward would replace the manager terminal with the running
		// tunnel. Detaching lets the shell come back, `fwd active` and
		// the details panel surface the live tunnel, and a relaunched UI
		// shows it again under the host's [active] section.
		argv = append([]string{"sshmgr", "fwd", "-d", alias}, extraArgs...)
	case tui.ActionExec:
		argv = append([]string{"sshmgr", "exec"}, extraArgs...)
	case tui.ActionPlaybook:
		argv = append([]string{"sshmgr", "playbook"}, extraArgs...)
	case tui.ActionWatch:
		// extraArgs = {interval, command}; flags must precede the alias.
		argv = []string{"sshmgr", "watch", "-n", extraArgs[0], alias, extraArgs[1]}
	default:
		// ActionConnect: extraArgs[0], if present, is a snippet command line.
		argv = []string{"sshmgr", alias}
		argv = append(argv, extraArgs...)
	}
	// Belt-and-suspenders terminal reset before handing over to the
	// re-exec'd child: leave tview's alternate screen, drop any lingering
	// SGR attributes, re-show the cursor, disable mouse tracking, and
	// drop DECCKM (application-mode cursor keys) so readline-based shells
	// in the child see normal `ESC [ A/B/C/D` arrow sequences.
	fmt.Fprint(os.Stderr, "\x1b[?1049l\x1b[?1000l\x1b[?1l\x1b[?25h\x1b[0m")
	if err := syscall.Exec(exe, argv, env); err != nil {
		fatal("exec self: " + err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
