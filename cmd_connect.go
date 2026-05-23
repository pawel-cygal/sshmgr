package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/external"
	"sshmgr/internal/snippets"
	"sshmgr/internal/sshc"

)

func parseConnectArgs(args []string) (alias, command string, forceTTY bool) {
	rest := args
	if len(rest) > 0 && rest[0] == "-t" {
		forceTTY = true
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return "", "", forceTTY
	}
	alias = rest[0]
	if len(rest) > 1 {
		command = strings.Join(rest[1:], " ")
	}
	return alias, command, forceTTY
}

func cmdRunOneShot(alias, command string, forceTTY bool) {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	// `sshmgr <alias> :<name>` runs a saved snippet — resolved across file
	// libraries, the host's groups and the host itself (host > group > file).
	if strings.HasPrefix(command, ":") {
		name := strings.TrimSpace(command[1:])
		snip, found := snippets.Find(cfg, alias, name)
		if !found {
			fatal("no snippet named " + strconv.Quote(name) + " on host " + alias)
		}
		command = snip.Command
	}
	// External hosts run the one-shot command (and snippets, already
	// resolved above) through the system ssh client.
	if h.External {
		recordLogin(alias, "exec")
		code, err := external.Run("ssh", external.SSHCommandArgv(h, command, forceTTY))
		if err != nil {
			fatal(err.Error())
		}
		if code != 0 {
			os.Exit(code)
		}
		return
	}
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		fatal(err.Error())
	}
	defer sshc.CloseChain(client)
	recordLogin(alias, "exec")
	code, err := sshc.RunOneShot(client, command, forceTTY)
	if err != nil {
		fatal(err.Error())
	}
	if code != 0 {
		os.Exit(code)
	}
}

func cmdConnect(alias string) {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("host alias not found: " + alias)
	}

	if h.External {
		recordLogin(alias, "connect")
		code, err := external.Run("ssh", external.SSHArgv(h))
		if err != nil {
			fatal(err.Error())
		}
		maybeReturnToUI()
		if code != 0 {
			os.Exit(code)
		}
		return
	}

	if os.Getenv("SSHMGR_FROM_UI") != "1" {
		fmt.Fprintf(os.Stderr, "[sshmgr] connecting to %s (%s@%s:%d)\n", alias, h.User, h.Host, h.Port)
	}
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		fatal(err.Error())
	}
	defer sshc.CloseChain(client)
	recordLogin(alias, "connect")

	// login_steps takes priority over the simple one-shot Commands path —
	// you typically want an interactive shell at the end of the chain.
	if len(h.LoginSteps) == 0 && (len(h.Commands) > 0 || h.Become.User != "") {
		if err := sshc.RunCommands(client, h); err != nil {
			fmt.Fprintf(os.Stderr, "[sshmgr] error: %v\n", err)
		}
		maybeReturnToUI()
		return
	}
	logPath := ""
	if h.SessionLog {
		logPath = sessionLogPath(alias)
		fmt.Fprintf(os.Stderr, "[sshmgr] session log: %s\n", logPath)
	}
	if err := sshc.InteractiveShell(client, h, h.LoginSteps, h.X11Forward, h.ForwardAgent, logPath, h.Persistent, alias); err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] error: %v\n", err)
	}
	maybeReturnToUI()
}

