package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/external"
	"sshmgr/internal/sshc"
	"sshmgr/internal/transfer"
	"sshmgr/internal/tui"

)

func humanBytes(n int64) string { return transfer.HumanBytes(n) }

// splitFwdArgs separates the host alias from the -L/-R/-D flag tokens. Go's
// flag parser stops at the first non-flag token, so `fwd <alias> -L <spec>`
// (alias first — the documented form) and `fwd -L <spec> <alias>` must both
// work. The first bare token is the alias; flag tokens are returned first so
// fs.Parse sees them before any stray positional.
func cmdFiles(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr files <alias>")
	}
	alias := args[0]
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	if h.External {
		fatal("files (2-pane manager) needs the native SSH backend and is " +
			"not available for external hosts — use `sshmgr sftp " + alias + "` instead")
	}
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		fatal(err.Error())
	}
	defer sshc.CloseChain(client)
	recordLogin(alias, "files")
	if err := tui.RunFiles(client, alias); err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] files: %v\n", err)
	}
	maybeReturnToUI()
}

func cmdSCP(args []string) {
	fs := flag.NewFlagSet("scp", flag.ExitOnError)
	recursive := fs.Bool("r", false, "recurse into directories")
	_ = fs.Parse(args)
	pos := fs.Args()
	if len(pos) != 2 {
		fatal("usage: sshmgr scp [-r] <src> <dst>   (one of src/dst is alias:/path)")
	}
	src, dst := pos[0], pos[1]
	alias := remoteAlias(src)
	if alias == "" {
		alias = remoteAlias(dst)
	}
	if alias == "" {
		fatal("scp: at least one of src/dst must be of the form alias:/path")
	}
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	if h.External {
		code, err := external.Run("scp", external.SCPArgv(h, alias, src, dst, *recursive))
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
	if err := transfer.SCP(client, src, dst, *recursive); err != nil {
		fatal(err.Error())
	}
}

func cmdSFTP(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr sftp <alias>")
	}
	alias := args[0]
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	if h.External {
		recordLogin(alias, "sftp")
		code, err := external.Run("sftp", external.SFTPArgv(h))
		if err != nil {
			fatal(err.Error())
		}
		maybeReturnToUI()
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
	recordLogin(alias, "sftp")
	if err := transfer.SFTP(client, alias); err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] sftp: %v\n", err)
	}
	maybeReturnToUI()
}

func remoteAlias(spec string) string {
	if i := strings.IndexByte(spec, ':'); i > 0 && !strings.ContainsAny(spec[:i], "/\\") {
		return spec[:i]
	}
	return ""
}

