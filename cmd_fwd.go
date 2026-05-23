package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/external"
	"sshmgr/internal/forwards"
	"sshmgr/internal/fwd"
	"sshmgr/internal/fwdregistry"
	"sshmgr/internal/sshc"

)

func splitFwdArgs(args []string) (alias string, flagArgs []string) {
	valueFlags := map[string]bool{"-L": true, "-R": true, "-D": true}
	var extras []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			// "-L spec" consumes the next token; "-L=spec" is self-contained.
			if valueFlags[a] && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		if alias == "" {
			alias = a
		} else {
			extras = append(extras, a)
		}
	}
	return alias, append(flagArgs, extras...)
}

// cmdFwd dispatches the fwd subcommands (ls / run / add / rm / active) or,
// when the call carries a -L / -R / -D flag, runs the direct CLI form
// `sshmgr fwd <alias> -L/-R/-D <spec>`. The flag-first rule preserves the
// alias-first model: a host named `run`, `ls`, `add`, `rm` or `active`
// still works through the direct form because the disambiguator only
// treats args[0] as a subcommand when no direct-form flag is present.
func cmdFwd(args []string) {
	if hasFwdDirectFlag(args) {
		cmdFwdDirect(args)
		return
	}
	if len(args) > 0 {
		switch args[0] {
		case "ls":
			cmdFwdLs(args[1:])
			return
		case "run":
			cmdFwdRun(args[1:])
			return
		case "add":
			cmdFwdAdd(args[1:])
			return
		case "rm":
			cmdFwdRm(args[1:])
			return
		case "active":
			cmdFwdActive(args[1:])
			return
		case "stop":
			cmdFwdStop(args[1:])
			return
		}
	}
	cmdFwdDirect(args)
}

// hasFwdDirectFlag reports whether args carry one of the -L / -R / -D
// flags that mark the direct port-forward form. Accepts both the bare
// token (`-L`) and the joined form (`-L=spec` / `-Lspec`) so any way Go's
// flag package would recognise it.
func hasFwdDirectFlag(args []string) bool {
	for _, a := range args {
		if a == "-L" || a == "-R" || a == "-D" {
			return true
		}
		if len(a) > 2 && (a[0] == '-') && (a[1] == 'L' || a[1] == 'R' || a[1] == 'D') {
			return true
		}
	}
	return false
}

// fwdSource returns the source label persisted to the active-forwards
// registry when this process drives a forward through cmdFwdDirect — "tui"
// for a re-exec from the TUI, "direct" for a plain shell invocation.
func fwdSource() string {
	if os.Getenv("SSHMGR_FROM_UI") == "1" {
		return "tui"
	}
	return "direct"
}

func cmdFwdDirect(args []string) {
	fs := flag.NewFlagSet("fwd", flag.ExitOnError)
	localSpec := fs.String("L", "", "local forward: [bind:]localPort:remoteHost:remotePort")
	remoteSpec := fs.String("R", "", "remote forward: [bind:]remotePort:localHost:localPort")
	dynamicSpec := fs.String("D", "", "dynamic SOCKS5 proxy: [bind:]port")
	detach := fs.Bool("d", false, "run the forward in the background; parent returns immediately with PID + log path")
	// Go's flag parser stops at the first non-flag token, so pull the alias
	// out first — otherwise `fwd <alias> -L <spec>` (the documented form)
	// would never see the -L/-R/-D flags.
	alias, flagArgs := splitFwdArgs(args)
	_ = fs.Parse(flagArgs)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("unexpected argument(s): " + strings.Join(extra, " "))
	}
	if alias == "" {
		fatal("usage: sshmgr fwd <alias> -L/-R/-D <spec> [-d]   (or `sshmgr fwd ls|run|add|rm|active`)")
	}
	if *detach && os.Getenv("SSHMGR_FWD_DAEMON") != "1" {
		runDetached(args)
		return
	}
	typ, spec, count := "", "", 0
	if *localSpec != "" {
		typ, spec, count = "L", *localSpec, count+1
	}
	if *remoteSpec != "" {
		typ, spec, count = "R", *remoteSpec, count+1
	}
	if *dynamicSpec != "" {
		typ, spec, count = "D", *dynamicSpec, count+1
	}
	if count != 1 {
		fatal("specify exactly one of -L / -R / -D")
	}

	cfg, cfgPath, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	runForward(cfg, cfgPath, h, alias, typ, spec, fwdSource())
}

// runForward executes one port-forward end-to-end: preflight the local
// listen address for -L / -D so a busy port fails fast, register the run
// in the active-forwards registry, dispatch to the external or native
// backend, persist the run to ForwardHistory and block until ctrl-c.
// source ends up in the registry entry — "direct", "tui" or "saved:<name>".
func runForward(cfg *config.Config, cfgPath string, h config.HostConfig, alias, typ, spec, source string) {
	var listen, target string
	switch typ {
	case "L":
		l, t, err := fwd.ParseLocalSpec(spec)
		if err != nil {
			fatal(err.Error())
		}
		listen, target = l, t
		if err := fwd.PreflightListen(listen); err != nil {
			fatal(err.Error())
		}
	case "R":
		l, t, err := fwd.ParseRemoteSpec(spec)
		if err != nil {
			fatal(err.Error())
		}
		listen, target = l, t
	case "D":
		l, err := fwd.ParseDynamicSpec(spec)
		if err != nil {
			fatal(err.Error())
		}
		listen = l
		if err := fwd.PreflightListen(listen); err != nil {
			fatal(err.Error())
		}
	default:
		fatal("invalid forward type: " + typ)
	}

	backend := "native"
	if h.External {
		backend = "external"
	}
	if _, cleanup, err := fwdregistry.Register(alias, typ, spec, backend, source); err == nil {
		defer cleanup()
	} else {
		fmt.Fprintf(os.Stderr, "[sshmgr] could not register forward: %v\n", err)
	}

	if h.External {
		cmdFwdExternal(cfg, cfgPath, h, alias, typ, spec)
		return
	}

	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		fatal(err.Error())
	}
	defer sshc.CloseChain(client)
	recordLogin(alias, "fwd")

	ctx, cancel := fwd.CtxOnSignal()
	defer cancel()

	var runErr error
	switch typ {
	case "L":
		runErr = fwd.Local(ctx, client, listen, target)
	case "R":
		runErr = fwd.Remote(ctx, client, listen, target)
	case "D":
		runErr = fwd.Dynamic(ctx, client, listen)
	}

	entry := config.ForwardEntry{
		Alias: alias, Type: typ, Spec: spec,
		LastUsed: time.Now().UTC().Format("2006-01-02"),
	}
	cfg.ForwardHistory = upsertForward(cfg.ForwardHistory, entry, 20)
	if err := config.Save(cfg, cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] could not save forward history: %v\n", err)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] fwd: %v\n", runErr)
	}
	maybeReturnToUI()
}

func cmdFwdLs(args []string) {
	fs := flag.NewFlagSet("fwd ls", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	profiles := forwards.All(cfg)
	if len(profiles) == 0 {
		fmt.Fprintln(os.Stderr, "no saved forwards (try `sshmgr fwd add` or drop a YAML in forwards_dir)")
		return
	}
	maxName, maxAlias, maxSpec, maxSource := len("NAME"), len("ALIAS"), len("SPEC"), len("SOURCE")
	for _, p := range profiles {
		if n := len(p.Name); n > maxName {
			maxName = n
		}
		if n := len(p.Alias); n > maxAlias {
			maxAlias = n
		}
		if n := len(p.Spec); n > maxSpec {
			maxSpec = n
		}
		if n := len(p.Source); n > maxSource {
			maxSource = n
		}
	}
	fmt.Printf("%-*s  %-*s  %-4s  %-*s  %-*s  %s\n",
		maxName, "NAME", maxAlias, "ALIAS", "TYPE", maxSpec, "SPEC", maxSource, "SOURCE", "DESCRIPTION")
	for _, p := range profiles {
		fmt.Printf("%-*s  %-*s  %-4s  %-*s  %-*s  %s\n",
			maxName, p.Name, maxAlias, p.Alias, p.Type, maxSpec, p.Spec, maxSource, p.Source, p.Description)
	}
}

func cmdFwdRun(args []string) {
	fs := flag.NewFlagSet("fwd run", flag.ExitOnError)
	detach := fs.Bool("d", false, "run the forward in the background; parent returns immediately with PID + log path")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: sshmgr fwd run [-d] <name>")
	}
	name := fs.Arg(0)
	if *detach && os.Getenv("SSHMGR_FWD_DAEMON") != "1" {
		runDetached(append([]string{"run"}, args...))
		return
	}
	cfg, cfgPath, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	profile, ok := forwards.Find(cfg, name)
	if !ok {
		fatal(fmt.Sprintf("saved forward %q not found (try `sshmgr fwd ls`)", name))
	}
	if err := forwards.ValidateProfile(profile.ForwardProfile); err != nil {
		fatal(fmt.Sprintf("forward %q is invalid: %v", name, err))
	}
	h, ok := cfg.ResolveHost(profile.Alias)
	if !ok {
		fatal(fmt.Sprintf("forward %q references unknown alias %q", name, profile.Alias))
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] running saved forward %q (-%s %s on %s · %s)\n",
		name, profile.Type, profile.Spec, profile.Alias, profile.Source)
	runForward(cfg, cfgPath, h, profile.Alias, profile.Type, profile.Spec, "saved:"+name)
}

func cmdFwdAdd(args []string) {
	fs := flag.NewFlagSet("fwd add", flag.ExitOnError)
	aliasFlag := fs.String("alias", "", "host alias the forward runs on")
	typeFlag := fs.String("type", "", "forward type: L | R | D")
	specFlag := fs.String("spec", "", "spec (e.g. `3000:internal:3000` or `1080`)")
	descFlag := fs.String("description", "", "optional description")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: sshmgr fwd add <name> --alias A --type L|R|D --spec SPEC [--description TEXT]")
	}
	name := fs.Arg(0)
	profile := config.ForwardProfile{
		Alias: *aliasFlag, Type: *typeFlag, Spec: *specFlag, Description: *descFlag,
	}
	if err := forwards.ValidateProfile(profile); err != nil {
		fatal(err.Error())
	}
	cfg, cfgPath, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if _, ok := cfg.Hosts[profile.Alias]; !ok {
		fatal(fmt.Sprintf("alias %q is not configured", profile.Alias))
	}
	if cfg.Forwards == nil {
		cfg.Forwards = map[string]config.ForwardProfile{}
	}
	if _, exists := cfg.Forwards[name]; exists {
		fatal(fmt.Sprintf("forward %q already exists — `sshmgr fwd rm %s` first", name, name))
	}
	cfg.Forwards[name] = profile
	if err := config.Save(cfg, cfgPath); err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] saved forward %q\n", name)
}

func cmdFwdRm(args []string) {
	fs := flag.NewFlagSet("fwd rm", flag.ExitOnError)
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: sshmgr fwd rm <name>")
	}
	name := fs.Arg(0)
	cfg, cfgPath, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if _, exists := cfg.Forwards[name]; !exists {
		fatal(fmt.Sprintf("inline forward %q not found (file-library forwards can't be removed via the CLI — edit the YAML)", name))
	}
	delete(cfg.Forwards, name)
	if err := config.Save(cfg, cfgPath); err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] removed forward %q\n", name)
}

func cmdFwdActive(args []string) {
	fs := flag.NewFlagSet("fwd active", flag.ExitOnError)
	_ = fs.Parse(args)
	entries, err := fwdregistry.List()
	if err != nil {
		fatal(err.Error())
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no active forwards")
		return
	}
	// padded table; ID truncated to 8 hex chars for readability.
	maxAlias, maxSpec, maxSource := len("ALIAS"), len("SPEC"), len("SOURCE")
	for _, e := range entries {
		if n := len(e.Alias); n > maxAlias {
			maxAlias = n
		}
		if n := len(e.Spec); n > maxSpec {
			maxSpec = n
		}
		if n := len(e.Source); n > maxSource {
			maxSource = n
		}
	}
	fmt.Printf("%-8s  %-*s  %-4s  %-*s  %-7s  %-9s  %s\n",
		"ID", maxAlias, "ALIAS", "TYPE", maxSpec, "SPEC", "PID", "AGE", "SOURCE")
	now := time.Now().UTC()
	for _, e := range entries {
		shortID := e.ID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		age := now.Sub(e.StartedAt).Round(time.Second)
		fmt.Printf("%-8s  %-*s  %-4s  %-*s  %-7d  %-9s  %s\n",
			shortID, maxAlias, e.Alias, e.Type, maxSpec, e.Spec, e.PID, age, e.Source)
	}
}

func cmdFwdStop(args []string) {
	fs := flag.NewFlagSet("fwd stop", flag.ExitOnError)
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: sshmgr fwd stop <id-or-prefix>")
	}
	id := fs.Arg(0)
	e, err := fwdregistry.Find(id)
	if err != nil {
		fatal(err.Error())
	}
	if err := fwdregistry.Kill(e, 2*time.Second); err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] stopped -%s %s on %s (pid %d)\n", e.Type, e.Spec, e.Alias, e.PID)
}

// fwdLogDir returns the directory holding detached-forward logs: honours
// $XDG_STATE_HOME, falls back to ~/.local/state/sshmgr/fwd-logs, then the
// OS temp dir if even the home directory is unreachable.
func fwdLogDir() string {
	if state := os.Getenv("XDG_STATE_HOME"); state != "" {
		return filepath.Join(state, "sshmgr", "fwd-logs")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "sshmgr", "fwd-logs")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("sshmgr-%d-fwd-logs", os.Getuid()))
}

// runDetached re-spawns sshmgr in the background to take over running the
// forward described by fwdArgs (the args that would normally follow
// `sshmgr fwd`). The parent prints PID + log path and exits; the child
// sees SSHMGR_FWD_DAEMON=1 in the environment and skips the detach branch
// so it just runs the forward with stdio redirected to the log file.
func runDetached(fwdArgs []string) {
	exe, err := os.Executable()
	if err != nil {
		fatal("cannot resolve sshmgr binary: " + err.Error())
	}
	dir := fwdLogDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] could not create %s: %v\n", dir, err)
	}
	logPath := filepath.Join(dir, "fwd-"+time.Now().UTC().Format("20060102-150405")+".log")
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fatal("cannot open detach log " + logPath + ": " + err.Error())
	}
	cmd := exec.Command(exe, append([]string{"fwd"}, fwdArgs...)...)
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.Env = append(os.Environ(), "SSHMGR_FWD_DAEMON=1")
	// Setsid puts the child in a new session so the parent's controlling
	// terminal is no longer wired to it — Ctrl-C in the parent shell will
	// not propagate to the backgrounded forward.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logF.Close()
		fatal("could not background the forward: " + err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] forward backgrounded — pid %d, log %s\n", cmd.Process.Pid, logPath)
	_ = logF.Close()
}

// cmdFwdExternal runs `sshmgr fwd` for an external host via the system ssh
// client (`ssh -N -L/-R/-D`). Exactly one of local/remote/dynamic is set
// (the caller already enforced that). Specs are validated with the same
// parsers as the native path, then forwarding history is recorded.
func cmdFwdExternal(cfg *config.Config, cfgPath string, h config.HostConfig, alias, typ, spec string) {
	fwdFlag := "-" + typ
	recordLogin(alias, "fwd")
	entry := config.ForwardEntry{
		Alias:    alias,
		Type:     typ,
		Spec:     spec,
		LastUsed: time.Now().UTC().Format("2006-01-02"),
	}
	cfg.ForwardHistory = upsertForward(cfg.ForwardHistory, entry, 20)
	if err := config.Save(cfg, cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] could not save forward history: %v\n", err)
	}
	code, err := external.Run("ssh", external.FwdArgv(h, fwdFlag, spec))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sshmgr] fwd: %v\n", err)
	}
	maybeReturnToUI()
	if code != 0 {
		os.Exit(code)
	}
}

// recordLogin appends a successful action (connect/sftp/files/fwd) to login
// history. Best-effort; save errors are swallowed.
