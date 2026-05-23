package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"sshmgr/internal/completion"
	"sshmgr/internal/config"
	exec_ "sshmgr/internal/exec"
	"sshmgr/internal/importer"
	"sshmgr/internal/lint"
	"sshmgr/internal/rotate"
	"sshmgr/internal/secret"
	"sshmgr/internal/theme"

	"golang.org/x/term"
)

func cmdLint(args []string) {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	_ = fs.Parse(args)
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	findings := lint.Run(cfg)
	if *jsonOut {
		report := lint.Summarize(findings)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal(err.Error())
		}
		if report.Errors > 0 {
			os.Exit(1)
		}
		return
	}
	if errs := lint.Print(findings); errs > 0 {
		os.Exit(1)
	}
}

// cmdExec runs a single command across every host matching --group, --tag,
// --host (comma-separated alias list), or --all. Parallelism caps concurrent
// connections at -p (default 8). Each host's lines are streamed to stderr
// prefixed with [alias]; a coloured summary lands at the end.
func cmdImport(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr import (ssh-config [path] | ansible <inv> | hosts <file>) [--group G] [--dry-run]")
	}
	source := args[0]

	fs := flag.NewFlagSet("import", flag.ExitOnError)
	group := fs.String("group", "", "assign imported hosts to this group")
	only := fs.String("only", "", "comma-separated glob patterns — import only matching aliases (ssh-config)")
	dryRun := fs.Bool("dry-run", false, "show what would be imported, write nothing")
	_ = fs.Parse(args[1:])
	pos := fs.Args()

	var onlyPatterns []string
	if *only != "" {
		for _, p := range strings.Split(*only, ",") {
			if p = strings.TrimSpace(p); p != "" {
				if _, err := filepath.Match(p, "probe"); err != nil {
					fatal("bad --only pattern " + strconv.Quote(p) + ": " + err.Error())
				}
				onlyPatterns = append(onlyPatterns, p)
			}
		}
	}

	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}

	var res *importer.Result
	switch source {
	case "ssh-config", "sshconfig":
		src := "~/.ssh/config"
		if len(pos) > 0 {
			src = pos[0]
		}
		res, err = importer.SSHConfig(cfg, src, *group, onlyPatterns)
	case "ansible":
		if len(pos) < 1 {
			fatal("usage: sshmgr import ansible <inventory-file>")
		}
		if *group != "" {
			fatal("--group is not used for ansible imports — groups come from the inventory's [section] names")
		}
		res, err = importer.Ansible(cfg, pos[0])
	case "hosts":
		if len(pos) < 1 {
			fatal("usage: sshmgr import hosts <file> [--group G]")
		}
		res, err = importer.Hosts(cfg, pos[0], *group)
	default:
		fatal("unknown import source %q — use ssh-config, ansible, or hosts")
	}
	if err != nil {
		fatal(err.Error())
	}

	fmt.Fprintf(os.Stderr, "[sshmgr] import %s: %d new, %d already present\n",
		source, len(res.Added), len(res.Skipped))
	for _, a := range res.Added {
		fmt.Println("  + " + a)
	}
	if *dryRun {
		fmt.Fprintln(os.Stderr, "[sshmgr] dry-run — config not written")
		return
	}
	if len(res.Added) == 0 && len(res.Groups) == 0 {
		fmt.Fprintln(os.Stderr, "[sshmgr] nothing to import")
		return
	}
	if err := config.Save(cfg, path); err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] saved to %s\n", path)
}

// selectAliases resolves the standard --group/--tag/--host/--all selector
// flags into a sorted alias list, aborting if nothing matches.
func cmdRotateKey(args []string) {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	group := fs.String("group", "", "select hosts in this group")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias")
	newKey := fs.String("new-key", "", "path to the new private key")
	removeOld := fs.Bool("remove-old", false, "remove the old key AFTER the new one verifies")
	dryRun := fs.Bool("dry-run", false, "show what would happen, change nothing")
	parallel := fs.Int("p", 6, "maximum concurrent connections")
	_ = fs.Parse(args)

	if *newKey == "" {
		fatal("rotate-key requires --new-key <path-to-new-private-key>")
	}
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	sel := exec_.Selector{Group: *group, Tag: *tag, All: *all}
	if *hosts != "" {
		for _, h := range strings.Split(*hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				sel.Hosts = append(sel.Hosts, h)
			}
		}
	}
	aliases := exec_.Select(cfg, sel)
	if len(aliases) == 0 {
		fatal("no hosts matched the selector (try --group, --tag, --host, or --all)")
	}
	rejectExternal(cfg, aliases, "rotate-key")

	mode := "append + verify"
	if *removeOld {
		mode = "append + verify + REMOVE OLD"
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] key rotation on %d host(s) — mode: %s\n", len(aliases), mode)
	results := rotate.Run(cfg, aliases, *newKey, *removeOld, *dryRun, *parallel)
	for _, r := range results {
		if r.Err != nil {
			os.Exit(1)
		}
	}
}

// cmdWatch re-runs a command on one host every N seconds with change
// highlighting. `sshmgr watch [-n SECS] <alias> <command…>`.
func cmdCompletion(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr completion <bash|zsh|fish>")
	}
	if err := completion.Print(os.Stdout, args[0]); err != nil {
		fatal(err.Error())
	}
}

func cmdTheme(args []string) {
	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if len(args) < 1 {
		// List + show current.
		current := cfg.Theme
		if current == "" {
			current = "default"
		}
		fmt.Println("available themes:")
		for _, n := range theme.Names() {
			marker := "  "
			if n == current {
				marker = "* "
			}
			fmt.Printf("%s%s\n", marker, n)
		}
		fmt.Printf("\ncurrent: %s\n", current)
		fmt.Println("set with: sshmgr theme <name>")
		fmt.Println("override per-session: SSHMGR_THEME=<name> sshmgr ui")
		return
	}
	name := strings.ToLower(args[0])
	valid := false
	for _, n := range theme.Names() {
		if n == name {
			valid = true
			break
		}
	}
	if !valid {
		fatal("unknown theme: " + name + " (try: " + strings.Join(theme.Names(), ", ") + ")")
	}
	cfg.Theme = name
	if err := config.Save(cfg, path); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("theme set to %q in %s\n", name, path)
}

// cmdTrust removes the known_hosts entry for an alias's host:port. Useful
// when a remote server's key legitimately changed (re-imaging, key rotation)
// and sshmgr otherwise refuses to connect with a MITM warning.
func cmdTrust(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr trust <alias>")
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
	port := h.Port
	if port == 0 {
		port = 22
	}
	// Cover every way OpenSSH could have stored a key for this destination:
	// the bare host/IP, the bracketed [host]:port form (non-22 ports), the
	// sshmgr alias name (likely matches the ssh-config alias if the user
	// first connected via `ssh <alias>`), and the alias's bracketed form.
	targets := []string{
		h.Host,
		fmt.Sprintf("[%s]:%d", h.Host, port),
		alias,
		fmt.Sprintf("[%s]:%d", alias, port),
	}
	seen := map[string]bool{}
	for _, t := range targets {
		if seen[t] {
			continue
		}
		seen[t] = true
		cmd := exec.Command("ssh-keygen", "-R", t)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		_ = cmd.Run()
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] cleared known_hosts entries for %s (%s)\n", alias, h.Host)
}

func cmdKeyring(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr keyring (set|get|rm|ls) [key]")
	}
	switch args[0] {
	case "set":
		if len(args) < 2 {
			fatal("usage: sshmgr keyring set [--stdin] <key>")
		}
		stdinMode := false
		rest := args[1:]
		if rest[0] == "--stdin" {
			stdinMode = true
			rest = rest[1:]
			if len(rest) < 1 {
				fatal("usage: sshmgr keyring set --stdin <key>")
			}
		}
		key := rest[0]
		var pw []byte
		var err error
		if stdinMode {
			pw, err = io.ReadAll(os.Stdin)
			if err != nil {
				fatal(err.Error())
			}
			pw = bytes.TrimRight(pw, "\r\n")
		} else {
			fmt.Fprintf(os.Stderr, "password for %q: ", key)
			pw, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				fatal(err.Error())
			}
		}
		if len(pw) == 0 {
			fatal("empty password not stored")
		}
		if err := secret.KeyringSet(key, string(pw)); err != nil {
			fatal("keyring set: " + err.Error())
		}
		fmt.Printf("stored %q in OS keyring (service=%s)\n", key, secret.KeyringService)
	case "get":
		if len(args) < 2 {
			fatal("usage: sshmgr keyring get <key>")
		}
		v, err := secret.KeyringGet(args[1])
		if err != nil {
			fatal(err.Error())
		}
		fmt.Println(v)
	case "rm", "delete":
		if len(args) < 2 {
			fatal("usage: sshmgr keyring rm <key>")
		}
		if err := secret.KeyringDelete(args[1]); err != nil {
			fatal(err.Error())
		}
		fmt.Printf("removed %q from OS keyring\n", args[1])
	case "ls", "list":
		// zalando/go-keyring has no portable list; we discover keys by scanning
		// the loaded config (after group merge so inherited password_keyring
		// values also show up) and probe each referenced entry.
		cfg, _, err := config.Load()
		if err != nil {
			fatal(err.Error())
		}
		seen := map[string]bool{}
		report := func(key, alias string) {
			if key == "" || seen[key] {
				return
			}
			seen[key] = true
			_, err := secret.KeyringGet(key)
			status := "stored"
			if err != nil {
				status = "MISSING (" + err.Error() + ")"
			}
			fmt.Printf("%-30s used by %-20s  %s\n", key, alias, status)
		}
		for alias := range cfg.Hosts {
			h, _ := cfg.ResolveHost(alias)
			report(h.PasswordKeyring, alias)
			for _, st := range h.LoginSteps {
				report(st.PasswordKeyring, alias)
			}
		}
		if len(seen) == 0 {
			fmt.Fprintln(os.Stderr, "no password_keyring entries referenced from config")
		}
	default:
		fatal("unknown keyring action: " + args[0])
	}
}

func cmdAdd(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr add <alias>")
	}
	alias := args[0]

	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if _, exists := cfg.Hosts[alias]; exists {
		fatal("alias already exists: " + alias)
	}

	reader := bufio.NewReader(os.Stdin)
	host := prompt(reader, "host", "")
	if host == "" {
		fatal("host is required")
	}
	usr := prompt(reader, "user", os.Getenv("USER"))
	if usr == "" {
		fatal("user is required")
	}
	portStr := prompt(reader, "port", "22")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fatal("invalid port: " + portStr)
	}
	key := prompt(reader, "key path", "~/.ssh/id_ed25519")
	autoDuo := prompt(reader, "auto duo push? [y/N]", "n")

	cfg.Hosts[alias] = config.HostConfig{
		Host:        host,
		Port:        port,
		User:        usr,
		Key:         key,
		AutoDuoPush: strings.EqualFold(strings.TrimSpace(autoDuo), "y"),
	}
	if err := config.Save(cfg, path); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("added %s -> %s@%s:%d (saved to %s)\n", alias, usr, host, port, path)
}

func cmdEdit(args []string) {
	_, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorExec, err := lookPath(editor)
	if err != nil {
		fatal("cannot find " + editor + " in PATH: " + err.Error())
	}
	editorArgs := []string{editor, path}
	// If the user supplied an alias, pass it to vim/nvim as a "go to this line"
	// hint via /pattern (works for vi/vim/nvim; harmless otherwise).
	_ = args
	cmd := exec.Command(editorExec, editorArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fatal(err.Error())
	}
}

func cmdRm(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr rm <alias>")
	}
	alias := args[0]
	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if _, ok := cfg.Hosts[alias]; !ok {
		fatal("alias not found: " + alias)
	}
	delete(cfg.Hosts, alias)
	if err := config.Save(cfg, path); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("removed %s from %s\n", alias, path)
}

