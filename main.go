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
	"sort"
	"strconv"
	"strings"
	"syscall"

	"sshmgr/internal/ansible"
	"sshmgr/internal/completion"
	"sshmgr/internal/config"
	exec_ "sshmgr/internal/exec"
	"sshmgr/internal/external"
	"sshmgr/internal/forwards"
	"sshmgr/internal/fwd"
	"sshmgr/internal/fwdregistry"
	"sshmgr/internal/importer"
	"sshmgr/internal/lint"
	"sshmgr/internal/rotate"
	"sshmgr/internal/secret"
	"sshmgr/internal/snippets"
	"sshmgr/internal/sshc"
	"sshmgr/internal/theme"
	"sshmgr/internal/transfer"
	"sshmgr/internal/tui"

	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
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
func cmdExec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	group := fs.String("group", "", "select hosts in this group")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias in the config")
	parallel := fs.Int("p", 8, "maximum concurrent connections")
	diff := fs.Bool("diff", false, "group identical output (drift detection)")
	dryRun := fs.Bool("dry-run", false, "list target hosts without connecting")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON (no live output or summary)")
	timeout := fs.Duration("timeout", 0, "per-host timeout, e.g. 30s (0 = no limit)")
	retry := fs.Int("retry", 0, "retry each failed host up to N more times")
	failFast := fs.Bool("fail-fast", false, "stop launching new hosts after the first failure")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		fatal("usage: sshmgr exec [--group G|--tag T|--host a,b|--all] [-p N] [--timeout D] [--retry N] [--fail-fast] [--diff] [--json] [--dry-run] <command…>")
	}
	cmd := strings.Join(rest, " ")
	if *retry < 0 {
		fatal("--retry must be >= 0")
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

	if *dryRun {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(struct {
				DryRun bool     `json:"dry_run"`
				Hosts  []string `json:"hosts"`
			}{true, aliases})
			return
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] dry-run — would run %q on %d host(s):\n", cmd, len(aliases))
		for _, a := range aliases {
			fmt.Println("  " + a)
		}
		return
	}

	opts := exec_.Options{
		Parallel: *parallel,
		Timeout:  *timeout,
		Retry:    *retry,
		FailFast: *failFast,
		Quiet:    *jsonOut,
	}
	if !*jsonOut {
		fmt.Fprintf(os.Stderr, "[sshmgr] running on %d host(s) with parallelism=%d\n", len(aliases), *parallel)
	}
	results := exec_.Run(cfg, aliases, cmd, opts)

	if *jsonOut {
		if code := emitExecJSON(results, *diff); code != 0 {
			os.Exit(code)
		}
		return
	}

	exec_.PrintSummary(results)

	fromUI := os.Getenv("SSHMGR_FROM_UI") == "1"

	if *diff {
		groups := exec_.GroupByOutput(results)
		if fromUI {
			if tui.ShowDriftReport("drift report · "+cmd, cmd, groups) == tui.ExecBackToUI {
				maybeReturnToUI()
			}
			return
		}
		fmt.Fprint(os.Stderr, renderDrift(results, groups, true))
		// Non-zero on drift OR on any host failure — a fleet that fails
		// identically is one group but is still a failure.
		if len(groups) > 1 || exec_.AnyFailed(results) {
			os.Exit(1)
		}
		return
	}

	if fromUI {
		// The live stream interleaves per goroutine — hand the structured
		// results to the viewer for a clean, filterable per-host view.
		title := fmt.Sprintf("exec on %d host(s) · cmd: %s", len(aliases), cmd)
		if tui.ShowHostResults(title, results) == tui.ExecBackToUI {
			maybeReturnToUI()
		}
		return
	}
	if exec_.AnyFailed(results) {
		os.Exit(1)
	}
}

// emitExecJSON writes the machine-readable exec result to stdout and returns
// the process exit code: 1 if any host failed, or — in --diff mode — if the
// fleet drifted into more than one output group.
func emitExecJSON(results []exec_.Result, diff bool) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if diff {
		report := exec_.DriftReport(results)
		_ = enc.Encode(report)
		if report.DistinctGroups > 1 || exec_.AnyFailed(results) {
			return 1
		}
		return 0
	}
	arr := make([]exec_.ResultJSON, len(results))
	for i, r := range results {
		arr[i] = r.JSON()
	}
	_ = enc.Encode(arr)
	if exec_.AnyFailed(results) {
		return 1
	}
	return 0
}

// renderDrift formats a drift report. When ansi is true it uses raw escape
// codes (for the terminal); when false it uses tview color tags (for the
// scrollable viewer).
func renderDrift(results []exec_.Result, groups []exec_.OutputGroup, ansi bool) string {
	col := func(c tcell.Color) string {
		if ansi {
			return theme.ANSI(c)
		}
		return "[" + theme.ColorTag(c) + "]"
	}
	reset := "[-]"
	if ansi {
		reset = theme.Reset()
	}
	primary := col(theme.Current.Primary)
	accent := col(theme.Current.AccentB)
	errc := col(theme.Current.Error)
	dim := col(theme.Current.Dim)

	var b strings.Builder
	fmt.Fprintf(&b, "%s=== drift report ===%s  %d host(s) · %d distinct result(s)\n",
		primary, reset, len(results), len(groups))
	for i, g := range groups {
		head, marker := primary, ""
		if g.Failed {
			head, marker = errc, "  ⚠ failed"
		} else if i > 0 {
			head, marker = accent, "  ⚠ drift"
		}
		label := g.Label
		if !ansi {
			label = tview.Escape(label)
		}
		fmt.Fprintf(&b, "\n%s═══ %d host(s) ═══%s  %s%s%s%s\n",
			head, len(g.Aliases), reset, head, label, reset, marker)
		line := "    "
		for _, a := range g.Aliases {
			if len(line)+len(a)+2 > 76 {
				fmt.Fprintf(&b, "%s%s%s\n", dim, line, reset)
				line = "    "
			}
			line += a + "  "
		}
		if strings.TrimSpace(line) != "" {
			fmt.Fprintf(&b, "%s%s%s\n", dim, line, reset)
		}
	}
	return b.String()
}

// cmdImport pulls hosts into the config from an external source:
//   sshmgr import ssh-config [path]      (default ~/.ssh/config)
//   sshmgr import ansible <inventory>
//   sshmgr import hosts <file>
// Common flags: --group <name>, --dry-run. Existing aliases are never
// overwritten — only new ones are added.
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
func selectAliases(cfg *config.Config, group, tag, hosts string, all bool) []string {
	sel := exec_.Selector{Group: group, Tag: tag, All: all}
	if hosts != "" {
		for _, h := range strings.Split(hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				sel.Hosts = append(sel.Hosts, h)
			}
		}
	}
	aliases := exec_.Select(cfg, sel)
	if len(aliases) == 0 {
		fatal("no hosts matched the selector (try --group, --tag, --host, or --all)")
	}
	return aliases
}

// cmdExport dispatches `sshmgr export <target>`. The only target today is
// `ansible` — an Ansible inventory generated from the fleet.
func cmdExport(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr export ansible [--format yaml|ini] [--group G|--tag T|--host a,b|--all] [--out path]")
	}
	switch args[0] {
	case "ansible":
		cmdExportAnsible(args[1:])
	default:
		fatal("unknown export target %q — use: ansible")
	}
}

func cmdExportAnsible(args []string) {
	fs := flag.NewFlagSet("export ansible", flag.ExitOnError)
	format := fs.String("format", "yaml", "inventory format: yaml | ini")
	group := fs.String("group", "", "select hosts in this group")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias")
	out := fs.String("out", "", "write to this file instead of stdout")
	_ = fs.Parse(args)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("export ansible takes no positional arguments; unexpected: " + strings.Join(extra, " "))
	}

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	aliases := selectAliases(cfg, *group, *tag, *hosts, *all)
	inv, err := ansible.Inventory(cfg, aliases, *format)
	if err != nil {
		fatal(err.Error())
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(inv), 0o644); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] wrote inventory for %d host(s) to %s\n", len(aliases), *out)
		return
	}
	fmt.Print(inv)
}

// multiFlag collects a repeatable string flag (e.g. --extra-vars).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// splitPlaybookArgs separates the playbook argument from the flag tokens, so
// `playbook <file> --group g` works despite Go's flag parser stopping at the
// first non-flag token. The first bare token is the playbook.
func splitPlaybookArgs(args []string) (playbook string, flagArgs []string) {
	valueFlags := map[string]bool{
		"-group": true, "--group": true, "-tag": true, "--tag": true,
		"-host": true, "--host": true, "-limit": true, "--limit": true,
		"-extra-vars": true, "--extra-vars": true,
	}
	var extras []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if valueFlags[a] && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		if playbook == "" {
			playbook = a
		} else {
			extras = append(extras, a)
		}
	}
	return playbook, append(flagArgs, extras...)
}

// cmdPlaybook runs an Ansible playbook against selected hosts: it generates a
// temporary inventory from the fleet and shells out to `ansible-playbook`.
func cmdPlaybook(args []string) {
	playbookArg, flagArgs := splitPlaybookArgs(args)
	if playbookArg == "" {
		fatal("usage: sshmgr playbook <playbook.yml> [--group G|--tag T|--host a,b|--all] [--check] [--diff] [--limit E] [--extra-vars V] [--inventory-debug]")
	}
	fs := flag.NewFlagSet("playbook", flag.ExitOnError)
	group := fs.String("group", "", "select hosts in this group")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias")
	check := fs.Bool("check", false, "run ansible-playbook in --check (dry-run) mode")
	diff := fs.Bool("diff", false, "pass --diff to ansible-playbook")
	limit := fs.String("limit", "", "ansible --limit pattern (further restricts the run)")
	invDebug := fs.Bool("inventory-debug", false, "print the generated inventory and exit")
	var extraVars multiFlag
	fs.Var(&extraVars, "extra-vars", "extra vars for ansible-playbook (repeatable)")
	_ = fs.Parse(flagArgs)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("unexpected argument(s) after the playbook: " + strings.Join(extra, " ") +
			" (one playbook per invocation; scope hosts with --group/--tag/--host)")
	}

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	aliases := selectAliases(cfg, *group, *tag, *hosts, *all)

	inv, err := ansible.Inventory(cfg, aliases, "yaml")
	if err != nil {
		fatal(err.Error())
	}
	if *invDebug {
		fmt.Print(inv)
		return
	}

	pbPath, err := ansible.ResolvePlaybook(playbookArg, cfg.ResolvePlaybooksDir())
	if err != nil {
		fatal(err.Error())
	}
	pbBin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		fatal("ansible-playbook not found in PATH — install Ansible to run playbooks")
	}

	tmp, err := os.CreateTemp("", "sshmgr-inventory-*.yaml")
	if err != nil {
		fatal(err.Error())
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(inv); err != nil {
		tmp.Close()
		fatal(err.Error())
	}
	if err := tmp.Close(); err != nil {
		fatal(err.Error())
	}

	argv := ansible.PlaybookArgv(pbPath, tmpName, ansible.PlaybookOptions{
		Check:     *check,
		Diff:      *diff,
		Limit:     *limit,
		ExtraVars: extraVars,
	})
	fmt.Fprintf(os.Stderr, "[sshmgr] ansible-playbook on %d host(s): %s\n", len(aliases), pbPath)
	cmd := exec.Command(pbBin, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fatal(err.Error())
	}
}

// cmdRotateKey rolls a new SSH key onto a fleet, safely: append the new key,
// verify it works with a key-only connection, and only then (with
// --remove-old) drop the old key. Never removes the old key unless the new
// one is proven to work.
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
func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Int("n", 2, "refresh interval in seconds")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 2 {
		fatal("usage: sshmgr watch [-n SECS] <alias> <command…>")
	}
	alias := rest[0]
	cmd := strings.Join(rest[1:], " ")
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	// watch reconnects every tick. On a Duo-protected host that's a push
	// notification every N seconds — refuse rather than spam (and risk a
	// Duo rate-limit lockout).
	if h.AutoDuoPush {
		fatal("watch reconnects each tick — refusing on a Duo host (" + alias + ") to avoid a push every interval")
	}
	if err := exec_.Watch(cfg, alias, cmd, time.Duration(*interval)*time.Second); err != nil {
		fatal(err.Error())
	}
}

func cmdCompletion(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr completion <bash|zsh|fish>")
	}
	if err := completion.Print(os.Stdout, args[0]); err != nil {
		fatal(err.Error())
	}
}

func cmdHistory(args []string) {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	what := "transfers"
	if len(args) >= 1 {
		what = args[0]
	}
	switch what {
	case "transfers", "xfer":
		if len(cfg.TransferHistory) == 0 {
			fmt.Fprintln(os.Stderr, "no transfers logged yet")
			return
		}
		for _, e := range cfg.TransferHistory {
			arrow := "->"
			a, b := e.Local, e.Remote
			if e.Direction == "down" {
				arrow = "<-"
				a, b = e.Remote, e.Local
			}
			fmt.Printf("%s  %s  %-22s %s %s %s  (%s)\n",
				e.When, e.Direction, e.Alias, a, arrow, b, humanBytes(e.Bytes))
		}
	case "forwards", "fwd":
		if len(cfg.ForwardHistory) == 0 {
			fmt.Fprintln(os.Stderr, "no forwards logged yet")
			return
		}
		for _, e := range cfg.ForwardHistory {
			fmt.Printf("%s  %-22s -%s %s\n", e.LastUsed, e.Alias, e.Type, e.Spec)
		}
	case "logins", "login":
		if len(cfg.LoginHistory) == 0 {
			fmt.Fprintln(os.Stderr, "no logins logged yet")
			return
		}
		for _, e := range cfg.LoginHistory {
			fmt.Printf("%s  %-7s %s\n", e.When, e.Action, e.Alias)
		}
	default:
		fatal("usage: sshmgr history [transfers|forwards|logins]")
	}
}

func humanBytes(n int64) string { return transfer.HumanBytes(n) }

// splitFwdArgs separates the host alias from the -L/-R/-D flag tokens. Go's
// flag parser stops at the first non-flag token, so `fwd <alias> -L <spec>`
// (alias first — the documented form) and `fwd -L <spec> <alias>` must both
// work. The first bare token is the alias; flag tokens are returned first so
// fs.Parse sees them before any stray positional.
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
func recordLogin(alias, action string) {
	cfg, path, err := config.Load()
	if err != nil {
		return
	}
	cfg.LoginHistory = append([]config.LoginEntry{{
		Alias:  alias,
		Action: action,
		When:   time.Now().UTC().Format(time.RFC3339),
	}}, cfg.LoginHistory...)
	if len(cfg.LoginHistory) > 500 {
		cfg.LoginHistory = cfg.LoginHistory[:500]
	}
	_ = config.Save(cfg, path)
}

// persistTransferLog appends a TransferEntry to the config file, capped at 200.
// Best-effort: silently swallows save errors so a flaky write doesn't break
// the user's transfer.
func persistTransferLog(direction, alias, local, remote string, n int64, when time.Time) {
	cfg, path, err := config.Load()
	if err != nil {
		return
	}
	e := config.TransferEntry{
		Alias:     alias,
		Direction: direction,
		Local:     local,
		Remote:    remote,
		Bytes:     n,
		When:      when.UTC().Format(time.RFC3339),
	}
	out := append([]config.TransferEntry{e}, cfg.TransferHistory...)
	if len(out) > 200 {
		out = out[:200]
	}
	cfg.TransferHistory = out
	_ = config.Save(cfg, path)
}

func upsertForward(hist []config.ForwardEntry, e config.ForwardEntry, cap int) []config.ForwardEntry {
	out := make([]config.ForwardEntry, 0, len(hist)+1)
	out = append(out, e)
	for _, h := range hist {
		if h.Alias == e.Alias && h.Type == e.Type && h.Spec == e.Spec {
			continue
		}
		out = append(out, h)
		if len(out) >= cap {
			break
		}
	}
	return out
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

func sessionLogPath(alias string) string {
	dir := os.Getenv("SSHMGR_SESSION_DIR")
	if dir == "" {
		if base := os.Getenv("XDG_DATA_HOME"); base != "" {
			dir = filepath.Join(base, "sshmgr", "sessions")
		} else {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, ".local", "share", "sshmgr", "sessions")
		}
	}
	// Include PID so two operators on the same host within the same second
	// don't share a log file (would interleave their sessions).
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dir, fmt.Sprintf("%s-%s-%d.log", alias, stamp, os.Getpid()))
}

// maybeReturnToUI re-execs `sshmgr ui` when SSHMGR_FROM_UI=1 is set in the
// environment, so a TUI-launched connection drops the user back into the host
// list after the remote shell exits.
func maybeReturnToUI() {
	if os.Getenv("SSHMGR_FROM_UI") != "1" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	env := os.Environ()
	// Keep SSHMGR_FROM_UI=1 so subsequent connect-from-TUI loops work.
	_ = syscall.Exec(exe, []string{"sshmgr", "ui"}, env)
}

func lookPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		p := dir + "/" + name
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found in PATH: %s", name)
}

// parseCompleteArgs interprets the tokens after "__complete". Shells pass the
// partial word followed by already-typed tokens; fish prefixes a literal
// "--" separator, which is dropped.
func parseCompleteArgs(args []string) (passed []string, word string) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return nil, ""
	}
	if len(args) > 1 {
		passed = args[1:]
	}
	return passed, args[0]
}

// rejectExternal aborts when any selected alias is an external host. Used by
// rotate-key, whose native-backend key manipulation has no safe system-ssh
// equivalent — failing fast beats a confusing partial run.
func rejectExternal(cfg *config.Config, aliases []string, cmdName string) {
	if ext := external.Aliases(cfg, aliases); len(ext) > 0 {
		fatal(cmdName + " is not supported for external hosts: " + strings.Join(ext, ", ") +
			" — external hosts use the system ssh client")
	}
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

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	groupFilter := fs.String("group", "", "show only hosts in this group")
	tagFilter := fs.String("tag", "", "show only hosts with this tag")
	_ = fs.Parse(args)

	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if len(cfg.Hosts) == 0 {
		fmt.Fprintf(os.Stderr, "no hosts configured in %s\n", path)
		return
	}
	aliases := make([]string, 0, len(cfg.Hosts))
	for a := range cfg.Hosts {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	matched := 0
	for _, a := range aliases {
		h, _ := cfg.ResolveHost(a)
		if *groupFilter != "" && !containsString(h.Groups, *groupFilter) {
			continue
		}
		if *tagFilter != "" && !containsString(h.Tags, *tagFilter) {
			continue
		}
		tags := ""
		if len(h.Tags) > 0 {
			tags = "  [" + strings.Join(h.Tags, " ") + "]"
		}
		fmt.Printf("%-25s %s@%s:%d%s\n", a, h.User, h.Host, h.Port, tags)
		matched++
	}
	if matched == 0 {
		fmt.Fprintf(os.Stderr, "no hosts match the given filters\n")
	}
}

func cmdGroups() {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	counts := map[string]int{}
	for _, h := range cfg.Hosts {
		for _, g := range h.Groups {
			counts[g]++
		}
	}
	names := make([]string, 0, len(cfg.Groups))
	for g := range cfg.Groups {
		names = append(names, g)
	}
	for g := range counts {
		if _, ok := cfg.Groups[g]; !ok {
			names = append(names, g) // host references a non-defined group; still report it
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "no groups defined")
		return
	}
	for _, g := range names {
		marker := ""
		if _, defined := cfg.Groups[g]; !defined {
			marker = "  (used but not defined)"
		}
		fmt.Printf("%-20s %d host(s)%s\n", g, counts[g], marker)
	}
}

func cmdInfo(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr info <alias>")
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
	out := struct {
		Alias string             `json:"alias"`
		Host  config.HostConfig `json:"host"`
	}{Alias: alias, Host: h}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal(err.Error())
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
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

func prompt(reader *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
