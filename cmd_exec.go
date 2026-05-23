package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"sshmgr/internal/config"
	exec_ "sshmgr/internal/exec"
	"sshmgr/internal/theme"
	"sshmgr/internal/tui"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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

