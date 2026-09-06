package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/config"
	exec_ "github.com/systeampl/sshmgr/internal/exec"
	"github.com/systeampl/sshmgr/internal/projectstate"
)

func cmdAudit(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			auditUsage(os.Stdout)
			return
		case "show", "latest":
			cmdAuditShow(args[1:])
			return
		case "diff":
			cmdAuditDiff(args[1:])
			return
		case "who-has":
			cmdAuditLookup("who-has", args[1:])
			return
		case "where-is-key":
			cmdAuditLookup("where-is-key", args[1:])
			return
		case "push":
			cmdAuditPush(args[1:])
			return
		}
	}
	cmdAuditRun(args)
}

func auditUsage(w *os.File) {
	fmt.Fprintln(w, "sshmgr audit — full, read-only SSH access audit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sshmgr audit (--group G [--group G...]|--tag T|--host a,b|--all) [--push]")
	fmt.Fprintln(w, "  sshmgr audit show")
	fmt.Fprintln(w, "  sshmgr audit diff")
	fmt.Fprintln(w, "  sshmgr audit who-has <host>")
	fmt.Fprintln(w, "  sshmgr audit where-is-key <SHA256:...>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The default audit uses system scope, sudo -n, local accounts, bounded reads,")
	fmt.Fprintln(w, "and fingerprints only. It always stores a private immutable snapshot locally.")
	fmt.Fprintln(w, "No data leaves this machine unless --push (or `audit push`) is explicit.")
}

func cmdAuditRun(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	var groups accessGroupFlags
	fs.Var(&groups, "group", "select the union of this group; may be repeated")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias in the config")
	excludeHosts := fs.String("exclude-host", "", "comma-separated aliases to exclude")
	excludeTags := fs.String("exclude-tag", "", "comma-separated tags to exclude")
	push := fs.Bool("push", false, "show privacy preview and explicitly upload the redacted result")
	out := fs.String("out", "", "export an additional copy; private state is always written")
	parallel := fs.Int("p", 4, "maximum concurrent connections")
	timeout := fs.Duration("timeout", 45*time.Second, "per-host timeout")
	requireFull := fs.Bool("require-full", false, "exit 2 when any host lacks full coverage")
	failOn := fs.String("fail-on", "", "exit 2 at or above: critical | high | medium | low | info")
	dryRun := fs.Bool("dry-run", false, "resolve targets without connecting or writing state")
	_ = fs.Parse(args)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("audit takes no positional arguments; unexpected: " + strings.Join(extra, " "))
	}
	if *parallel < 1 || *timeout <= 0 {
		fatal("audit requires -p >= 1 and --timeout > 0")
	}
	failOnSeverity, err := access.NormalizeFailOnSeverity(*failOn)
	if err != nil {
		fatal(err.Error())
	}
	if *dryRun && (*push || *out != "" || failOnSeverity != "") {
		fatal("--dry-run cannot be combined with --push, --out, or --fail-on")
	}

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	selector := exec_.Selector{Groups: []string(groups), Tag: strings.TrimSpace(*tag), Hosts: splitCSV(*hosts), All: *all}
	if err := exec_.ValidateSelector(cfg, selector); err != nil {
		fatal(err.Error())
	}
	matched := exec_.Select(cfg, selector)
	selected, excluded, err := excludeAccessHosts(cfg, matched, splitCSV(*excludeHosts), splitCSV(*excludeTags))
	if err != nil {
		fatal(err.Error())
	}
	if len(selected) == 0 {
		fatal("no hosts matched the selector after exclusions")
	}
	printAccessTargets(selected, excluded, splitCSV(*excludeHosts), splitCSV(*excludeTags), *dryRun, false)
	if *dryRun {
		return
	}

	accountMode, accounts, maxAccounts, err := access.NormalizeSystemAccountSelection(access.AccountModeLocal, nil, 0)
	if err != nil {
		fatal(err.Error())
	}
	maxSourceBytes, maxTotalBytes, err := access.NormalizeSystemCollectionLimits(0, 0)
	if err != nil {
		fatal(err.Error())
	}
	options := access.ScanOptions{
		Parallel: *parallel, Timeout: *timeout, ScannerVersion: currentBuildInfo().Version,
		Selector: accessSelectorDescription(selector), HostExclusions: splitCSV(*excludeHosts),
		TagExclusions: splitCSV(*excludeTags), ExcludedMatched: excluded, UseSudo: true,
		AccountMode: accountMode, Accounts: accounts, MaxAccounts: maxAccounts,
		MaxSourceBytes: maxSourceBytes, MaxTotalBytes: maxTotalBytes,
	}
	snapshot := access.ScanSystem(context.Background(), cfg, selected, options)
	paths, err := projectstate.ResolveActive()
	if err != nil {
		fatal(err.Error())
	}
	statePath, err := projectstate.StoreAudit(paths, snapshot)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] private audit stored at %s (mode 0600)\n", statePath)
	if strings.TrimSpace(*out) != "" {
		if sameAccessPath(statePath, *out) {
			fatal("--out must not overwrite the immutable private audit")
		}
		if err := access.WriteSnapshot(*out, snapshot); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] audit exported to %s (mode 0600)\n", *out)
	}
	fmt.Print(access.RenderText(snapshot))
	if *push {
		fmt.Fprintln(os.Stderr, "[sshmgr] --push explicitly enables one redacted Cloud upload; privacy preview follows")
		cmdCloudPush([]string{statePath, "--yes"})
	}
	if snapshot.Summary.HostsFailed == snapshot.Summary.HostsRequested {
		os.Exit(1)
	}
	if *requireFull && (snapshot.Summary.HostsPartial > 0 || snapshot.Summary.HostsFailed > 0) {
		os.Exit(2)
	}
	exitOnAccessFindingPolicy(snapshot.Findings, failOnSeverity)
}

func cmdAuditShow(args []string) {
	if len(args) > 1 {
		fatal("usage: sshmgr audit show [SCAN_ID]")
	}
	path := resolveAuditPath(singleArgument(args))
	snapshot, err := access.ReadSnapshot(path)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderText(snapshot))
	fmt.Fprintf(os.Stderr, "[sshmgr] private audit: %s\n", path)
}

func cmdAuditDiff(args []string) {
	paths, err := auditDiffPaths(args)
	if err != nil {
		fatal(err.Error())
	}
	before, err := access.ReadSnapshot(paths[0])
	if err != nil {
		fatal(err.Error())
	}
	after, err := access.ReadSnapshot(paths[1])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderDiffText(access.SemanticDiff(before, after)))
}

func cmdAuditLookup(command string, args []string) {
	if len(args) != 1 {
		fatal("usage: sshmgr audit " + command + " <value>")
	}
	path := resolveAuditPath("")
	if command == "who-has" {
		cmdAccessWhoHas([]string{args[0], "--scan", path})
		return
	}
	cmdAccessWhereIsKey([]string{args[0], "--scan", path})
}

func cmdAuditPush(args []string) {
	fs := flag.NewFlagSet("audit push", flag.ExitOnError)
	profile := fs.String("profile", "", "Cloud profile name")
	timeout := fs.Duration("timeout", 2*time.Minute, "Cloud request timeout")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 {
		fatal("usage: sshmgr audit push [--profile NAME] [--timeout 2m]")
	}
	path := resolveAuditPath("")
	pushArgs := []string{path, "--yes", "--timeout", timeout.String()}
	if strings.TrimSpace(*profile) != "" {
		pushArgs = append(pushArgs, "--profile", *profile)
	}
	fmt.Fprintln(os.Stderr, "[sshmgr] explicit audit push requested; privacy preview follows")
	cmdCloudPush(pushArgs)
}

func resolveAuditPath(id string) string {
	paths, err := projectstate.ResolveActive()
	if err != nil {
		fatal(err.Error())
	}
	id = strings.TrimSpace(id)
	if id == "" {
		path, err := projectstate.LatestAudit(paths)
		if err != nil {
			fatal(err.Error())
		}
		return path
	}
	if strings.ContainsAny(id, `/\\`) || !strings.HasPrefix(id, "scan_") {
		fatal("audit ID must start with scan_ and must not contain a path")
	}
	return filepath.Join(paths.Audits, id+".json")
}

func auditDiffPaths(args []string) ([2]string, error) {
	var result [2]string
	switch len(args) {
	case 0:
		paths, err := projectstate.ResolveActive()
		if err != nil {
			return result, err
		}
		recent, err := projectstate.RecentAudits(paths)
		if err != nil {
			return result, err
		}
		if len(recent) < 2 {
			return result, fmt.Errorf("audit diff needs two stored audits; found %d", len(recent))
		}
		return [2]string{recent[1], recent[0]}, nil
	case 1:
		return [2]string{resolveAuditPath(args[0]), resolveAuditPath("")}, nil
	case 2:
		return [2]string{resolveAuditPath(args[0]), resolveAuditPath(args[1])}, nil
	default:
		return result, fmt.Errorf("usage: sshmgr audit diff [BEFORE_SCAN_ID [AFTER_SCAN_ID]]")
	}
}

func singleArgument(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return ""
}
