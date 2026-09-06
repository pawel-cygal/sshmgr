package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/config"
	exec_ "github.com/systeampl/sshmgr/internal/exec"
)

func cmdAccess(args []string) {
	if len(args) == 0 {
		accessUsage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "-h", "--help", "help":
		if len(args) == 2 && args[1] == "--all" {
			accessAdvancedUsage(os.Stdout)
		} else if len(args) == 1 {
			accessUsage(os.Stdout)
		} else {
			fatal("usage: sshmgr access help [--all]")
		}
	case "scan":
		cmdAccessScan(args[1:])
	case "invite":
		cmdAccessInvite(args[1:])
	case "status":
		cmdAccessStatus(args[1:])
	case "approve":
		cmdAccessApprove(args[1:])
	case "revoke":
		cmdAccessRevoke(args[1:])
	case "sync":
		cmdAccessSync(args[1:])
	case "plan":
		cmdAccessPlan(args[1:])
	case "apply":
		cmdAccessApply(args[1:])
	case "export":
		cmdAccessExport(args[1:])
	case "report":
		cmdAccessReport(args[1:])
	case "graph":
		cmdAccessGraph(args[1:])
	case "merge":
		cmdAccessMerge(args[1:])
	case "identity-map":
		cmdAccessIdentityMap(args[1:])
	case "review":
		cmdAccessReview(args[1:])
	case "offboarding":
		cmdAccessOffboarding(args[1:])
	case "offboarding-check":
		cmdAccessOffboardingCheck(args[1:])
	case "diff":
		cmdAccessDiff(args[1:])
	case "where-is-key":
		cmdAccessWhereIsKey(args[1:])
	case "who-has":
		cmdAccessWhoHas(args[1:])
	default:
		fatal(fmt.Sprintf("unknown access command %q — use `sshmgr access help` or `sshmgr access help --all`", args[0]))
	}
}

func accessUsage(w io.Writer) {
	fmt.Fprintln(w, "sshmgr access — SSH access lifecycle")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Common workflow:")
	fmt.Fprintln(w, "  1. Observe:   sshmgr audit --group G [--push]")
	fmt.Fprintln(w, "  2. Grant:     sshmgr access invite EMAIL --group G --account USER --ttl 30d")
	fmt.Fprintln(w, "                sshmgr access status [EMAIL|INVITE_ID]")
	fmt.Fprintln(w, "                sshmgr access approve INVITE_ID")
	fmt.Fprintln(w, "  3. Reconcile: sshmgr access sync (--group G|--tag T|--host a,b|--all)")
	fmt.Fprintln(w, "  4. Revoke:    sshmgr access revoke EMAIL (--group G|--tag T|--host a,b|--all)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Safety: invite/approve/revoke change desired state only. `sync` shows an exact")
	fmt.Fprintln(w, "host-change plan and requires its ID before applying with backup and rollback.")
	fmt.Fprintln(w, "Run `sshmgr access help --all` for scan, reports, merge, plan, and apply.")
}

func accessAdvancedUsage(w io.Writer) {
	fmt.Fprintln(w, "sshmgr access — lifecycle and complete expert API")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sshmgr access invite EMAIL --group G --account USER --ttl 30d")
	fmt.Fprintln(w, "  sshmgr access status [EMAIL|INVITE_ID]")
	fmt.Fprintln(w, "  sshmgr access approve INVITE_ID")
	fmt.Fprintln(w, "  sshmgr access revoke EMAIL [selector]")
	fmt.Fprintln(w, "  sshmgr access sync [selector]")
	fmt.Fprintln(w, "  sshmgr access plan [selector] --out access.plan")
	fmt.Fprintln(w, "  sshmgr access apply access.plan")
	fmt.Fprintln(w, "  sshmgr access export ansible access.plan --out playbook.yml")
	fmt.Fprintln(w, "  sshmgr access scan [--group G [--group G...]|--tag T|--host a,b|--all] --out scan.json [--fail-on SEVERITY]")
	fmt.Fprintln(w, "  sshmgr access scan --host H --sudo --preflight --out preflight.json")
	fmt.Fprintln(w, "  sshmgr access scan --host H --sudo --accounts explicit --account root,deploy --out scan.json")
	fmt.Fprintln(w, "  sshmgr access scan --host H --sudo --preflight --accounts explicit --account root,deploy")
	fmt.Fprintln(w, "  sshmgr access report <scan.json> [--html report.html] [--csv access.csv] [--fail-on SEVERITY]")
	fmt.Fprintln(w, "  sshmgr access graph <scan.json> [--json graph.json]")
	fmt.Fprintln(w, "  sshmgr access merge <scan1.json> <scan2.json> [...] --out merged.json")
	fmt.Fprintln(w, "  sshmgr access identity-map <scan.json> --out identities.yaml")
	fmt.Fprintln(w, "  sshmgr access review <scan.json> --identities identities.yaml [exports] [--fail-on SEVERITY]")
	fmt.Fprintln(w, "  sshmgr access offboarding <identity> --scan scan.json --review review.json [--json report.json] [--html report.html] [--csv report.csv]")
	fmt.Fprintln(w, "  sshmgr access offboarding-check --baseline report.json --before-scan scan.json --before-review review.json --after-scan scan.json --after-review review.json [exports]")
	fmt.Fprintln(w, "  sshmgr access diff <before.json> <after.json>")
	fmt.Fprintln(w, "  sshmgr access who-has <host> --scan scan.json")
	fmt.Fprintln(w, "  sshmgr access where-is-key <SHA256:...> --scan scan.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Current-account scans inspect default authorized_keys paths. System preflight")
	fmt.Fprintln(w, "enumerates bounded account metadata and expands effective sshd sources through")
	fmt.Fprintln(w, "sudo -n. Without --preflight, system scope reads bounded static key files.")
	fmt.Fprintln(w, "Account modes: local (default, /etc/passwd), nss (explicit opt-in), explicit.")
	fmt.Fprintln(w, "Both modes are agentless, read-only, and never upload data.")
	fmt.Fprintln(w, "Identity maps are explicit local claims; comments never become verified owners.")
	fmt.Fprintln(w, "--fail-on is opt-in; high matches high and critical findings and exits 2.")
}

func cmdAccessDiff(args []string) {
	if len(args) != 2 {
		fatal("usage: sshmgr access diff <before.json> <after.json>")
	}
	before, err := access.ReadSnapshot(args[0])
	if err != nil {
		fatal(err.Error())
	}
	after, err := access.ReadSnapshot(args[1])
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderDiffText(access.SemanticDiff(before, after)))
}

func cmdAccessScan(args []string) {
	fs := flag.NewFlagSet("access scan", flag.ExitOnError)
	var groups accessGroupFlags
	fs.Var(&groups, "group", "select the union of this group; may be repeated")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias in the config")
	excludeHosts := fs.String("exclude-host", "", "comma-separated aliases to exclude")
	excludeTags := fs.String("exclude-tag", "", "comma-separated tags to exclude")
	scope := fs.String("scope", "current", "scan scope: current | system")
	sudo := fs.Bool("sudo", false, "shorthand for --scope system using sudo -n")
	dryRun := fs.Bool("dry-run", false, "resolve and print targets without connecting")
	preflight := fs.Bool("preflight", false, "check connectivity and source metadata without reading key contents")
	requireFull := fs.Bool("require-full", false, "exit 2 when any host has partial coverage")
	failOn := fs.String("fail-on", "", "exit 2 when findings meet this severity: critical | high | medium | low | info")
	out := fs.String("out", "", "write the JSON snapshot to this path")
	format := fs.String("format", "json", "snapshot format (json)")
	parallel := fs.Int("p", 4, "maximum concurrent connections")
	timeout := fs.Duration("timeout", 45*time.Second, "per-host timeout")
	includePublicKeys := fs.Bool("include-public-keys", false, "include normalized public keys; fingerprints only by default")
	accountMode := fs.String("accounts", access.AccountModeLocal, "system account source: local | nss | explicit")
	accountNames := fs.String("account", "", "comma-separated accounts for --accounts explicit")
	maxAccounts := fs.Int("max-accounts", 0, "per-host account budget; 0 uses the mode default")
	maxSourceMiB := fs.Int64("max-source-mib", 0, "system scan per-file read budget in MiB; 0 uses 4 MiB")
	maxTotalMiB := fs.Int64("max-total-mib", 0, "system scan total read budget per host in MiB; 0 uses 16 MiB")
	_ = fs.Parse(args)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("access scan takes no positional arguments; unexpected: " + strings.Join(extra, " "))
	}
	failOnSeverity, err := access.NormalizeFailOnSeverity(*failOn)
	if err != nil {
		fatal(err.Error())
	}
	if *dryRun && failOnSeverity != "" {
		fatal("--fail-on cannot be used with --dry-run because no findings are produced")
	}
	if *sudo {
		if *scope != "current" && *scope != "system" {
			fatal("--sudo cannot be combined with an unsupported --scope")
		}
		*scope = "system"
	}
	if *scope != "current" && *scope != "system" {
		fatal("unsupported scan scope: " + *scope + " (use current or system)")
	}
	if *preflight && *includePublicKeys {
		fatal("--include-public-keys is not used by preflight scans")
	}
	requestedAccounts := splitCSV(*accountNames)
	if *scope != "system" && (*accountMode != access.AccountModeLocal || len(requestedAccounts) > 0 || *maxAccounts != 0) {
		fatal("--accounts, --account, and --max-accounts apply only to --scope system/--sudo")
	}
	if *scope != "system" && (*maxSourceMiB != 0 || *maxTotalMiB != 0) {
		fatal("--max-source-mib and --max-total-mib apply only to --scope system/--sudo")
	}
	if *preflight && (*maxSourceMiB != 0 || *maxTotalMiB != 0) {
		fatal("system content read budgets do not apply to --preflight")
	}
	if len(requestedAccounts) > 0 && *accountMode == access.AccountModeLocal {
		*accountMode = access.AccountModeExplicit
	}
	if *scope == "system" {
		var normalizeErr error
		*accountMode, requestedAccounts, *maxAccounts, normalizeErr = access.NormalizeSystemAccountSelection(*accountMode, requestedAccounts, *maxAccounts)
		if normalizeErr != nil {
			fatal(normalizeErr.Error())
		}
	} else {
		*accountMode = ""
		requestedAccounts = nil
		*maxAccounts = 0
	}
	if *maxSourceMiB < 0 || *maxSourceMiB > 16 {
		fatal("--max-source-mib must be between 1 and 16 (or 0 for the default)")
	}
	if *maxTotalMiB < 0 || *maxTotalMiB > 64 {
		fatal("--max-total-mib must be between 1 and 64 (or 0 for the default)")
	}
	maxSourceBytes := *maxSourceMiB << 20
	maxTotalBytes := *maxTotalMiB << 20
	if *scope == "system" && !*preflight {
		var limitErr error
		maxSourceBytes, maxTotalBytes, limitErr = access.NormalizeSystemCollectionLimits(maxSourceBytes, maxTotalBytes)
		if limitErr != nil {
			fatal(limitErr.Error())
		}
	} else {
		maxSourceBytes = 0
		maxTotalBytes = 0
	}
	if *format != "json" {
		fatal("unsupported snapshot format: " + *format + " (use json)")
	}
	if *parallel < 1 {
		fatal("-p must be at least 1")
	}
	if *timeout <= 0 {
		fatal("--timeout must be greater than zero")
	}
	if !*dryRun && !*preflight && *out == "" {
		fatal("access scan requires --out <snapshot.json> (or use --dry-run/--preflight)")
	}

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	selector := exec_.Selector{Groups: []string(groups), Tag: *tag, Hosts: splitCSV(*hosts), All: *all}
	if err := exec_.ValidateSelector(cfg, selector); err != nil {
		fatal(err.Error())
	}
	matched := exec_.Select(cfg, selector)
	if len(matched) == 0 {
		fatal("no hosts matched the selector")
	}
	hostExclusions := splitCSV(*excludeHosts)
	tagExclusions := splitCSV(*excludeTags)
	selected, excluded, err := excludeAccessHosts(cfg, matched, hostExclusions, tagExclusions)
	if err != nil {
		fatal(err.Error())
	}
	if len(selected) == 0 {
		fatal("all matched hosts were excluded")
	}
	printAccessTargets(selected, excluded, hostExclusions, tagExclusions, *dryRun, *preflight)
	if *scope == "system" {
		fmt.Fprintf(os.Stderr, "[sshmgr] system accounts: mode=%s max=%d", *accountMode, *maxAccounts)
		if len(requestedAccounts) > 0 {
			fmt.Fprintf(os.Stderr, " requested=%s", strings.Join(requestedAccounts, ","))
		}
		fmt.Fprintln(os.Stderr)
		if !*preflight {
			fmt.Fprintf(os.Stderr, "[sshmgr] system source budgets: per-file=%d bytes per-host=%d bytes\n", maxSourceBytes, maxTotalBytes)
		}
	}
	if *dryRun {
		return
	}

	options := access.ScanOptions{
		Parallel:          *parallel,
		Timeout:           *timeout,
		IncludePublicKeys: *includePublicKeys,
		Preflight:         *preflight,
		ScannerVersion:    currentBuildInfo().Version,
		Selector:          accessSelectorDescription(selector),
		HostExclusions:    hostExclusions,
		TagExclusions:     tagExclusions,
		ExcludedMatched:   excluded,
		UseSudo:           *sudo,
		AccountMode:       *accountMode,
		Accounts:          requestedAccounts,
		MaxAccounts:       *maxAccounts,
		MaxSourceBytes:    maxSourceBytes,
		MaxTotalBytes:     maxTotalBytes,
	}
	var snapshot *access.Snapshot
	if *scope == "system" {
		if *preflight {
			snapshot = access.ScanSystemPreflight(context.Background(), cfg, selected, options)
		} else {
			snapshot = access.ScanSystem(context.Background(), cfg, selected, options)
		}
	} else {
		snapshot = access.ScanCurrent(context.Background(), cfg, selected, options)
	}
	if *out != "" {
		if err := access.WriteSnapshot(*out, snapshot); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] snapshot written to %s (mode 0600)\n", *out)
	}
	fmt.Print(access.RenderText(snapshot))
	if snapshot.Summary.HostsFailed == snapshot.Summary.HostsRequested {
		os.Exit(1)
	}
	if *requireFull && (snapshot.Summary.HostsPartial > 0 || snapshot.Summary.HostsFailed > 0) {
		os.Exit(2)
	}
	exitOnAccessFindingPolicy(snapshot.Findings, failOnSeverity)
}

func cmdAccessReport(args []string) {
	snapshotPath, flagArgs, extras := splitAccessOnePositional(args, map[string]bool{
		"-html": true, "--html": true, "-csv": true, "--csv": true, "-fail-on": true, "--fail-on": true,
	})
	if snapshotPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr access report <snapshot.json> [--html report.html] [--csv access.csv] [--fail-on SEVERITY]")
	}
	fs := flag.NewFlagSet("access report", flag.ExitOnError)
	htmlPath := fs.String("html", "", "write a self-contained HTML report")
	csvPath := fs.String("csv", "", "write deterministic observed access edges as CSV")
	failOn := fs.String("fail-on", "", "exit 2 when findings meet this severity: critical | high | medium | low | info")
	_ = fs.Parse(flagArgs)
	failOnSeverity, err := access.NormalizeFailOnSeverity(*failOn)
	if err != nil {
		fatal(err.Error())
	}
	snapshot, err := access.ReadSnapshot(snapshotPath)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderText(snapshot))
	if *htmlPath != "" {
		if err := access.WriteHTMLReport(*htmlPath, snapshot); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] HTML report written to %s (mode 0600)\n", *htmlPath)
	}
	if *csvPath != "" {
		if err := access.WriteAccessCSV(*csvPath, snapshot); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] access CSV written to %s (mode 0600)\n", *csvPath)
	}
	exitOnAccessFindingPolicy(snapshot.Findings, failOnSeverity)
}

func cmdAccessGraph(args []string) {
	snapshotPath, flagArgs, extras := splitAccessOnePositional(args, map[string]bool{"-json": true, "--json": true})
	if snapshotPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr access graph <snapshot.json> [--json graph.json]")
	}
	fs := flag.NewFlagSet("access graph", flag.ExitOnError)
	jsonPath := fs.String("json", "", "write the normalized access graph as JSON")
	_ = fs.Parse(flagArgs)
	snapshot, err := access.ReadSnapshot(snapshotPath)
	if err != nil {
		fatal(err.Error())
	}
	graph, err := access.BuildAccessGraph(snapshot)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderAccessGraphText(graph))
	if *jsonPath != "" {
		if err := access.WriteAccessGraphJSON(*jsonPath, graph); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] access graph JSON written to %s (mode 0600)\n", *jsonPath)
	}
}

func cmdAccessMerge(args []string) {
	inputs, flagArgs := splitAccessPositionals(args, map[string]bool{"-out": true, "--out": true})
	if len(inputs) < 2 {
		fatal("usage: sshmgr access merge <scan1.json> <scan2.json> [...] --out merged.json")
	}
	fs := flag.NewFlagSet("access merge", flag.ExitOnError)
	out := fs.String("out", "", "write the merged snapshot to this path")
	_ = fs.Parse(flagArgs)
	if *out == "" {
		fatal("access merge requires --out <merged.json>")
	}
	for _, input := range inputs {
		if sameAccessPath(input, *out) {
			fatal("access merge output must not overwrite an input snapshot: " + input)
		}
	}

	snapshots := make([]*access.Snapshot, 0, len(inputs))
	for _, path := range inputs {
		snapshot, err := access.ReadSnapshot(path)
		if err != nil {
			fatal(err.Error())
		}
		snapshots = append(snapshots, snapshot)
	}
	merged, err := access.MergeSnapshots(currentBuildInfo().Version, snapshots...)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteSnapshot(*out, merged); err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderText(merged))
	fmt.Fprintf(os.Stderr, "[sshmgr] merged %d snapshots into %s (mode 0600)\n", len(inputs), *out)
}

func cmdAccessIdentityMap(args []string) {
	snapshotPath, flagArgs, extras := splitAccessOnePositional(args, map[string]bool{"-out": true, "--out": true})
	if snapshotPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr access identity-map <snapshot.json> --out identities.yaml")
	}
	fs := flag.NewFlagSet("access identity-map", flag.ExitOnError)
	out := fs.String("out", "", "write an explicit local identity-map template")
	_ = fs.Parse(flagArgs)
	*out = strings.TrimSpace(*out)
	if *out == "" {
		fatal("access identity-map requires --out <identities.yaml>")
	}
	if sameAccessPath(snapshotPath, *out) {
		fatal("identity map output must not overwrite the input snapshot")
	}
	snapshot, err := access.ReadSnapshot(snapshotPath)
	if err != nil {
		fatal(err.Error())
	}
	identityMap, err := access.BuildIdentityMapTemplate(snapshot)
	if err != nil {
		fatal(err.Error())
	}
	if err := access.WriteIdentityMap(*out, identityMap); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Identity map template\n  Observed fingerprints: %d\n  Assigned claims:       0\n", len(identityMap.Keys))
	fmt.Fprintf(os.Stderr, "[sshmgr] identity map template written to %s (mode 0600)\n", *out)
}

func cmdAccessReview(args []string) {
	valueFlags := map[string]bool{
		"-identities": true, "--identities": true, "-json": true, "--json": true,
		"-html": true, "--html": true, "-csv": true, "--csv": true, "-fail-on": true, "--fail-on": true,
	}
	snapshotPath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if snapshotPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr access review <snapshot.json> --identities identities.yaml [--json review.json] [--html review.html] [--csv review.csv] [--fail-on SEVERITY]")
	}
	fs := flag.NewFlagSet("access review", flag.ExitOnError)
	identitiesPath := fs.String("identities", "", "validated local identity map YAML")
	jsonPath := fs.String("json", "", "write deterministic ownership review JSON")
	htmlPath := fs.String("html", "", "write self-contained ownership review HTML")
	csvPath := fs.String("csv", "", "write deterministic ownership review CSV")
	failOn := fs.String("fail-on", "", "exit 2 when ownership findings meet this severity: critical | high | medium | low | info")
	_ = fs.Parse(flagArgs)
	*identitiesPath = strings.TrimSpace(*identitiesPath)
	*jsonPath = strings.TrimSpace(*jsonPath)
	*htmlPath = strings.TrimSpace(*htmlPath)
	*csvPath = strings.TrimSpace(*csvPath)
	failOnSeverity, err := access.NormalizeFailOnSeverity(*failOn)
	if err != nil {
		fatal(err.Error())
	}
	if *identitiesPath == "" {
		fatal("access review requires --identities <identities.yaml>")
	}
	if err := validateAccessReviewPaths(snapshotPath, *identitiesPath, map[string]string{
		"JSON": *jsonPath, "HTML": *htmlPath, "CSV": *csvPath,
	}); err != nil {
		fatal(err.Error())
	}
	snapshot, err := access.ReadSnapshot(snapshotPath)
	if err != nil {
		fatal(err.Error())
	}
	identityMap, err := access.ReadIdentityMap(*identitiesPath)
	if err != nil {
		fatal(err.Error())
	}
	review, err := access.BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderOwnershipReviewText(review))
	if *jsonPath != "" {
		if err := access.WriteOwnershipReviewJSON(*jsonPath, review); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] ownership review JSON written to %s (mode 0600)\n", *jsonPath)
	}
	if *htmlPath != "" {
		if err := access.WriteOwnershipReviewHTML(*htmlPath, review); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] ownership review HTML written to %s (mode 0600)\n", *htmlPath)
	}
	if *csvPath != "" {
		if err := access.WriteOwnershipReviewCSV(*csvPath, review); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] ownership review CSV written to %s (mode 0600)\n", *csvPath)
	}
	exitOnAccessFindingPolicy(review.Findings, failOnSeverity)
}

func exitOnAccessFindingPolicy(findings []access.Finding, threshold string) {
	matched, err := access.CountFindingsAtOrAbove(findings, threshold)
	if err != nil {
		fatal(err.Error())
	}
	if matched == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] --fail-on %s matched %d finding(s); exiting with status 2\n", threshold, matched)
	os.Exit(2)
}

func validateAccessReviewPaths(snapshotPath, identitiesPath string, outputs map[string]string) error {
	inputs := []string{snapshotPath, identitiesPath}
	seen := map[string]string{}
	labels := make([]string, 0, len(outputs))
	for label := range outputs {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		path := outputs[label]
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		for _, input := range inputs {
			if sameAccessPath(path, input) {
				return fmt.Errorf("ownership review %s output must not overwrite input %s", strings.ToLower(label), input)
			}
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			absolute = filepath.Clean(path)
		}
		absolute = filepath.Clean(absolute)
		if previous, exists := seen[absolute]; exists {
			return fmt.Errorf("ownership review %s and %s outputs resolve to the same path", previous, label)
		}
		seen[absolute] = label
	}
	return nil
}

func cmdAccessOffboarding(args []string) {
	valueFlags := map[string]bool{
		"-scan": true, "--scan": true, "-review": true, "--review": true,
		"-json": true, "--json": true, "-html": true, "--html": true, "-csv": true, "--csv": true,
	}
	identityID, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if identityID == "" || len(extras) > 0 {
		fatal("usage: sshmgr access offboarding <identity> --scan scan.json --review review.json [--json report.json] [--html report.html] [--csv report.csv]")
	}
	fs := flag.NewFlagSet("access offboarding", flag.ExitOnError)
	scanPath := fs.String("scan", "", "validated access snapshot JSON")
	reviewPath := fs.String("review", "", "validated ownership review JSON for the snapshot")
	jsonPath := fs.String("json", "", "write deterministic read-only offboarding report JSON")
	htmlPath := fs.String("html", "", "write self-contained read-only offboarding report HTML")
	csvPath := fs.String("csv", "", "write deterministic read-only offboarding evidence CSV")
	_ = fs.Parse(flagArgs)
	identityID = strings.TrimSpace(identityID)
	*scanPath = strings.TrimSpace(*scanPath)
	*reviewPath = strings.TrimSpace(*reviewPath)
	*jsonPath = strings.TrimSpace(*jsonPath)
	*htmlPath = strings.TrimSpace(*htmlPath)
	*csvPath = strings.TrimSpace(*csvPath)
	if *scanPath == "" || *reviewPath == "" {
		fatal("access offboarding requires --scan scan.json and --review review.json")
	}
	if err := validateOffboardingOutputPaths([]string{*scanPath, *reviewPath}, map[string]string{
		"JSON": *jsonPath, "HTML": *htmlPath, "CSV": *csvPath,
	}); err != nil {
		fatal(err.Error())
	}
	snapshot, err := access.ReadSnapshot(*scanPath)
	if err != nil {
		fatal(err.Error())
	}
	review, err := access.ReadOwnershipReview(*reviewPath)
	if err != nil {
		fatal(err.Error())
	}
	report, err := access.BuildOffboardingReport(snapshot, review, identityID)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderOffboardingReportText(report))
	if *jsonPath != "" {
		if err := access.WriteOffboardingReportJSON(*jsonPath, report); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] read-only offboarding report JSON written to %s (mode 0600)\n", *jsonPath)
	}
	if *htmlPath != "" {
		if err := access.WriteOffboardingReportHTML(*htmlPath, report); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] read-only offboarding report HTML written to %s (mode 0600)\n", *htmlPath)
	}
	if *csvPath != "" {
		if err := access.WriteOffboardingReportCSV(*csvPath, report); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] read-only offboarding report CSV written to %s (mode 0600)\n", *csvPath)
	}
}

func validateOffboardingOutputPaths(inputs []string, outputs map[string]string) error {
	type namedPath struct {
		label string
		path  string
	}
	var seen []namedPath
	labels := make([]string, 0, len(outputs))
	for label := range outputs {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		path := strings.TrimSpace(outputs[label])
		if path == "" {
			continue
		}
		for _, input := range inputs {
			if sameAccessPath(path, input) {
				return fmt.Errorf("offboarding %s output must not overwrite input %s", strings.ToLower(label), input)
			}
		}
		for _, previous := range seen {
			if sameAccessPath(path, previous.path) {
				return fmt.Errorf("offboarding %s and %s outputs resolve to the same path", previous.label, label)
			}
		}
		seen = append(seen, namedPath{label: label, path: path})
	}
	return nil
}

func cmdAccessOffboardingCheck(args []string) {
	fs := flag.NewFlagSet("access offboarding-check", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "validated baseline offboarding report JSON")
	beforeScanPath := fs.String("before-scan", "", "snapshot used to create the baseline report")
	beforeReviewPath := fs.String("before-review", "", "ownership review used to create the baseline report")
	afterScanPath := fs.String("after-scan", "", "fresh post-action access snapshot")
	afterReviewPath := fs.String("after-review", "", "ownership review derived from the post-action snapshot")
	jsonPath := fs.String("json", "", "write deterministic offboarding-check JSON")
	htmlPath := fs.String("html", "", "write self-contained offboarding-check HTML")
	csvPath := fs.String("csv", "", "write deterministic offboarding-check CSV")
	_ = fs.Parse(args)
	if len(fs.Args()) > 0 {
		fatal("access offboarding-check takes flags only; unexpected: " + strings.Join(fs.Args(), " "))
	}
	for _, value := range []*string{baselinePath, beforeScanPath, beforeReviewPath, afterScanPath, afterReviewPath, jsonPath, htmlPath, csvPath} {
		*value = strings.TrimSpace(*value)
	}
	if *baselinePath == "" || *beforeScanPath == "" || *beforeReviewPath == "" || *afterScanPath == "" || *afterReviewPath == "" {
		fatal("access offboarding-check requires --baseline, --before-scan, --before-review, --after-scan, and --after-review")
	}
	inputs := []string{*baselinePath, *beforeScanPath, *beforeReviewPath, *afterScanPath, *afterReviewPath}
	if err := validateOffboardingOutputPaths(inputs, map[string]string{"JSON": *jsonPath, "HTML": *htmlPath, "CSV": *csvPath}); err != nil {
		fatal(err.Error())
	}
	baseline, err := access.ReadOffboardingReport(*baselinePath)
	if err != nil {
		fatal(err.Error())
	}
	beforeSnapshot, err := access.ReadSnapshot(*beforeScanPath)
	if err != nil {
		fatal(err.Error())
	}
	beforeReview, err := access.ReadOwnershipReview(*beforeReviewPath)
	if err != nil {
		fatal(err.Error())
	}
	afterSnapshot, err := access.ReadSnapshot(*afterScanPath)
	if err != nil {
		fatal(err.Error())
	}
	afterReview, err := access.ReadOwnershipReview(*afterReviewPath)
	if err != nil {
		fatal(err.Error())
	}
	check, err := access.BuildOffboardingCheck(baseline, beforeSnapshot, beforeReview, afterSnapshot, afterReview)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderOffboardingCheckText(check))
	if *jsonPath != "" {
		if err := access.WriteOffboardingCheckJSON(*jsonPath, check); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] read-only offboarding check JSON written to %s (mode 0600)\n", *jsonPath)
	}
	if *htmlPath != "" {
		if err := access.WriteOffboardingCheckHTML(*htmlPath, check); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] read-only offboarding check HTML written to %s (mode 0600)\n", *htmlPath)
	}
	if *csvPath != "" {
		if err := access.WriteOffboardingCheckCSV(*csvPath, check); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] read-only offboarding check CSV written to %s (mode 0600)\n", *csvPath)
	}
}

func cmdAccessWhereIsKey(args []string) {
	fingerprint, scanPath := parseAccessLookupArgs("where-is-key", args)
	snapshot, err := access.ReadSnapshot(scanPath)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderFingerprintText(snapshot, fingerprint))
}

func cmdAccessWhoHas(args []string) {
	host, scanPath := parseAccessLookupArgs("who-has", args)
	snapshot, err := access.ReadSnapshot(scanPath)
	if err != nil {
		fatal(err.Error())
	}
	report, found := access.RenderHostAccessText(snapshot, host)
	if !found {
		fatal("host not found in snapshot: " + host)
	}
	fmt.Print(report)
}

func parseAccessLookupArgs(command string, args []string) (string, string) {
	value, flagArgs, extras := splitAccessOnePositional(args, map[string]bool{"-scan": true, "--scan": true})
	if value == "" || len(extras) > 0 {
		kind := "fingerprint"
		if command == "who-has" {
			kind = "host"
		}
		fatal(fmt.Sprintf("usage: sshmgr access %s <%s> --scan snapshot.json", command, kind))
	}
	fs := flag.NewFlagSet("access "+command, flag.ExitOnError)
	scanPath := fs.String("scan", "", "snapshot JSON to query")
	_ = fs.Parse(flagArgs)
	if *scanPath == "" {
		fatal("--scan <snapshot.json> is required")
	}
	return value, *scanPath
}

func splitCSV(value string) []string {
	var values []string
	seen := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			values = append(values, item)
		}
	}
	return values
}

func excludeAccessHosts(cfg *config.Config, matched, excludeAliases, excludeTags []string) ([]string, []string, error) {
	for _, alias := range excludeAliases {
		if _, ok := cfg.Hosts[alias]; !ok {
			return nil, nil, fmt.Errorf("unknown excluded host alias: %s", alias)
		}
	}
	for _, tag := range excludeTags {
		known := false
		for alias := range cfg.Hosts {
			host, _ := cfg.ResolveHost(alias)
			if containsAccessValue(host.Tags, tag) {
				known = true
				break
			}
		}
		if !known {
			return nil, nil, fmt.Errorf("unknown excluded host tag: %s", tag)
		}
	}
	excludedAliasSet := make(map[string]bool, len(excludeAliases))
	for _, alias := range excludeAliases {
		excludedAliasSet[alias] = true
	}
	var selected, excluded []string
	for _, alias := range matched {
		host, _ := cfg.ResolveHost(alias)
		exclude := excludedAliasSet[alias]
		for _, tag := range excludeTags {
			exclude = exclude || containsAccessValue(host.Tags, tag)
		}
		if exclude {
			excluded = append(excluded, alias)
		} else {
			selected = append(selected, alias)
		}
	}
	sort.Strings(selected)
	sort.Strings(excluded)
	return selected, excluded, nil
}

func containsAccessValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func accessSelectorDescription(selector exec_.Selector) string {
	groups := exec_.SelectorGroups(selector)
	switch {
	case len(groups) == 1:
		return "group:" + groups[0]
	case len(groups) > 1:
		return "groups:" + strings.Join(groups, ",")
	case selector.Tag != "":
		return "tag:" + selector.Tag
	case len(selector.Hosts) > 0:
		return "hosts:" + strings.Join(selector.Hosts, ",")
	case selector.All:
		return "all"
	default:
		return ""
	}
}

type accessGroupFlags []string

func (groups *accessGroupFlags) String() string {
	if groups == nil {
		return ""
	}
	return strings.Join(*groups, ",")
}

func (groups *accessGroupFlags) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("--group requires a non-empty group name")
	}
	*groups = append(*groups, value)
	return nil
}

func printAccessTargets(selected, excluded, hostExclusions, tagExclusions []string, dryRun, preflight bool) {
	mode := "scan"
	if dryRun {
		mode = "dry-run"
	} else if preflight {
		mode = "preflight"
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] access %s — %d selected, %d excluded\n", mode, len(selected), len(excluded))
	if len(hostExclusions) > 0 || len(tagExclusions) > 0 {
		fmt.Fprintln(os.Stderr, "[sshmgr] exclusion guards:")
		for _, alias := range hostExclusions {
			fmt.Fprintln(os.Stderr, "  host: "+alias)
		}
		for _, tag := range tagExclusions {
			fmt.Fprintln(os.Stderr, "  tag:  "+tag)
		}
	}
	if len(excluded) > 0 {
		fmt.Fprintln(os.Stderr, "[sshmgr] excluded:")
		for _, alias := range excluded {
			fmt.Fprintln(os.Stderr, "  - "+alias)
		}
	}
	fmt.Fprintln(os.Stderr, "[sshmgr] selected:")
	for _, alias := range selected {
		fmt.Fprintln(os.Stderr, "  "+alias)
	}
}

func splitAccessOnePositional(args []string, valueFlags map[string]bool) (value string, flagArgs, extras []string) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valueFlags[arg] && index+1 < len(args) {
				flagArgs = append(flagArgs, args[index+1])
				index++
			}
			continue
		}
		if value == "" {
			value = arg
		} else {
			extras = append(extras, arg)
		}
	}
	return value, flagArgs, extras
}

func splitAccessPositionals(args []string, valueFlags map[string]bool) (values, flagArgs []string) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if valueFlags[arg] && index+1 < len(args) {
				flagArgs = append(flagArgs, args[index+1])
				index++
			}
			continue
		}
		values = append(values, arg)
	}
	return values, flagArgs
}

func sameAccessPath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	leftAbsolute = filepath.Clean(leftAbsolute)
	rightAbsolute = filepath.Clean(rightAbsolute)
	if leftAbsolute == rightAbsolute {
		return true
	}
	leftInfo, leftStatErr := os.Stat(leftAbsolute)
	rightInfo, rightStatErr := os.Stat(rightAbsolute)
	if leftStatErr == nil && rightStatErr == nil {
		return os.SameFile(leftInfo, rightInfo)
	}
	resolveMissingLeaf := func(path string) string {
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return path
		}
		return filepath.Join(parent, filepath.Base(path))
	}
	return resolveMissingLeaf(leftAbsolute) == resolveMissingLeaf(rightAbsolute)
}
