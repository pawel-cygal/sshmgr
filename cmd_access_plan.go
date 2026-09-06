package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/accessplan"
	"github.com/systeampl/sshmgr/internal/config"
	exec_ "github.com/systeampl/sshmgr/internal/exec"
	"github.com/systeampl/sshmgr/internal/projectstate"
	"github.com/systeampl/sshmgr/internal/provision"
	"golang.org/x/term"
)

type accessPlanFlags struct {
	Groups  accessGroupFlags
	Tag     string
	Hosts   string
	All     bool
	Profile string
	Scan    string
	Out     string
	TTL     time.Duration
	SignKey string
}

func cmdAccessPlan(args []string) {
	values := parseAccessPlanFlags("access plan", args, true)
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	selector, aliases := resolvePlanSelector(cfg, values.Groups, values.Tag, values.Hosts, values.All)
	human, token := requireHumanProject(values.Profile)
	paths, err := projectstate.Resolve(projectstate.Context{Organization: human.Profile.Organization, Project: human.Profile.Project})
	if err != nil {
		fatal(err.Error())
	}
	scanPath := strings.TrimSpace(values.Scan)
	if scanPath == "" {
		scanPath, err = projectstate.LatestAudit(paths)
		if err != nil {
			fatal(err.Error())
		}
	}
	snapshot, err := access.ReadSnapshot(scanPath)
	if err != nil {
		fatal(err.Error())
	}
	grants := fetchDesiredGrants(human, token)
	plan, err := accessplan.Build(snapshot, cfg, grants, accessplan.BuildOptions{
		Organization: human.Profile.Organization, Project: human.Profile.Project,
		Selector: accessSelectorDescription(selector), Aliases: aliases, Now: time.Now(), TTL: values.TTL,
	})
	if err != nil {
		fatal(err.Error())
	}
	if strings.TrimSpace(values.SignKey) != "" {
		privateKey, err := accessplan.ReadSigningPrivateKey(values.SignKey)
		if err != nil {
			fatal(err.Error())
		}
		if err := accessplan.Sign(plan, privateKey); err != nil {
			fatal(err.Error())
		}
	}
	statePath, err := projectstate.StorePlan(paths, plan)
	if err != nil {
		fatal(err.Error())
	}
	if !sameAccessPath(statePath, values.Out) {
		if err := accessplan.Write(values.Out, plan); err != nil {
			fatal(err.Error())
		}
	}
	fmt.Print(accessplan.Render(plan))
	fmt.Fprintf(os.Stderr, "[sshmgr] immutable private plan: %s\n[sshmgr] exported plan: %s (mode 0600)\n", statePath, values.Out)
}

func cmdAccessApply(args []string) {
	valueFlags := map[string]bool{"-profile": true, "--profile": true, "-trusted-key": true, "--trusted-key": true}
	planPath, flagArgs, extras := splitAccessOnePositional(args, valueFlags)
	if planPath == "" || len(extras) > 0 {
		fatal("usage: sshmgr access apply access.plan [--yes --trusted-key CUSTOMER.pub]")
	}
	fs := flag.NewFlagSet("access apply", flag.ExitOnError)
	profileName := fs.String("profile", "", "Cloud profile")
	yes := fs.Bool("yes", false, "non-interactive apply; requires a customer-trusted plan signature")
	trustedKey := fs.String("trusted-key", "", "customer Ed25519 public key required with --yes")
	_ = fs.Parse(flagArgs)
	plan, err := accessplan.Read(planPath)
	if err != nil {
		fatal(err.Error())
	}
	human, token := requireHumanProject(*profileName)
	if plan.Organization != human.Profile.Organization || plan.Project != human.Profile.Project {
		fatal("access plan does not belong to the active organization/project")
	}
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if *yes {
		if strings.TrimSpace(*trustedKey) == "" {
			fatal("non-interactive --yes requires --trusted-key; unsigned or self-asserted plans are rejected")
		}
		publicKey, err := accessplan.ReadTrustedPublicKey(*trustedKey)
		if err != nil {
			fatal(err.Error())
		}
		if err := accessplan.VerifySignature(plan, publicKey); err != nil {
			fatal(err.Error())
		}
	} else {
		confirmPlanID(plan)
	}
	executeAccessPlan(plan, cfg, human, token)
}

func cmdAccessSync(args []string) {
	fs := flag.NewFlagSet("access sync", flag.ExitOnError)
	var groups accessGroupFlags
	fs.Var(&groups, "group", "select the union of this group; may be repeated")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated aliases")
	all := fs.Bool("all", false, "select every alias")
	profileName := fs.String("profile", "", "Cloud profile")
	parallel := fs.Int("p", 4, "maximum concurrent audit connections")
	timeout := fs.Duration("timeout", 45*time.Second, "per-host audit timeout")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 || *parallel < 1 || *timeout <= 0 {
		fatal("usage: sshmgr access sync (--group G|--tag T|--host a,b|--all)")
	}
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	selector, aliases := resolvePlanSelector(cfg, groups, *tag, *hosts, *all)
	human, token := requireHumanProject(*profileName)
	paths, err := projectstate.Resolve(projectstate.Context{Organization: human.Profile.Organization, Project: human.Profile.Project})
	if err != nil {
		fatal(err.Error())
	}
	fmt.Fprintln(os.Stderr, "[sshmgr] sync refresh: full read-only system audit")
	snapshot := scanPlanBaseline(cfg, selector, aliases, *parallel, *timeout)
	auditPath, err := projectstate.StoreAudit(paths, snapshot)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(access.RenderText(snapshot))
	fmt.Fprintf(os.Stderr, "[sshmgr] refresh baseline: %s\n", auditPath)
	grants := fetchDesiredGrants(human, token)
	plan, err := accessplan.Build(snapshot, cfg, grants, accessplan.BuildOptions{
		Organization: human.Profile.Organization, Project: human.Profile.Project,
		Selector: accessSelectorDescription(selector), Aliases: aliases, Now: time.Now(), TTL: 30 * time.Minute,
	})
	if err != nil {
		fatal(err.Error())
	}
	planPath, err := projectstate.StorePlan(paths, plan)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(accessplan.Render(plan))
	fmt.Fprintf(os.Stderr, "[sshmgr] immutable plan: %s\n", planPath)
	if len(plan.Changes) == 0 {
		fmt.Println("Desired state already matches the refreshed audit. No changes to apply.")
		return
	}
	confirmPlanID(plan)
	executeAccessPlan(plan, cfg, human, token)
}

func cmdAccessExport(args []string) {
	if len(args) == 0 || args[0] != "ansible" {
		fatal("usage: sshmgr access export ansible access.plan --out playbook.yml")
	}
	planPath, flagArgs, extras := splitAccessOnePositional(args[1:], map[string]bool{"-out": true, "--out": true})
	fs := flag.NewFlagSet("access export ansible", flag.ExitOnError)
	out := fs.String("out", "", "Ansible playbook output")
	_ = fs.Parse(flagArgs)
	if planPath == "" || len(extras) > 0 || strings.TrimSpace(*out) == "" {
		fatal("usage: sshmgr access export ansible access.plan --out playbook.yml")
	}
	plan, err := accessplan.Read(planPath)
	if err != nil {
		fatal(err.Error())
	}
	data, err := accessplan.RenderAnsible(plan)
	if err != nil {
		fatal(err.Error())
	}
	if err := writePrivateOutput(*out, []byte(data)); err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] Ansible/GitOps playbook written to %s (mode 0600)\n", *out)
}

func parseAccessPlanFlags(name string, args []string, requireOut bool) accessPlanFlags {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	values := accessPlanFlags{TTL: 30 * time.Minute}
	fs.Var(&values.Groups, "group", "select the union of this group; may be repeated")
	fs.StringVar(&values.Tag, "tag", "", "select hosts with this tag")
	fs.StringVar(&values.Hosts, "host", "", "comma-separated aliases")
	fs.BoolVar(&values.All, "all", false, "select every alias")
	fs.StringVar(&values.Profile, "profile", "", "Cloud profile")
	fs.StringVar(&values.Scan, "scan", "", "baseline snapshot; default is project latest")
	fs.StringVar(&values.Out, "out", "", "export immutable plan")
	fs.DurationVar(&values.TTL, "ttl", 30*time.Minute, "plan validity")
	fs.StringVar(&values.SignKey, "sign-key", "", "customer Ed25519 private key for CI apply")
	_ = fs.Parse(args)
	if len(fs.Args()) != 0 || requireOut && strings.TrimSpace(values.Out) == "" {
		fatal("access plan requires a selector and --out access.plan")
	}
	return values
}

func resolvePlanSelector(cfg *config.Config, groups accessGroupFlags, tag, hosts string, all bool) (exec_.Selector, []string) {
	selector := exec_.Selector{Groups: []string(groups), Tag: strings.TrimSpace(tag), Hosts: splitCSV(hosts), All: all}
	if err := exec_.ValidateSelector(cfg, selector); err != nil {
		fatal(err.Error())
	}
	aliases := exec_.Select(cfg, selector)
	if len(aliases) == 0 {
		fatal("no hosts matched the selector")
	}
	return selector, aliases
}

func fetchDesiredGrants(human humanContext, token string) []cloudcontract.DesiredGrant {
	client := newHumanClient(human, token, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result, err := client.Grants(ctx, human.Profile.Organization, human.Profile.Project)
	cancel()
	if err != nil {
		fatal("read desired access state: " + err.Error())
	}
	return result.Grants
}

func scanPlanBaseline(cfg *config.Config, selector exec_.Selector, aliases []string, parallel int, timeout time.Duration) *access.Snapshot {
	accountMode, accounts, maxAccounts, err := access.NormalizeSystemAccountSelection(access.AccountModeLocal, nil, 0)
	if err != nil {
		fatal(err.Error())
	}
	maxSource, maxTotal, err := access.NormalizeSystemCollectionLimits(0, 0)
	if err != nil {
		fatal(err.Error())
	}
	options := access.ScanOptions{Parallel: parallel, Timeout: timeout, ScannerVersion: currentBuildInfo().Version,
		Selector: accessSelectorDescription(selector), UseSudo: true, AccountMode: accountMode, Accounts: accounts,
		MaxAccounts: maxAccounts, MaxSourceBytes: maxSource, MaxTotalBytes: maxTotal}
	return access.ScanSystem(context.Background(), cfg, aliases, options)
}

func executeAccessPlan(plan *accessplan.Plan, cfg *config.Config, human humanContext, token string) {
	current := fetchDesiredGrants(human, token)
	digest, err := accessplan.DesiredStateDigest(cfg, current, plan.Hosts)
	if err != nil {
		fatal(err.Error())
	}
	if digest != plan.DesiredStateSHA256 {
		fatal("stale plan: Cloud desired state changed after plan creation")
	}
	paths, err := projectstate.Resolve(projectstate.Context{Organization: plan.Organization, Project: plan.Project})
	if err != nil {
		fatal(err.Error())
	}
	receipt, applyErr := provision.Apply(context.Background(), cfg, plan)
	if applyErr == nil {
		postScan := scanPlanBaseline(cfg, exec_.Selector{Hosts: changedPlanHosts(plan)}, changedPlanHosts(plan), 4, 45*time.Second)
		postPath, scanErr := projectstate.StorePostScan(paths, postScan)
		if scanErr == nil {
			receipt.PostScanID = postScan.ScanID
			scanErr = verifyPostScan(plan, postScan)
		}
		if scanErr != nil {
			receipt.Status = "partial"
			applyErr = fmt.Errorf("post-scan did not prove convergence: %w", scanErr)
		} else {
			receipt.Status = "observed"
			fmt.Fprintf(os.Stderr, "[sshmgr] post-scan evidence: %s\n", postPath)
		}
		receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	receiptPath, receiptErr := projectstate.StoreReceipt(paths, receipt)
	if receiptErr != nil {
		fatal("store provisioning receipt: " + receiptErr.Error())
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] private apply receipt: %s\n", receiptPath)
	if applyErr != nil {
		fatal(applyErr.Error())
	}
	fmt.Printf("Plan %s applied and confirmed by post-scan evidence.\n", plan.PlanID)
}

func confirmPlanID(plan *accessplan.Plan) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fatal("interactive apply requires a terminal; CI must use --yes with a customer-trusted signature")
	}
	fmt.Printf("Type plan ID %s to apply the exact diff: ", plan.PlanID)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != plan.PlanID {
		fatal("plan confirmation did not match; nothing was changed")
	}
}

func changedPlanHosts(plan *accessplan.Plan) []string {
	seen := map[string]bool{}
	for _, change := range plan.Changes {
		seen[change.Host] = true
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func verifyPostScan(plan *accessplan.Plan, snapshot *access.Snapshot) error {
	for _, change := range plan.Changes {
		var account *access.AccountSnapshot
		for hostIndex := range snapshot.Hosts {
			host := &snapshot.Hosts[hostIndex]
			if host.Alias != change.Host {
				continue
			}
			if host.Coverage != access.CoverageFull {
				return fmt.Errorf("host %s coverage is %s", host.Alias, host.Coverage)
			}
			for accountIndex := range host.Accounts {
				if host.Accounts[accountIndex].Username == change.Account {
					account = &host.Accounts[accountIndex]
				}
			}
		}
		if account == nil {
			return fmt.Errorf("account %s on %s is absent", change.Account, change.Host)
		}
		for _, operation := range change.Operations {
			fingerprintFound, markerFound := false, false
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					if entry.Fingerprint == operation.Fingerprint {
						fingerprintFound = true
					}
					for _, field := range strings.Fields(entry.Comment) {
						markerFound = markerFound || field == operation.Marker
					}
				}
			}
			if operation.Action == "add" && !fingerprintFound {
				return fmt.Errorf("added fingerprint %s was not observed on %s", operation.Fingerprint, change.Host)
			}
			if operation.Action == "remove" && markerFound {
				return fmt.Errorf("revoked managed marker %s is still present on %s", operation.Marker, change.Host)
			}
		}
	}
	return nil
}

func writePrivateOutput(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".sshmgr-output-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
