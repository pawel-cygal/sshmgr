package tui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type accessScanKind string

const (
	accessScanCurrent      accessScanKind = "current"
	accessScanSystem       accessScanKind = "system"
	accessPreflightCurrent accessScanKind = "current-preflight"
	accessPreflightSystem  accessScanKind = "system-preflight"
	defaultAccessParallel                 = "4"
	defaultAccessTimeout                  = "45s"
)

type accessScanFormValues struct {
	Output            string
	Parallel          string
	Timeout           string
	Groups            string
	ExcludeHosts      string
	ExcludeTags       string
	RequireFull       bool
	FailOn            string
	DryRun            bool
	IncludePublicKeys bool
	UseSudo           bool
	AccountMode       string
	Accounts          string
	MaxAccounts       string
	MaxSourceMiB      string
	MaxTotalMiB       string
}

type cloudDashboardGateValues struct {
	FailOn                     string
	RequireFull                bool
	RequireCurrentOwnership    bool
	RequireCompleteOffboarding bool
}

// openAccessMenu presents the governance loop in the order an operator performs
// it. Expert artifact and low-level scan tools remain behind Advanced tools.
func (s *uiState) openAccessMenu() {
	scopeLabel, selectorArgs, scopeOK := s.scopeSelector()
	if !scopeOK {
		scopeLabel = "no audit target selected"
	}
	list := tview.NewList().ShowSecondaryText(true).SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.SelText).SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).SetTitle(fmt.Sprintf(" SSH access workflow · %s   (Enter=open  Esc=close) ", scopeLabel)).
		SetTitleAlign(tview.AlignLeft).SetBorderColor(theme.Current.Primary).SetTitleColor(theme.Current.Primary)
	close := func() { s.pages.RemovePage("accessmenu"); s.focusList() }
	launchAudit := func(args []string) {
		s.action = ActionAudit
		s.extraArgs = args
		s.app.Stop()
	}
	list.AddItem("1 · Audit current scope", "OBSERVE · read-only system scan · fingerprints only · private by default", 'a', func() {
		if !scopeOK {
			s.modal("nothing selected — choose a host or group first", func() { s.app.SetFocus(list) })
			return
		}
		launchAudit(selectorArgs)
	})
	list.AddItem("2 · Review latest audit", "OBSERVE · inspect coverage, evidence and findings before decisions", 'l', func() {
		launchAudit([]string{"show"})
	})
	list.AddItem("3 · Publish evidence", "OBSERVE · privacy preview, then explicit upload to the active project", 'p', func() {
		launchAudit([]string{"push"})
	})
	list.AddItem("4 · Invite an identity", "GRANT · define identity, target and TTL; create one verification command", 'i', func() {
		if !scopeOK {
			s.modal("nothing selected — choose a host or group first", func() { s.app.SetFocus(list) })
			return
		}
		s.pages.RemovePage("accessmenu")
		s.openQuickInviteForm(scopeLabel, selectorArgs)
	})
	list.AddItem("5 · Review pending requests", "GRANT · see invitation, key-possession and approval state", 'v', func() {
		s.action = ActionAccess
		s.extraArgs = []string{"status"}
		s.app.Stop()
	})
	list.AddItem("6 · Approve a request", "GRANT · confirm a verified identity and its exact intended scope", 'r', func() {
		s.pages.RemovePage("accessmenu")
		s.openQuickApproveForm()
	})
	list.AddItem("7 · Reconcile access", "APPLY · refresh → exact plan → confirm plan ID → apply → post-scan", 's', func() {
		if !scopeOK {
			s.modal("nothing selected — choose a host or group first", func() { s.app.SetFocus(list) })
			return
		}
		s.action = ActionAccess
		s.extraArgs = append([]string{"sync"}, selectorArgs...)
		s.app.Stop()
	})
	list.AddItem("8 · Revoke desired access", "REVOKE · update desired state; reconciliation performs the host change", 'd', func() {
		if !scopeOK {
			s.modal("nothing selected — choose a host or group first", func() { s.app.SetFocus(list) })
			return
		}
		s.pages.RemovePage("accessmenu")
		s.openQuickRevokeForm(scopeLabel, selectorArgs)
	})
	list.AddItem("Advanced tools", "manual scans, reports, plans, history, bundles and exports", 'x', func() {
		s.pages.RemovePage("accessmenu")
		s.openAdvancedAccessMenu()
	})
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		return event
	})
	s.pages.AddPage("accessmenu", centered(list, 78, 27), true, true)
	s.app.SetFocus(list)
}

func (s *uiState) openQuickInviteForm(scopeLabel string, selectorArgs []string) {
	var email, account, ttl string
	ttl = "30d"
	form := tview.NewForm()
	form.AddInputField("email", "", 48, nil, func(value string) { email = value })
	form.AddInputField("OS account", "deploy", 32, nil, func(value string) { account = value })
	account = "deploy"
	form.AddInputField("TTL", ttl, 12, nil, func(value string) { ttl = value })
	form.AddButton("Create invite", func() {
		if strings.TrimSpace(email) == "" || strings.TrimSpace(account) == "" {
			s.modal("email and OS account are required", func() { s.app.SetFocus(form) })
			return
		}
		s.action = ActionAccess
		s.extraArgs = append([]string{"invite", strings.TrimSpace(email)}, selectorArgs...)
		s.extraArgs = append(s.extraArgs, "--account", strings.TrimSpace(account), "--ttl", strings.TrimSpace(ttl))
		s.app.Stop()
	})
	form.AddButton("Cancel", func() { s.pages.RemovePage("quickinvite"); s.openAccessMenu() })
	styleAccessForm(form, " invite access · "+scopeLabel+" ")
	s.pages.AddPage("quickinvite", centered(form, 68, 15), true, true)
	s.app.SetFocus(form)
}

func (s *uiState) openQuickApproveForm() {
	var invitationID, reason string
	var override bool
	form := tview.NewForm()
	form.AddInputField("invitation ID", "", 48, nil, func(value string) { invitationID = value })
	form.AddCheckbox("override unverified", false, func(value bool) { override = value })
	form.AddInputField("override reason", "", 48, nil, func(value string) { reason = value })
	form.AddButton("Approve", func() {
		if strings.TrimSpace(invitationID) == "" || override && len(strings.TrimSpace(reason)) < 3 {
			s.modal("invitation ID is required; an override also needs a reason", func() { s.app.SetFocus(form) })
			return
		}
		args := []string{"approve", strings.TrimSpace(invitationID)}
		if override {
			args = append(args, "--override-unverified", "--reason", strings.TrimSpace(reason))
		}
		s.action, s.extraArgs = ActionAccess, args
		s.app.Stop()
	})
	form.AddButton("Cancel", func() { s.pages.RemovePage("quickapprove"); s.openAccessMenu() })
	styleAccessForm(form, " approve access ")
	s.pages.AddPage("quickapprove", centered(form, 68, 16), true, true)
	s.app.SetFocus(form)
}

func (s *uiState) openQuickRevokeForm(scopeLabel string, selectorArgs []string) {
	var email, account, reason string
	reason = "revoked by human operator"
	form := tview.NewForm()
	form.AddInputField("email", "", 48, nil, func(value string) { email = value })
	form.AddInputField("OS account (optional)", "", 32, nil, func(value string) { account = value })
	form.AddInputField("reason", reason, 48, nil, func(value string) { reason = value })
	form.AddButton("Revoke desired", func() {
		if strings.TrimSpace(email) == "" || len(strings.TrimSpace(reason)) < 3 {
			s.modal("email and an audit reason are required", func() { s.app.SetFocus(form) })
			return
		}
		args := append([]string{"revoke", strings.TrimSpace(email)}, selectorArgs...)
		if strings.TrimSpace(account) != "" {
			args = append(args, "--account", strings.TrimSpace(account))
		}
		args = append(args, "--reason", strings.TrimSpace(reason))
		s.action, s.extraArgs = ActionAccess, args
		s.app.Stop()
	})
	form.AddButton("Cancel", func() { s.pages.RemovePage("quickrevoke"); s.openAccessMenu() })
	styleAccessForm(form, " revoke desired access · "+scopeLabel+" ")
	s.pages.AddPage("quickrevoke", centered(form, 72, 16), true, true)
	s.app.SetFocus(form)
}

// openAdvancedAccessMenu exposes the compatible low-level API without making
// it the first screen operators have to understand.
func (s *uiState) openAdvancedAccessMenu() {
	scopeLabel, selectorArgs, scopeOK := s.scopeSelector()
	if !scopeOK {
		scopeLabel = "no scan target selected"
	}

	list := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.SelText).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" access audit · %s   (Enter=open  Esc=close) ", scopeLabel)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	close := func() {
		s.pages.RemovePage("accessmenu")
		s.focusList()
	}
	openScan := func(kind accessScanKind) {
		if !scopeOK {
			s.modal("nothing selected — move the cursor to a host (or a group node) first, or Space to multi-select", func() { s.app.SetFocus(list) })
			return
		}
		s.pages.RemovePage("accessmenu")
		s.openAccessScanForm(scopeLabel, selectorArgs, kind)
	}

	list.AddItem("scan current account keys", "read authorized_keys for the SSH login account; fingerprints only by default", '1', func() {
		openScan(accessScanCurrent)
	})
	list.AddItem("scan system account keys", "read bounded static AuthorizedKeysFile sources through root or sudo -n", '2', func() {
		openScan(accessScanSystem)
	})
	list.AddItem("preflight current account", "connectivity and source metadata only; do not read key contents", '3', func() {
		openScan(accessPreflightCurrent)
	})
	list.AddItem("preflight system accounts", "bounded account and effective sshd metadata; sudo -n by default", '4', func() {
		openScan(accessPreflightSystem)
	})
	list.AddItem("preview selected targets", "CLI --dry-run: resolve scope without connecting", '5', func() {
		if !scopeOK {
			s.modal("nothing selected — move the cursor to a host (or a group node) first, or Space to multi-select", func() { s.app.SetFocus(list) })
			return
		}
		args := append([]string{"scan"}, selectorArgs...)
		s.launchAccess(append(args, "--dry-run"), "accessmenu")
	})
	list.AddItem("render snapshot report", "print summary and optionally create local HTML and CSV reports", '6', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessReportForm()
	})
	list.AddItem("build access graph", "identity hints → fingerprints → OS accounts → hosts; optional graph JSON", 'g', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessGraphForm()
	})
	list.AddItem("merge snapshots", "combine disjoint validated snapshots and recalculate fleet-wide findings", 'm', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessMergeForm()
	})
	list.AddItem("create identity map", "write a local YAML template; observed comments remain unverified hints", 'i', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessIdentityMapForm()
	})
	list.AddItem("review key ownership", "combine a snapshot with explicit identity claims; report unknown/shared/offboarded", 'r', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessReviewForm()
	})
	list.AddItem("build offboarding report", "read-only identity-to-access evidence; never an executable removal plan", 'o', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessOffboardingForm()
	})
	list.AddItem("check offboarding outcome", "compare baseline and fresh evidence; complete, still present, or inconclusive", 'k', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessOffboardingCheckForm()
	})
	list.AddItem("prepare Cloud upload plan", "offline only: validate and preview the exact redacted snapshot payload", 'c', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudUploadPlanForm()
	})
	list.AddItem("push snapshot to Cloud", "build plan/history/bundle automatically, preview privacy, then upload explicitly", 'q', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudPushForm()
	})
	list.AddItem("inspect Cloud upload plan", "offline only: revalidate an existing plan and show its privacy preview", 'v', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudInspectForm()
	})
	list.AddItem("build Cloud workspace history", "offline only: deduplicate upload plans and calculate safe chronological changes", 'h', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudHistoryBuildForm()
	})
	list.AddItem("inspect Cloud workspace history", "offline only: validate and display a local workspace timeline", 'j', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudHistoryInspectForm()
	})
	list.AddItem("build Cloud ownership history", "offline only: bind ownership reviews and calculate identity/claim changes", 'y', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudOwnershipHistoryBuildForm()
	})
	list.AddItem("inspect Cloud ownership history", "offline only: validate ownership coverage, freshness, and transitions", 'b', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudOwnershipHistoryInspectForm()
	})
	list.AddItem("build Cloud offboarding history", "offline only: bind validated offboarding checks to one workspace timeline", 'x', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudOffboardingHistoryBuildForm()
	})
	list.AddItem("inspect Cloud offboarding history", "offline only: validate current and stale identity outcomes", 'z', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudOffboardingHistoryInspectForm()
	})
	list.AddItem("build Cloud ingestion bundle", "offline only: freeze complete validated workspace evidence for explicit upload", 'e', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudBundleBuildForm()
	})
	list.AddItem("inspect Cloud ingestion bundle", "offline only: verify content digests, privacy preview, and idempotency key", 'l', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudBundleInspectForm()
	})
	list.AddItem("manage Cloud profiles", "login, remote service status, and local workspace/profile selection", 'f', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudProfileMenu()
	})
	list.AddItem("upload Cloud ingestion bundle", "explicit HTTPS upload of one validated bundle; token comes from keyring or CI env", 'p', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudUploadForm()
	})
	list.AddItem("render Cloud workspace dashboard", "offline only: self-contained HTML overview, findings, access graph, and timeline", 'd', func() {
		s.pages.RemovePage("accessmenu")
		s.openCloudDashboardForm()
	})
	list.AddItem("compare two snapshots", "semantic access diff between before and after JSON snapshots", '7', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessDiffForm()
	})
	list.AddItem("who has access to a host?", "query an existing snapshot; highlighted host is prefilled", '8', func() {
		host := s.currentAlias()
		s.pages.RemovePage("accessmenu")
		s.openAccessWhoHasForm(host)
	})
	list.AddItem("where is this key used?", "find every account and host for an SHA256 fingerprint", '9', func() {
		s.pages.RemovePage("accessmenu")
		s.openAccessWhereIsKeyForm()
	})

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		return event
	})
	s.pages.AddPage("accessmenu", centered(list, 78, 31), true, true)
	s.app.SetFocus(list)
}

func (s *uiState) openAccessScanForm(scopeLabel string, selectorArgs []string, kind accessScanKind) {
	values := accessScanFormValues{
		Output:       defaultAccessSnapshotPath(kind),
		Parallel:     defaultAccessParallel,
		Timeout:      defaultAccessTimeout,
		UseSudo:      true,
		AccountMode:  access.AccountModeLocal,
		MaxAccounts:  "0",
		MaxSourceMiB: "0",
		MaxTotalMiB:  "0",
	}
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", values.Output, 62, nil, func(v string) { values.Output = v })
	groups, groupSelector := accessSelectorGroupArgs(selectorArgs)
	if groupSelector {
		values.Groups = strings.Join(groups, ",")
		form.AddInputField("groups (comma-separated union)", values.Groups, 62, nil, func(v string) { values.Groups = v })
	}
	form.AddInputField("parallel (-p)", values.Parallel, 8, nil, func(v string) { values.Parallel = v })
	form.AddInputField("host timeout", values.Timeout, 12, nil, func(v string) { values.Timeout = v })
	form.AddInputField("exclude hosts", "", 62, nil, func(v string) { values.ExcludeHosts = v })
	form.AddInputField("exclude tags", "", 62, nil, func(v string) { values.ExcludeTags = v })
	form.AddCheckbox("require full coverage", false, func(v bool) { values.RequireFull = v })
	addAccessFailOnDropDown(form, &values.FailOn)
	form.AddCheckbox("preview targets only (--dry-run)", false, func(v bool) { values.DryRun = v })

	if kind == accessScanCurrent || kind == accessScanSystem {
		form.AddCheckbox("include full public keys (sensitive)", false, func(v bool) { values.IncludePublicKeys = v })
	}
	if kind == accessPreflightSystem || kind == accessScanSystem {
		form.AddCheckbox("use sudo -n", true, func(v bool) { values.UseSudo = v })
		accountLabels := []string{
			"local (/etc/passwd, default budget 4096)",
			"NSS / directory enumeration (default budget 1000)",
			"explicit account list (keyed lookups)",
		}
		accountModes := []string{access.AccountModeLocal, access.AccountModeNSS, access.AccountModeExplicit}
		form.AddDropDown("account source", accountLabels, 0, func(_ string, index int) {
			values.AccountMode = accountModes[index]
		})
		form.AddInputField("explicit accounts", "", 62, nil, func(v string) { values.Accounts = v })
		form.AddInputField("max accounts (0=mode default)", values.MaxAccounts, 12, nil, func(v string) { values.MaxAccounts = v })
		if kind == accessScanSystem {
			form.AddInputField("max source MiB (0=4)", values.MaxSourceMiB, 12, nil, func(v string) { values.MaxSourceMiB = v })
			form.AddInputField("max total MiB/host (0=16)", values.MaxTotalMiB, 12, nil, func(v string) { values.MaxTotalMiB = v })
		}
		styleAccessDropDown(form, "account source")
	}

	form.AddButton("Run", func() {
		args, err := accessScanExtraArgs(selectorArgs, kind, values)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessscan")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessscan")
		s.openAccessMenu()
	})
	styleAccessForm(form, fmt.Sprintf(" access scan · %s · %s ", accessScanKindLabel(kind), scopeLabel))
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			s.pages.RemovePage("accessscan")
			s.openAccessMenu()
			return nil
		}
		return event
	})
	height := 20
	if kind == accessPreflightSystem {
		height = 25
	} else if kind == accessScanSystem {
		height = 28
	}
	if groupSelector {
		height++
	}
	s.pages.AddPage("accessscan", centered(form, 78, height), true, true)
	s.app.SetFocus(form)
}

func accessScanExtraArgs(selectorArgs []string, kind accessScanKind, values accessScanFormValues) ([]string, error) {
	selectorArgs, err := accessScanSelectorArgs(selectorArgs, values.Groups)
	if err != nil {
		return nil, err
	}
	parallel, err := strconv.Atoi(strings.TrimSpace(values.Parallel))
	if err != nil || parallel < 1 {
		return nil, errors.New("parallel must be a positive integer")
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(values.Timeout))
	if err != nil || timeout <= 0 {
		return nil, errors.New("host timeout must be a positive duration, for example 45s or 2m")
	}
	output := strings.TrimSpace(values.Output)
	if output == "" && !values.DryRun {
		return nil, errors.New("snapshot JSON path is required")
	}

	args := append([]string{"scan"}, selectorArgs...)
	switch kind {
	case accessScanCurrent:
		if values.IncludePublicKeys {
			args = append(args, "--include-public-keys")
		}
	case accessPreflightCurrent:
		if values.IncludePublicKeys {
			return nil, errors.New("public-key contents are not available in preflight mode")
		}
		args = append(args, "--preflight")
	case accessScanSystem, accessPreflightSystem:
		if kind == accessPreflightSystem && values.IncludePublicKeys {
			return nil, errors.New("public-key contents are not available in system preflight mode")
		}
		accountMode := strings.TrimSpace(values.AccountMode)
		accounts := splitAccessFormCSV(values.Accounts)
		maxAccounts, err := parseAccessNonNegativeInt(values.MaxAccounts, "max accounts")
		if err != nil {
			return nil, err
		}
		if _, _, _, err := access.NormalizeSystemAccountSelection(accountMode, accounts, maxAccounts); err != nil {
			return nil, err
		}
		args = append(args, "--scope", "system")
		if kind == accessPreflightSystem {
			args = append(args, "--preflight")
		}
		if values.UseSudo {
			args = append(args, "--sudo")
		}
		args = append(args, "--accounts", accountMode)
		if len(accounts) > 0 {
			args = append(args, "--account", strings.Join(accounts, ","))
		}
		if maxAccounts > 0 {
			args = append(args, "--max-accounts", strconv.Itoa(maxAccounts))
		}
		if kind == accessScanSystem {
			maxSourceMiB, err := parseAccessNonNegativeInt(values.MaxSourceMiB, "max source MiB")
			if err != nil {
				return nil, err
			}
			maxTotalMiB, err := parseAccessNonNegativeInt(values.MaxTotalMiB, "max total MiB")
			if err != nil {
				return nil, err
			}
			if maxSourceMiB > 16 {
				return nil, errors.New("max source MiB must be between 1 and 16 (or 0 for the default)")
			}
			if maxTotalMiB > 64 {
				return nil, errors.New("max total MiB must be between 1 and 64 (or 0 for the default)")
			}
			if _, _, err := access.NormalizeSystemCollectionLimits(int64(maxSourceMiB)<<20, int64(maxTotalMiB)<<20); err != nil {
				return nil, err
			}
			if maxSourceMiB > 0 {
				args = append(args, "--max-source-mib", strconv.Itoa(maxSourceMiB))
			}
			if maxTotalMiB > 0 {
				args = append(args, "--max-total-mib", strconv.Itoa(maxTotalMiB))
			}
			if values.IncludePublicKeys {
				args = append(args, "--include-public-keys")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported access scan mode %q", kind)
	}

	if values.DryRun {
		args = append(args, "--dry-run")
	} else {
		args = append(args, "--out", output)
	}
	args = append(args, "-p", strconv.Itoa(parallel), "--timeout", timeout.String())
	if excludes := splitAccessFormCSV(values.ExcludeHosts); len(excludes) > 0 {
		args = append(args, "--exclude-host", strings.Join(excludes, ","))
	}
	if excludes := splitAccessFormCSV(values.ExcludeTags); len(excludes) > 0 {
		args = append(args, "--exclude-tag", strings.Join(excludes, ","))
	}
	if values.RequireFull && !values.DryRun {
		args = append(args, "--require-full")
	}
	failOn, err := access.NormalizeFailOnSeverity(values.FailOn)
	if err != nil {
		return nil, err
	}
	if failOn != "" {
		if values.DryRun {
			return nil, errors.New("fail-on policy is unavailable in target preview mode")
		}
		args = append(args, "--fail-on", failOn)
	}
	return args, nil
}

func validAccessSelectorArgs(args []string) bool {
	if len(args) == 2 && args[0] == "--host" && strings.TrimSpace(args[1]) != "" {
		return true
	}
	_, ok := accessSelectorGroupArgs(args)
	return ok
}

func accessSelectorGroupArgs(args []string) ([]string, bool) {
	if len(args) < 2 || len(args)%2 != 0 {
		return nil, false
	}
	seen := map[string]bool{}
	groups := make([]string, 0, len(args)/2)
	for index := 0; index < len(args); index += 2 {
		group := strings.TrimSpace(args[index+1])
		if args[index] != "--group" || group == "" {
			return nil, false
		}
		if !seen[group] {
			seen[group] = true
			groups = append(groups, group)
		}
	}
	return groups, len(groups) > 0
}

func accessScanSelectorArgs(selectorArgs []string, groupOverride string) ([]string, error) {
	if !validAccessSelectorArgs(selectorArgs) {
		return nil, errors.New("invalid or empty access scan target")
	}
	groupOverride = strings.TrimSpace(groupOverride)
	if groupOverride == "" {
		return append([]string(nil), selectorArgs...), nil
	}
	if _, ok := accessSelectorGroupArgs(selectorArgs); !ok {
		return nil, errors.New("group union can only extend a group target; select a group node first")
	}
	groups := splitAccessFormCSV(groupOverride)
	if len(groups) == 0 {
		return nil, errors.New("at least one group is required")
	}
	args := make([]string, 0, len(groups)*2)
	for _, group := range groups {
		args = append(args, "--group", group)
	}
	return args, nil
}

func parseAccessNonNegativeInt(value, label string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "0"
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be zero or a positive integer", label)
	}
	return n, nil
}

func splitAccessFormCSV(value string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func defaultAccessSnapshotPath(kind accessScanKind) string {
	prefix := "sshmgr-access"
	switch kind {
	case accessScanSystem:
		prefix += "-system"
	case accessPreflightCurrent:
		prefix += "-current-preflight"
	case accessPreflightSystem:
		prefix += "-system-preflight"
	}
	return prefix + "-" + time.Now().Format("20060102-150405") + ".json"
}

func accessScanKindLabel(kind accessScanKind) string {
	switch kind {
	case accessScanCurrent:
		return "current account keys"
	case accessScanSystem:
		return "system account keys"
	case accessPreflightCurrent:
		return "current preflight"
	case accessPreflightSystem:
		return "system preflight"
	default:
		return string(kind)
	}
}

func (s *uiState) openAccessReportForm() {
	var snapshot, html, csv, failOn string
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("HTML output (optional)", "", 64, nil, func(v string) { html = v })
	form.AddInputField("CSV output (optional)", "", 64, nil, func(v string) { csv = v })
	addAccessFailOnDropDown(form, &failOn)
	form.AddButton("Run", func() {
		args, err := accessReportExtraArgs(snapshot, html, csv, failOn)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessreport")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessreport")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessreport", " access report ", form, 14)
}

func accessReportExtraArgs(snapshot, html, csv, failOn string) ([]string, error) {
	snapshot = strings.TrimSpace(snapshot)
	if snapshot == "" {
		return nil, errors.New("snapshot JSON path is required")
	}
	args := []string{"report", snapshot}
	if html = strings.TrimSpace(html); html != "" {
		args = append(args, "--html", html)
	}
	if csv = strings.TrimSpace(csv); csv != "" {
		args = append(args, "--csv", csv)
	}
	failOn, err := access.NormalizeFailOnSeverity(failOn)
	if err != nil {
		return nil, err
	}
	if failOn != "" {
		args = append(args, "--fail-on", failOn)
	}
	return args, nil
}

func (s *uiState) openAccessGraphForm() {
	var snapshot, jsonOutput string
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("graph JSON (optional)", "", 64, nil, func(v string) { jsonOutput = v })
	form.AddButton("Run", func() {
		args, err := accessGraphExtraArgs(snapshot, jsonOutput)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessgraph")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessgraph")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessgraph", " access graph ", form, 11)
}

func accessGraphExtraArgs(snapshot, jsonOutput string) ([]string, error) {
	snapshot = strings.TrimSpace(snapshot)
	if snapshot == "" {
		return nil, errors.New("snapshot JSON path is required")
	}
	args := []string{"graph", snapshot}
	if jsonOutput = strings.TrimSpace(jsonOutput); jsonOutput != "" {
		args = append(args, "--json", jsonOutput)
	}
	return args, nil
}

func (s *uiState) openAccessMergeForm() {
	var inputs, output string
	form := tview.NewForm()
	form.AddInputField("snapshot JSON files (comma separated)", "", 64, nil, func(v string) { inputs = v })
	form.AddInputField("merged snapshot JSON", "", 64, nil, func(v string) { output = v })
	form.AddButton("Run", func() {
		args, err := accessMergeExtraArgs(inputs, output)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessmerge")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessmerge")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessmerge", " merge access snapshots ", form, 11)
}

func accessMergeExtraArgs(inputs, output string) ([]string, error) {
	paths := splitAccessFormCSV(inputs)
	if len(paths) < 2 {
		return nil, errors.New("at least two snapshot JSON paths are required")
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, errors.New("merged snapshot JSON path is required")
	}
	args := append([]string{"merge"}, paths...)
	return append(args, "--out", output), nil
}

func (s *uiState) openAccessIdentityMapForm() {
	var snapshot, output string
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("identity map YAML", "", 64, nil, func(v string) { output = v })
	form.AddButton("Run", func() {
		args, err := accessIdentityMapExtraArgs(snapshot, output)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessidentitymap")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessidentitymap")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessidentitymap", " create identity map ", form, 11)
}

func accessIdentityMapExtraArgs(snapshot, output string) ([]string, error) {
	snapshot = strings.TrimSpace(snapshot)
	output = strings.TrimSpace(output)
	if snapshot == "" || output == "" {
		return nil, errors.New("snapshot JSON and identity map YAML paths are required")
	}
	return []string{"identity-map", snapshot, "--out", output}, nil
}

func (s *uiState) openAccessReviewForm() {
	var snapshot, identities, jsonOutput, htmlOutput, csvOutput, failOn string
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("identity map YAML", "", 64, nil, func(v string) { identities = v })
	form.AddInputField("review JSON (optional)", "", 64, nil, func(v string) { jsonOutput = v })
	form.AddInputField("review HTML (optional)", "", 64, nil, func(v string) { htmlOutput = v })
	form.AddInputField("review CSV (optional)", "", 64, nil, func(v string) { csvOutput = v })
	addAccessFailOnDropDown(form, &failOn)
	form.AddButton("Run", func() {
		args, err := accessReviewExtraArgs(snapshot, identities, jsonOutput, htmlOutput, csvOutput, failOn)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessreview")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessreview")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessreview", " review key ownership ", form, 18)
}

func accessReviewExtraArgs(snapshot, identities, jsonOutput, htmlOutput, csvOutput, failOn string) ([]string, error) {
	snapshot = strings.TrimSpace(snapshot)
	identities = strings.TrimSpace(identities)
	if snapshot == "" || identities == "" {
		return nil, errors.New("snapshot JSON and identity map YAML paths are required")
	}
	args := []string{"review", snapshot, "--identities", identities}
	for _, output := range []struct{ flag, value string }{
		{"--json", jsonOutput}, {"--html", htmlOutput}, {"--csv", csvOutput},
	} {
		if value := strings.TrimSpace(output.value); value != "" {
			args = append(args, output.flag, value)
		}
	}
	failOn, err := access.NormalizeFailOnSeverity(failOn)
	if err != nil {
		return nil, err
	}
	if failOn != "" {
		args = append(args, "--fail-on", failOn)
	}
	return args, nil
}

func (s *uiState) openAccessOffboardingForm() {
	var identity, snapshot, review, jsonOutput, htmlOutput, csvOutput string
	form := tview.NewForm()
	form.AddInputField("identity ID", "", 64, nil, func(v string) { identity = v })
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("ownership review JSON", "", 64, nil, func(v string) { review = v })
	form.AddInputField("offboarding JSON (optional)", "", 64, nil, func(v string) { jsonOutput = v })
	form.AddInputField("offboarding HTML (optional)", "", 64, nil, func(v string) { htmlOutput = v })
	form.AddInputField("offboarding CSV (optional)", "", 64, nil, func(v string) { csvOutput = v })
	form.AddButton("Build read-only report", func() {
		args, err := accessOffboardingExtraArgs(identity, snapshot, review, jsonOutput, htmlOutput, csvOutput)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessoffboarding")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessoffboarding")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessoffboarding", " read-only offboarding report · no remote changes ", form, 17)
}

func accessOffboardingExtraArgs(identity, snapshot, review, jsonOutput, htmlOutput, csvOutput string) ([]string, error) {
	identity = strings.TrimSpace(identity)
	snapshot = strings.TrimSpace(snapshot)
	review = strings.TrimSpace(review)
	if identity == "" || snapshot == "" || review == "" {
		return nil, errors.New("identity ID, snapshot JSON, and ownership review JSON are required")
	}
	args := []string{"offboarding", identity, "--scan", snapshot, "--review", review}
	for _, output := range []struct{ flag, value string }{
		{"--json", jsonOutput}, {"--html", htmlOutput}, {"--csv", csvOutput},
	} {
		if value := strings.TrimSpace(output.value); value != "" {
			args = append(args, output.flag, value)
		}
	}
	return args, nil
}

func (s *uiState) openAccessOffboardingCheckForm() {
	var baseline, beforeScan, beforeReview, afterScan, afterReview, jsonOutput, htmlOutput, csvOutput string
	form := tview.NewForm()
	form.AddInputField("baseline report JSON", "", 64, nil, func(v string) { baseline = v })
	form.AddInputField("before snapshot JSON", "", 64, nil, func(v string) { beforeScan = v })
	form.AddInputField("before ownership review", "", 64, nil, func(v string) { beforeReview = v })
	form.AddInputField("after snapshot JSON", "", 64, nil, func(v string) { afterScan = v })
	form.AddInputField("after ownership review", "", 64, nil, func(v string) { afterReview = v })
	form.AddInputField("check JSON (optional)", "", 64, nil, func(v string) { jsonOutput = v })
	form.AddInputField("check HTML (optional)", "", 64, nil, func(v string) { htmlOutput = v })
	form.AddInputField("check CSV (optional)", "", 64, nil, func(v string) { csvOutput = v })
	form.AddButton("Compare read-only evidence", func() {
		args, err := accessOffboardingCheckExtraArgs(baseline, beforeScan, beforeReview, afterScan, afterReview, jsonOutput, htmlOutput, csvOutput)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessoffboardingcheck")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessoffboardingcheck")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessoffboardingcheck", " read-only offboarding check · no remote changes ", form, 21)
}

func accessOffboardingCheckExtraArgs(baseline, beforeScan, beforeReview, afterScan, afterReview, jsonOutput, htmlOutput, csvOutput string) ([]string, error) {
	values := []*string{&baseline, &beforeScan, &beforeReview, &afterScan, &afterReview}
	for _, value := range values {
		*value = strings.TrimSpace(*value)
		if *value == "" {
			return nil, errors.New("baseline report, before/after snapshots, and before/after ownership reviews are required")
		}
	}
	args := []string{
		"offboarding-check", "--baseline", baseline,
		"--before-scan", beforeScan, "--before-review", beforeReview,
		"--after-scan", afterScan, "--after-review", afterReview,
	}
	for _, output := range []struct{ flag, value string }{
		{"--json", jsonOutput}, {"--html", htmlOutput}, {"--csv", csvOutput},
	} {
		if value := strings.TrimSpace(output.value); value != "" {
			args = append(args, output.flag, value)
		}
	}
	return args, nil
}

func (s *uiState) openCloudUploadPlanForm() {
	var snapshot, workspace, output string
	var includeIdentityHints bool
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("workspace slug", "", 40, nil, func(v string) { workspace = v })
	form.AddInputField("upload plan JSON", "", 64, nil, func(v string) { output = v })
	form.AddCheckbox("include unverified identity hints", false, func(v bool) { includeIdentityHints = v })
	form.AddButton("Create local plan", func() {
		args, err := cloudUploadPlanExtraArgs(snapshot, workspace, output, includeIdentityHints)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "clouduploadplan")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("clouduploadplan")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("clouduploadplan", " offline Cloud upload plan · no network ", form, 14)
}

func cloudUploadPlanExtraArgs(snapshot, workspace, output string, includeIdentityHints bool) ([]string, error) {
	snapshot = strings.TrimSpace(snapshot)
	workspace = strings.TrimSpace(workspace)
	output = strings.TrimSpace(output)
	if snapshot == "" || workspace == "" || output == "" {
		return nil, errors.New("snapshot JSON, workspace slug, and upload plan JSON paths are required")
	}
	args := []string{"upload-plan", snapshot, "--workspace", workspace, "--out", output}
	if includeIdentityHints {
		args = append(args, "--include-identity-hints")
	}
	return args, nil
}

func (s *uiState) openCloudPushForm() {
	var snapshot, profile, endpoint, organization, project, workspace, tokenKeyring, tokenEnv string
	var ownershipPath, ownershipHistoryPath, offboardingHistoryPath, timeout string
	var includeIdentityHints, allowHTTPLoopback, skipPrompt bool
	form := tview.NewForm()
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddInputField("profile (empty = active/manual)", "", 40, nil, func(v string) { profile = v })
	form.AddInputField("manual API endpoint (optional)", "", 64, nil, func(v string) { endpoint = v })
	form.AddInputField("manual organization slug (v2)", "", 40, nil, func(v string) { organization = v })
	form.AddInputField("manual project slug (v2)", "", 40, nil, func(v string) { project = v })
	form.AddInputField("manual legacy workspace", "", 40, nil, func(v string) { workspace = v })
	form.AddInputField("manual token keyring entry", "", 40, nil, func(v string) { tokenKeyring = v })
	form.AddInputField("manual token env name", "", 40, nil, func(v string) { tokenEnv = v })
	form.AddInputField("ownership review JSON (optional)", "", 64, nil, func(v string) { ownershipPath = v })
	form.AddInputField("ownership history JSON (optional)", "", 64, nil, func(v string) { ownershipHistoryPath = v })
	form.AddInputField("offboarding history JSON (optional)", "", 64, nil, func(v string) { offboardingHistoryPath = v })
	form.AddInputField("upload timeout", "2m", 12, nil, func(v string) { timeout = v })
	form.AddCheckbox("include unverified identity hints", false, func(v bool) { includeIdentityHints = v })
	form.AddCheckbox("allow HTTP literal loopback (tests only)", false, func(v bool) { allowHTTPLoopback = v })
	form.AddCheckbox("skip prompt after privacy preview (--yes)", false, func(v bool) { skipPrompt = v })
	form.AddButton("Preview and push snapshot", func() {
		args, err := cloudPushExtraArgs(
			snapshot, profile, endpoint, organization, project, workspace, tokenKeyring, tokenEnv,
			ownershipPath, ownershipHistoryPath, offboardingHistoryPath, timeout,
			includeIdentityHints, allowHTTPLoopback, skipPrompt,
		)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudpush")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudpush")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudpush", " Cloud push · automatic private project history + explicit upload ", form, 36)
}

func cloudPushExtraArgs(snapshot, profile, endpoint, organization, project, workspace, tokenKeyring, tokenEnv, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, timeout string, includeIdentityHints, allowHTTPLoopback, skipPrompt bool) ([]string, error) {
	snapshot = strings.TrimSpace(snapshot)
	profile = strings.TrimSpace(profile)
	endpoint = strings.TrimSpace(endpoint)
	organization = strings.TrimSpace(organization)
	project = strings.TrimSpace(project)
	workspace = strings.TrimSpace(workspace)
	tokenKeyring = strings.TrimSpace(tokenKeyring)
	tokenEnv = strings.TrimSpace(tokenEnv)
	ownershipPath = strings.TrimSpace(ownershipPath)
	ownershipHistoryPath = strings.TrimSpace(ownershipHistoryPath)
	offboardingHistoryPath = strings.TrimSpace(offboardingHistoryPath)
	timeout = strings.TrimSpace(timeout)
	if snapshot == "" {
		return nil, errors.New("snapshot JSON path is required")
	}
	manual := endpoint != "" || organization != "" || project != "" || workspace != "" || tokenKeyring != "" || tokenEnv != "" || allowHTTPLoopback
	if profile != "" && manual {
		return nil, errors.New("select either a profile or a manual endpoint/context")
	}
	if manual {
		if endpoint == "" || (tokenKeyring == "") == (tokenEnv == "") {
			return nil, errors.New("manual push requires an endpoint and exactly one token source")
		}
		if (organization == "") != (project == "") {
			return nil, errors.New("manual organization and project are required together")
		}
		if (organization != "") == (workspace != "") {
			return nil, errors.New("manual push requires either organization/project or a legacy workspace")
		}
	}
	if timeout == "" {
		timeout = "2m"
	}
	if duration, err := time.ParseDuration(timeout); err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, errors.New("push timeout must be a duration greater than zero and at most 10m")
	}
	args := []string{"push", snapshot}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	if manual {
		args = append(args, "--endpoint", endpoint)
		if organization != "" {
			args = append(args, "--organization", organization, "--project", project)
		} else {
			args = append(args, "--workspace", workspace)
		}
		if tokenKeyring != "" {
			args = append(args, "--token-keyring", tokenKeyring)
		} else {
			args = append(args, "--token-env", tokenEnv)
		}
	}
	for _, artifact := range []struct{ flag, path string }{
		{"--ownership-review", ownershipPath},
		{"--ownership-history", ownershipHistoryPath},
		{"--offboarding-history", offboardingHistoryPath},
	} {
		if artifact.path != "" {
			args = append(args, artifact.flag, artifact.path)
		}
	}
	if includeIdentityHints {
		args = append(args, "--include-identity-hints")
	}
	args = append(args, "--timeout", timeout)
	if allowHTTPLoopback {
		args = append(args, "--allow-http-loopback")
	}
	if skipPrompt {
		args = append(args, "--yes")
	}
	return args, nil
}

func (s *uiState) openCloudInspectForm() {
	var planPath string
	form := tview.NewForm()
	form.AddInputField("upload plan JSON", "", 64, nil, func(v string) { planPath = v })
	form.AddButton("Inspect local plan", func() {
		args, err := cloudInspectExtraArgs(planPath)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudinspect")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudinspect")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudinspect", " inspect offline Cloud upload plan · no network ", form, 10)
}

func cloudInspectExtraArgs(planPath string) ([]string, error) {
	planPath = strings.TrimSpace(planPath)
	if planPath == "" {
		return nil, errors.New("upload plan JSON path is required")
	}
	return []string{"inspect", planPath}, nil
}

func (s *uiState) openCloudHistoryBuildForm() {
	var inputs, output string
	form := tview.NewForm()
	form.AddInputField("upload plan JSON files (comma separated)", "", 64, nil, func(v string) { inputs = v })
	form.AddInputField("workspace history JSON", "", 64, nil, func(v string) { output = v })
	form.AddButton("Build local history", func() {
		args, err := cloudHistoryBuildExtraArgs(inputs, output)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudhistorybuild")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudhistorybuild")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudhistorybuild", " build offline Cloud workspace history · no network ", form, 11)
}

func cloudHistoryBuildExtraArgs(inputs, output string) ([]string, error) {
	paths := splitAccessFormCSV(inputs)
	output = strings.TrimSpace(output)
	if len(paths) == 0 || output == "" {
		return nil, errors.New("at least one upload plan and the workspace history JSON path are required")
	}
	args := append([]string{"history-build"}, paths...)
	return append(args, "--out", output), nil
}

func (s *uiState) openCloudHistoryInspectForm() {
	var historyPath string
	form := tview.NewForm()
	form.AddInputField("workspace history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddButton("Inspect local history", func() {
		args, err := cloudHistoryInspectExtraArgs(historyPath)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudhistoryinspect")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudhistoryinspect")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudhistoryinspect", " inspect offline Cloud workspace history · no network ", form, 10)
}

func cloudHistoryInspectExtraArgs(historyPath string) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	if historyPath == "" {
		return nil, errors.New("workspace history JSON path is required")
	}
	return []string{"history-inspect", historyPath}, nil
}

func (s *uiState) openCloudOwnershipHistoryBuildForm() {
	var historyPath, reviews, output string
	form := tview.NewForm()
	form.AddInputField("workspace history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddInputField("ownership review JSON files (comma separated)", "", 64, nil, func(v string) { reviews = v })
	form.AddInputField("ownership history JSON", "", 64, nil, func(v string) { output = v })
	form.AddButton("Build ownership history", func() {
		args, err := cloudOwnershipHistoryBuildExtraArgs(historyPath, reviews, output)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudownershiphistorybuild")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudownershiphistorybuild")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudownershiphistorybuild", " build offline Cloud ownership history · no network ", form, 12)
}

func cloudOwnershipHistoryBuildExtraArgs(historyPath, reviews, output string) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	reviewPaths := splitAccessFormCSV(reviews)
	output = strings.TrimSpace(output)
	if historyPath == "" || len(reviewPaths) == 0 || output == "" {
		return nil, errors.New("workspace history, at least one ownership review, and output JSON paths are required")
	}
	args := append([]string{"ownership-history-build", historyPath}, reviewPaths...)
	return append(args, "--out", output), nil
}

func (s *uiState) openCloudOwnershipHistoryInspectForm() {
	var historyPath string
	form := tview.NewForm()
	form.AddInputField("ownership history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddButton("Inspect ownership history", func() {
		args, err := cloudOwnershipHistoryInspectExtraArgs(historyPath)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudownershiphistoryinspect")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudownershiphistoryinspect")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudownershiphistoryinspect", " inspect offline Cloud ownership history · no network ", form, 10)
}

func cloudOwnershipHistoryInspectExtraArgs(historyPath string) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	if historyPath == "" {
		return nil, errors.New("ownership history JSON path is required")
	}
	return []string{"ownership-history-inspect", historyPath}, nil
}

func (s *uiState) openCloudOffboardingHistoryBuildForm() {
	var historyPath, checks, output string
	form := tview.NewForm()
	form.AddInputField("workspace history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddInputField("offboarding check JSON files (comma separated)", "", 64, nil, func(v string) { checks = v })
	form.AddInputField("offboarding history JSON", "", 64, nil, func(v string) { output = v })
	form.AddButton("Build offboarding history", func() {
		args, err := cloudOffboardingHistoryBuildExtraArgs(historyPath, checks, output)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudoffboardinghistorybuild")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudoffboardinghistorybuild")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudoffboardinghistorybuild", " build offline Cloud offboarding history · no network ", form, 12)
}

func cloudOffboardingHistoryBuildExtraArgs(historyPath, checks, output string) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	checkPaths := splitAccessFormCSV(checks)
	output = strings.TrimSpace(output)
	if historyPath == "" || len(checkPaths) == 0 || output == "" {
		return nil, errors.New("workspace history, at least one offboarding check, and output JSON paths are required")
	}
	args := append([]string{"offboarding-history-build", historyPath}, checkPaths...)
	return append(args, "--out", output), nil
}

func (s *uiState) openCloudOffboardingHistoryInspectForm() {
	var historyPath string
	form := tview.NewForm()
	form.AddInputField("offboarding history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddButton("Inspect offboarding history", func() {
		args, err := cloudOffboardingHistoryInspectExtraArgs(historyPath)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudoffboardinghistoryinspect")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudoffboardinghistoryinspect")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudoffboardinghistoryinspect", " inspect offline Cloud offboarding history · no network ", form, 10)
}

func cloudOffboardingHistoryInspectExtraArgs(historyPath string) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	if historyPath == "" {
		return nil, errors.New("offboarding history JSON path is required")
	}
	return []string{"offboarding-history-inspect", historyPath}, nil
}

func (s *uiState) openCloudBundleBuildForm() {
	var historyPath, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, output string
	form := tview.NewForm()
	form.AddInputField("workspace history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddInputField("ownership review JSON (optional)", "", 64, nil, func(v string) { ownershipPath = v })
	form.AddInputField("ownership history JSON (optional)", "", 64, nil, func(v string) { ownershipHistoryPath = v })
	form.AddInputField("offboarding history JSON (optional)", "", 64, nil, func(v string) { offboardingHistoryPath = v })
	form.AddInputField("ingestion bundle JSON", "", 64, nil, func(v string) { output = v })
	form.AddButton("Build ingestion bundle", func() {
		args, err := cloudBundleBuildExtraArgs(historyPath, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, output)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudbundlebuild")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudbundlebuild")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudbundlebuild", " build offline Cloud ingestion bundle · no network ", form, 16)
}

func cloudBundleBuildExtraArgs(historyPath, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, output string) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	ownershipPath = strings.TrimSpace(ownershipPath)
	ownershipHistoryPath = strings.TrimSpace(ownershipHistoryPath)
	offboardingHistoryPath = strings.TrimSpace(offboardingHistoryPath)
	output = strings.TrimSpace(output)
	if historyPath == "" || output == "" {
		return nil, errors.New("workspace history and ingestion bundle output JSON paths are required")
	}
	args := []string{"bundle-build", historyPath}
	if ownershipPath != "" {
		args = append(args, "--ownership-review", ownershipPath)
	}
	if ownershipHistoryPath != "" {
		args = append(args, "--ownership-history", ownershipHistoryPath)
	}
	if offboardingHistoryPath != "" {
		args = append(args, "--offboarding-history", offboardingHistoryPath)
	}
	return append(args, "--out", output), nil
}

func (s *uiState) openCloudBundleInspectForm() {
	var bundlePath string
	form := tview.NewForm()
	form.AddInputField("ingestion bundle JSON", "", 64, nil, func(v string) { bundlePath = v })
	form.AddButton("Inspect ingestion bundle", func() {
		args, err := cloudBundleInspectExtraArgs(bundlePath)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudbundleinspect")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudbundleinspect")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudbundleinspect", " inspect offline Cloud ingestion bundle · no network ", form, 10)
}

func cloudBundleInspectExtraArgs(bundlePath string) ([]string, error) {
	bundlePath = strings.TrimSpace(bundlePath)
	if bundlePath == "" {
		return nil, errors.New("ingestion bundle JSON path is required")
	}
	return []string{"bundle-inspect", bundlePath}, nil
}

func (s *uiState) openCloudProfileMenu() {
	list := tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.SelText).SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).SetTitle(" Cloud profiles · CLI parity   (Enter=open  Esc=back) ").
		SetTitleAlign(tview.AlignLeft).SetBorderColor(theme.Current.Primary).SetTitleColor(theme.Current.Primary)
	back := func() {
		s.pages.RemovePage("cloudprofiles")
		s.openAccessMenu()
	}
	list.AddItem("login / configure profile", "verify token over HTTPS, then save metadata and keyring reference", 'l', func() {
		s.pages.RemovePage("cloudprofiles")
		s.openCloudLoginForm()
	})
	list.AddItem("remote service status", "authenticate the selected profile and query workspace capabilities", 's', func() {
		s.pages.RemovePage("cloudprofiles")
		s.openCloudStatusForm()
	})
	list.AddItem("show profile/workspace", "display one local profile without a network request", 'h', func() {
		s.pages.RemovePage("cloudprofiles")
		s.openCloudWorkspaceShowForm()
	})
	list.AddItem("list profiles", "list all local profiles; no token values and no network request", 'a', func() {
		s.launchCloud([]string{"workspace", "list"}, "cloudprofiles")
	})
	list.AddItem("use profile", "select the active profile used by status and upload", 'u', func() {
		s.pages.RemovePage("cloudprofiles")
		s.openCloudWorkspaceUseForm()
	})
	list.AddItem("set organization/project", "switch a profile to explicit v2 organization/project context", 'p', func() {
		s.pages.RemovePage("cloudprofiles")
		s.openCloudProjectSetForm()
	})
	list.AddItem("set workspace (legacy v1)", "change a legacy profile workspace locally; verify later with status", 'w', func() {
		s.pages.RemovePage("cloudprofiles")
		s.openCloudWorkspaceSetForm()
	})
	list.AddItem("back to access audit", "", 'b', back)
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			back()
			return nil
		}
		return event
	})
	s.pages.AddPage("cloudprofiles", centered(list, 78, 13), true, true)
	s.app.SetFocus(list)
}

func (s *uiState) openCloudLoginForm() {
	var profile, endpoint, organization, project, workspace, tokenKeyring, tokenEnv, timeout string
	var allowHTTPLoopback, confirmed bool
	form := tview.NewForm()
	form.AddInputField("profile name", "", 32, nil, func(v string) { profile = v })
	form.AddInputField("Cloud API endpoint", "https://", 64, nil, func(v string) { endpoint = v })
	form.AddInputField("organization slug (v2)", "", 40, nil, func(v string) { organization = v })
	form.AddInputField("project slug (v2)", "", 40, nil, func(v string) { project = v })
	form.AddInputField("legacy workspace slug (v1 only)", "", 40, nil, func(v string) { workspace = v })
	form.AddInputField("existing token keyring entry", "", 40, nil, func(v string) { tokenKeyring = v })
	form.AddInputField("token env name (store in keyring)", "", 40, nil, func(v string) { tokenEnv = v })
	form.AddInputField("verification timeout", "30s", 12, nil, func(v string) { timeout = v })
	form.AddCheckbox("allow HTTP literal loopback (tests only)", false, func(v bool) { allowHTTPLoopback = v })
	form.AddCheckbox("confirm authenticated network login", false, func(v bool) { confirmed = v })
	form.AddButton("Verify and save profile", func() {
		args, err := cloudLoginExtraArgs(profile, endpoint, organization, project, workspace, tokenKeyring, tokenEnv, timeout, allowHTTPLoopback, confirmed)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudlogin")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudlogin")
		s.openCloudProfileMenu()
	})
	s.openCloudProfileUtilityForm("cloudlogin", " Cloud login · organization/project or legacy workspace ", form, 26)
}

func cloudLoginExtraArgs(profile, endpoint, organization, project, workspace, tokenKeyring, tokenEnv, timeout string, allowHTTPLoopback, confirmed bool) ([]string, error) {
	profile, endpoint, workspace = strings.TrimSpace(profile), strings.TrimSpace(endpoint), strings.TrimSpace(workspace)
	organization, project = strings.TrimSpace(organization), strings.TrimSpace(project)
	tokenKeyring, tokenEnv, timeout = strings.TrimSpace(tokenKeyring), strings.TrimSpace(tokenEnv), strings.TrimSpace(timeout)
	if profile == "" || endpoint == "" || (tokenKeyring == "") == (tokenEnv == "") {
		return nil, errors.New("profile, endpoint, and exactly one keyring entry or token environment name are required")
	}
	if (organization == "") != (project == "") {
		return nil, errors.New("organization and project are required together")
	}
	if (organization != "") == (workspace != "") {
		return nil, errors.New("select either organization/project or the legacy workspace, not both")
	}
	if !confirmed {
		return nil, errors.New("confirm the authenticated network login")
	}
	if timeout == "" {
		timeout = "30s"
	}
	if duration, err := time.ParseDuration(timeout); err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, errors.New("login timeout must be greater than zero and at most 10m")
	}
	args := []string{"login", profile, "--endpoint", endpoint}
	if organization != "" {
		args = append(args, "--organization", organization, "--project", project)
	} else {
		args = append(args, "--workspace", workspace)
	}
	if tokenKeyring != "" {
		args = append(args, "--token-keyring", tokenKeyring)
	} else {
		args = append(args, "--token-env", tokenEnv)
	}
	args = append(args, "--timeout", timeout)
	if allowHTTPLoopback {
		args = append(args, "--allow-http-loopback")
	}
	return args, nil
}

func (s *uiState) openCloudStatusForm() {
	var profile, timeout string
	var asJSON, confirmed bool
	form := tview.NewForm()
	form.AddInputField("profile (empty = active)", "", 40, nil, func(v string) { profile = v })
	form.AddInputField("request timeout", "30s", 12, nil, func(v string) { timeout = v })
	form.AddCheckbox("JSON output", false, func(v bool) { asJSON = v })
	form.AddCheckbox("confirm authenticated status request", false, func(v bool) { confirmed = v })
	form.AddButton("Query remote status", func() {
		args, err := cloudStatusExtraArgs(profile, timeout, asJSON, confirmed)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudstatus")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudstatus")
		s.openCloudProfileMenu()
	})
	s.openCloudProfileUtilityForm("cloudstatus", " Cloud status · authenticated network request ", form, 16)
}

func cloudStatusExtraArgs(profile, timeout string, asJSON, confirmed bool) ([]string, error) {
	profile, timeout = strings.TrimSpace(profile), strings.TrimSpace(timeout)
	if !confirmed {
		return nil, errors.New("confirm the authenticated status request")
	}
	if timeout == "" {
		timeout = "30s"
	}
	if duration, err := time.ParseDuration(timeout); err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, errors.New("status timeout must be greater than zero and at most 10m")
	}
	args := []string{"status", "--timeout", timeout}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	if asJSON {
		args = append(args, "--json")
	}
	return args, nil
}

func (s *uiState) openCloudWorkspaceShowForm() {
	var profile string
	var asJSON bool
	form := tview.NewForm()
	form.AddInputField("profile (empty = active)", "", 40, nil, func(v string) { profile = v })
	form.AddCheckbox("JSON output", false, func(v bool) { asJSON = v })
	form.AddButton("Show local profile", func() { s.launchCloud(cloudWorkspaceShowArgs(profile, asJSON), "cloudworkspaceshow") })
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudworkspaceshow")
		s.openCloudProfileMenu()
	})
	s.openCloudProfileUtilityForm("cloudworkspaceshow", " Show Cloud profile · no network ", form, 12)
}

func cloudWorkspaceShowArgs(profile string, asJSON bool) []string {
	args := []string{"workspace", "show"}
	if profile = strings.TrimSpace(profile); profile != "" {
		args = append(args, "--profile", profile)
	}
	if asJSON {
		args = append(args, "--json")
	}
	return args
}

func (s *uiState) openCloudWorkspaceUseForm() {
	var profile string
	form := tview.NewForm()
	form.AddInputField("profile name", "", 40, nil, func(v string) { profile = v })
	form.AddButton("Use profile", func() {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			s.modal("profile name is required", func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud([]string{"workspace", "use", profile}, "cloudworkspaceuse")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudworkspaceuse")
		s.openCloudProfileMenu()
	})
	s.openCloudProfileUtilityForm("cloudworkspaceuse", " Select active Cloud profile · no network ", form, 11)
}

func (s *uiState) openCloudWorkspaceSetForm() {
	var profile, workspace string
	form := tview.NewForm()
	form.AddInputField("profile (empty = active)", "", 40, nil, func(v string) { profile = v })
	form.AddInputField("workspace slug", "", 40, nil, func(v string) { workspace = v })
	form.AddButton("Set workspace", func() {
		args, err := cloudWorkspaceSetArgs(profile, workspace)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudworkspaceset")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudworkspaceset")
		s.openCloudProfileMenu()
	})
	s.openCloudProfileUtilityForm("cloudworkspaceset", " Set Cloud workspace · verify later with status ", form, 12)
}

func cloudWorkspaceSetArgs(profile, workspace string) ([]string, error) {
	profile, workspace = strings.TrimSpace(profile), strings.TrimSpace(workspace)
	if workspace == "" {
		return nil, errors.New("workspace slug is required")
	}
	args := []string{"workspace", "set", workspace}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return args, nil
}

func (s *uiState) openCloudProjectSetForm() {
	var profile, organization, project string
	form := tview.NewForm()
	form.AddInputField("profile (empty = active)", "", 40, nil, func(v string) { profile = v })
	form.AddInputField("organization slug", "", 40, nil, func(v string) { organization = v })
	form.AddInputField("project slug", "", 40, nil, func(v string) { project = v })
	form.AddButton("Set organization/project", func() {
		args, err := cloudProjectSetArgs(profile, organization, project)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudprojectset")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudprojectset")
		s.openCloudProfileMenu()
	})
	s.openCloudProfileUtilityForm("cloudprojectset", " Set Cloud organization/project · verify later with status ", form, 13)
}

func cloudProjectSetArgs(profile, organization, project string) ([]string, error) {
	profile, organization, project = strings.TrimSpace(profile), strings.TrimSpace(organization), strings.TrimSpace(project)
	if organization == "" || project == "" {
		return nil, errors.New("organization and project slugs are required")
	}
	args := []string{"project", "set", project, "--organization", organization}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return args, nil
}

func (s *uiState) openCloudUploadForm() {
	var bundlePath, profile, endpoint, organization, project, tokenKeyring, tokenEnv, timeout string
	var allowHTTPLoopback, confirmed bool
	form := tview.NewForm()
	form.AddInputField("ingestion bundle JSON", "", 64, nil, func(v string) { bundlePath = v })
	form.AddInputField("profile (empty = active/manual)", "", 40, nil, func(v string) { profile = v })
	form.AddInputField("manual API endpoint (optional)", "", 64, nil, func(v string) { endpoint = v })
	form.AddInputField("manual organization slug (v2 optional)", "", 40, nil, func(v string) { organization = v })
	form.AddInputField("manual project slug (v2 optional)", "", 40, nil, func(v string) { project = v })
	form.AddInputField("token keyring entry (preferred)", "", 40, nil, func(v string) { tokenKeyring = v })
	form.AddInputField("token env name (CI alternative)", "", 40, nil, func(v string) { tokenEnv = v })
	form.AddInputField("upload timeout", "2m", 12, nil, func(v string) { timeout = v })
	form.AddCheckbox("allow HTTP literal loopback (tests only)", false, func(v bool) { allowHTTPLoopback = v })
	form.AddCheckbox("confirm explicit network upload", false, func(v bool) { confirmed = v })
	form.AddButton("Upload validated bundle", func() {
		args, err := cloudUploadExtraArgs(bundlePath, profile, endpoint, organization, project, tokenKeyring, tokenEnv, timeout, allowHTTPLoopback, confirmed)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "cloudupload")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("cloudupload")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("cloudupload", " explicit Cloud bundle upload · profile or manual origin ", form, 25)
}

func cloudUploadExtraArgs(bundlePath, profile, endpoint, organization, project, tokenKeyring, tokenEnv, timeout string, allowHTTPLoopback, confirmed bool) ([]string, error) {
	bundlePath = strings.TrimSpace(bundlePath)
	profile = strings.TrimSpace(profile)
	endpoint = strings.TrimSpace(endpoint)
	organization = strings.TrimSpace(organization)
	project = strings.TrimSpace(project)
	tokenKeyring = strings.TrimSpace(tokenKeyring)
	tokenEnv = strings.TrimSpace(tokenEnv)
	timeout = strings.TrimSpace(timeout)
	if bundlePath == "" {
		return nil, errors.New("ingestion bundle is required")
	}
	manual := endpoint != "" || tokenKeyring != "" || tokenEnv != ""
	if profile != "" && manual {
		return nil, errors.New("select either a profile or a manual endpoint/token source")
	}
	if manual && (endpoint == "" || (tokenKeyring == "") == (tokenEnv == "")) {
		return nil, errors.New("manual upload requires endpoint and exactly one token source")
	}
	if (organization == "") != (project == "") {
		return nil, errors.New("organization and project are required together")
	}
	if organization != "" && !manual {
		return nil, errors.New("organization/project apply to manual uploads only; a profile upload uses the profile context")
	}
	if !manual && allowHTTPLoopback {
		return nil, errors.New("HTTP loopback is stored in a profile or requires a manual endpoint")
	}
	if !confirmed {
		return nil, errors.New("confirm the explicit network upload")
	}
	if timeout == "" {
		timeout = "2m"
	}
	if duration, err := time.ParseDuration(timeout); err != nil || duration <= 0 || duration > 10*time.Minute {
		return nil, errors.New("upload timeout must be a duration greater than zero and at most 10m")
	}
	args := []string{"upload", bundlePath}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	if manual {
		args = append(args, "--endpoint", endpoint)
		if tokenKeyring != "" {
			args = append(args, "--token-keyring", tokenKeyring)
		} else {
			args = append(args, "--token-env", tokenEnv)
		}
		if organization != "" {
			args = append(args, "--organization", organization, "--project", project)
		}
	}
	args = append(args, "--timeout", timeout)
	if allowHTTPLoopback {
		args = append(args, "--allow-http-loopback")
	}
	return args, nil
}

func (s *uiState) openCloudDashboardForm() {
	var historyPath, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, htmlPath, csvPath string
	var gate cloudDashboardGateValues
	form := tview.NewForm()
	form.AddInputField("workspace history JSON", "", 64, nil, func(v string) { historyPath = v })
	form.AddInputField("ownership review JSON (optional)", "", 64, nil, func(v string) { ownershipPath = v })
	form.AddInputField("ownership history JSON (optional)", "", 64, nil, func(v string) { ownershipHistoryPath = v })
	form.AddInputField("offboarding history JSON (optional)", "", 64, nil, func(v string) { offboardingHistoryPath = v })
	form.AddInputField("dashboard HTML (optional)", "", 64, nil, func(v string) { htmlPath = v })
	form.AddInputField("access review CSV (optional)", "", 64, nil, func(v string) { csvPath = v })
	addAccessFailOnDropDown(form, &gate.FailOn)
	form.AddCheckbox("require full latest coverage", false, func(v bool) { gate.RequireFull = v })
	form.AddCheckbox("require current ownership", false, func(v bool) { gate.RequireCurrentOwnership = v })
	form.AddCheckbox("require complete offboarding", false, func(v bool) { gate.RequireCompleteOffboarding = v })
	form.AddButton("Render local dashboard", func() {
		args, err := cloudDashboardExtraArgs(historyPath, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, htmlPath, csvPath, gate)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchCloud(args, "clouddashboard")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("clouddashboard")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("clouddashboard", " render offline Cloud workspace dashboard · no network ", form, 26)
}

func cloudDashboardExtraArgs(historyPath, ownershipPath, ownershipHistoryPath, offboardingHistoryPath, htmlPath, csvPath string, gate cloudDashboardGateValues) ([]string, error) {
	historyPath = strings.TrimSpace(historyPath)
	ownershipPath = strings.TrimSpace(ownershipPath)
	ownershipHistoryPath = strings.TrimSpace(ownershipHistoryPath)
	offboardingHistoryPath = strings.TrimSpace(offboardingHistoryPath)
	htmlPath = strings.TrimSpace(htmlPath)
	csvPath = strings.TrimSpace(csvPath)
	if historyPath == "" || (htmlPath == "" && csvPath == "") {
		return nil, errors.New("workspace history JSON and at least one HTML or CSV output path are required")
	}
	args := []string{"dashboard", historyPath}
	if ownershipPath != "" {
		args = append(args, "--ownership-review", ownershipPath)
	}
	if ownershipHistoryPath != "" {
		args = append(args, "--ownership-history", ownershipHistoryPath)
	}
	if offboardingHistoryPath != "" {
		args = append(args, "--offboarding-history", offboardingHistoryPath)
	}
	if htmlPath != "" {
		args = append(args, "--html", htmlPath)
	}
	if csvPath != "" {
		args = append(args, "--csv", csvPath)
	}
	failOn, err := access.NormalizeFailOnSeverity(gate.FailOn)
	if err != nil {
		return nil, err
	}
	if failOn != "" {
		args = append(args, "--fail-on", failOn)
	}
	if gate.RequireFull {
		args = append(args, "--require-full")
	}
	if gate.RequireCurrentOwnership {
		args = append(args, "--require-current-ownership")
	}
	if gate.RequireCompleteOffboarding {
		args = append(args, "--require-complete-offboarding")
	}
	return args, nil
}

func (s *uiState) openAccessDiffForm() {
	var before, after string
	form := tview.NewForm()
	form.AddInputField("before snapshot", "", 64, nil, func(v string) { before = v })
	form.AddInputField("after snapshot", "", 64, nil, func(v string) { after = v })
	form.AddButton("Run", func() {
		args, err := accessDiffExtraArgs(before, after)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accessdiff")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accessdiff")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accessdiff", " access diff ", form, 11)
}

func accessDiffExtraArgs(before, after string) ([]string, error) {
	before = strings.TrimSpace(before)
	after = strings.TrimSpace(after)
	if before == "" || after == "" {
		return nil, errors.New("both before and after snapshot paths are required")
	}
	return []string{"diff", before, after}, nil
}

func (s *uiState) openAccessWhoHasForm(defaultHost string) {
	host := defaultHost
	var snapshot string
	form := tview.NewForm()
	form.AddInputField("host alias", host, 48, nil, func(v string) { host = v })
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddButton("Run", func() {
		args, err := accessLookupExtraArgs("who-has", host, snapshot)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accesswhohas")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accesswhohas")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accesswhohas", " who has access? ", form, 11)
}

func (s *uiState) openAccessWhereIsKeyForm() {
	var fingerprint, snapshot string
	form := tview.NewForm()
	form.AddInputField("SHA256 fingerprint", "", 64, nil, func(v string) { fingerprint = v })
	form.AddInputField("snapshot JSON", "", 64, nil, func(v string) { snapshot = v })
	form.AddButton("Run", func() {
		args, err := accessLookupExtraArgs("where-is-key", fingerprint, snapshot)
		if err != nil {
			s.modal(err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.launchAccess(args, "accesswhereiskey")
	})
	form.AddButton("Back", func() {
		s.pages.RemovePage("accesswhereiskey")
		s.openAccessMenu()
	})
	s.openAccessUtilityForm("accesswhereiskey", " where is key? ", form, 11)
}

func accessLookupExtraArgs(command, value, snapshot string) ([]string, error) {
	if command != "who-has" && command != "where-is-key" {
		return nil, fmt.Errorf("unsupported access lookup %q", command)
	}
	value = strings.TrimSpace(value)
	snapshot = strings.TrimSpace(snapshot)
	if value == "" {
		return nil, errors.New("host alias or SHA256 fingerprint is required")
	}
	if snapshot == "" {
		return nil, errors.New("snapshot JSON path is required")
	}
	return []string{command, value, "--scan", snapshot}, nil
}

func (s *uiState) openAccessUtilityForm(page, title string, form *tview.Form, height int) {
	styleAccessForm(form, title)
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			s.pages.RemovePage(page)
			s.openAccessMenu()
			return nil
		}
		return event
	})
	s.pages.AddPage(page, centered(form, 78, height), true, true)
	s.app.SetFocus(form)
}

func (s *uiState) openCloudProfileUtilityForm(page, title string, form *tview.Form, height int) {
	styleAccessForm(form, title)
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			s.pages.RemovePage(page)
			s.openCloudProfileMenu()
			return nil
		}
		return event
	})
	s.pages.AddPage(page, centered(form, 78, height), true, true)
	s.app.SetFocus(form)
}

func (s *uiState) launchAccess(args []string, page string) {
	s.action = ActionAccess
	s.extraArgs = append([]string(nil), args...)
	s.pages.RemovePage(page)
	s.app.Stop()
}

func (s *uiState) launchCloud(args []string, page string) {
	s.action = ActionCloud
	s.extraArgs = append([]string(nil), args...)
	s.pages.RemovePage(page)
	s.app.Stop()
}

func styleAccessForm(form *tview.Form, title string) {
	form.SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).
		SetTitle(title).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
}

func styleAccessDropDown(form *tview.Form, label string) {
	if dd, ok := form.GetFormItemByLabel(label).(*tview.DropDown); ok {
		dd.SetListStyles(
			tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(theme.Current.Text),
			tcell.StyleDefault.Background(theme.Current.Selection).Foreground(theme.Current.SelText).Bold(true),
		)
	}
}

func addAccessFailOnDropDown(form *tview.Form, value *string) {
	labels := []string{"disabled (default)", "critical", "high + critical", "medium and above", "low and above", "all findings"}
	severities := []string{"", access.SeverityCritical, access.SeverityHigh, access.SeverityMedium, access.SeverityLow, access.SeverityInfo}
	form.AddDropDown("fail on findings", labels, 0, func(_ string, index int) {
		*value = severities[index]
	})
	styleAccessDropDown(form, "fail on findings")
}
