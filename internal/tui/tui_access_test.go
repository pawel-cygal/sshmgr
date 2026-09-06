package tui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestAccessScanExtraArgsCurrentMatchesCLI(t *testing.T) {
	got, err := accessScanExtraArgs(
		[]string{"--host", "web1,web2"},
		accessScanCurrent,
		accessScanFormValues{
			Output:            " scans/current.json ",
			Parallel:          "8",
			Timeout:           "1m",
			ExcludeHosts:      "esprit, esprit",
			ExcludeTags:       "legacy, lab",
			RequireFull:       true,
			FailOn:            " HIGH ",
			IncludePublicKeys: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"scan", "--host", "web1,web2", "--include-public-keys",
		"--out", "scans/current.json", "-p", "8", "--timeout", "1m0s",
		"--exclude-host", "esprit", "--exclude-tag", "legacy,lab", "--require-full", "--fail-on", "high",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("accessScanExtraArgs:\n got %q\nwant %q", got, want)
	}
}

func TestAccessScanExtraArgsSystemExplicitMatchesCLI(t *testing.T) {
	got, err := accessScanExtraArgs(
		[]string{"--group", "prod"},
		accessPreflightSystem,
		accessScanFormValues{
			Output:      "system.json",
			Parallel:    "3",
			Timeout:     "45s",
			UseSudo:     true,
			AccountMode: access.AccountModeExplicit,
			Accounts:    "deploy, root,deploy",
			MaxAccounts: "2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"scan", "--group", "prod", "--scope", "system", "--preflight", "--sudo",
		"--accounts", "explicit", "--account", "deploy,root", "--max-accounts", "2",
		"--out", "system.json", "-p", "3", "--timeout", "45s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("accessScanExtraArgs:\n got %q\nwant %q", got, want)
	}
}

func TestAccessScanExtraArgsRepeatedGroupsMatchCLI(t *testing.T) {
	got, err := accessScanExtraArgs(
		[]string{"--group", "cygal.lan"}, accessScanCurrent,
		accessScanFormValues{
			Output: "fleet.json", Parallel: "4", Timeout: "45s",
			Groups: "cygal.lan, systeam,cygal.lan", ExcludeHosts: "esprit",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"scan", "--group", "cygal.lan", "--group", "systeam",
		"--out", "fleet.json", "-p", "4", "--timeout", "45s", "--exclude-host", "esprit",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("repeated-group args=%q, want %q", got, want)
	}
}

func TestAccessScanExtraArgsSystemKeepsModeDefaultsInCLI(t *testing.T) {
	got, err := accessScanExtraArgs(
		[]string{"--host", "directory-host"},
		accessPreflightSystem,
		accessScanFormValues{
			Output:      "nss.json",
			Parallel:    "1",
			Timeout:     "2m",
			AccountMode: access.AccountModeNSS,
			MaxAccounts: "0",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--accounts nss") {
		t.Fatalf("NSS mode missing from args: %q", got)
	}
	if strings.Contains(joined, "--max-accounts") {
		t.Fatalf("0 should let the CLI apply the documented per-mode default: %q", got)
	}
	if strings.Contains(joined, "--sudo") {
		t.Fatalf("disabled sudo unexpectedly present: %q", got)
	}
}

func TestAccessScanExtraArgsSystemCollectionMatchesCLI(t *testing.T) {
	got, err := accessScanExtraArgs(
		[]string{"--group", "prod"},
		accessScanSystem,
		accessScanFormValues{
			Output:            "system-scan.json",
			Parallel:          "2",
			Timeout:           "90s",
			UseSudo:           true,
			AccountMode:       access.AccountModeExplicit,
			Accounts:          "root,deploy",
			MaxAccounts:       "2",
			MaxSourceMiB:      "2",
			MaxTotalMiB:       "8",
			IncludePublicKeys: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"scan", "--group", "prod", "--scope", "system", "--sudo",
		"--accounts", "explicit", "--account", "root,deploy", "--max-accounts", "2",
		"--max-source-mib", "2", "--max-total-mib", "8", "--include-public-keys",
		"--out", "system-scan.json", "-p", "2", "--timeout", "1m30s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("accessScanExtraArgs:\n got %q\nwant %q", got, want)
	}
}

func TestAccessScanExtraArgsDryRunDoesNotRequireSnapshot(t *testing.T) {
	got, err := accessScanExtraArgs(
		[]string{"--host", "web"}, accessScanCurrent,
		accessScanFormValues{Parallel: "4", Timeout: "45s", DryRun: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"scan", "--host", "web", "--dry-run", "-p", "4", "--timeout", "45s"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dry-run args=%q, want %q", got, want)
	}
}

func TestAccessScanExtraArgsRejectsInvalidFormValues(t *testing.T) {
	base := accessScanFormValues{
		Output:      "scan.json",
		Parallel:    "4",
		Timeout:     "45s",
		AccountMode: access.AccountModeLocal,
		MaxAccounts: "0",
	}
	tests := []struct {
		name     string
		selector []string
		kind     accessScanKind
		mutate   func(*accessScanFormValues)
	}{
		{"empty selector", nil, accessScanCurrent, func(*accessScanFormValues) {}},
		{"zero parallel", []string{"--host", "web"}, accessScanCurrent, func(v *accessScanFormValues) { v.Parallel = "0" }},
		{"invalid timeout", []string{"--host", "web"}, accessScanCurrent, func(v *accessScanFormValues) { v.Timeout = "soon" }},
		{"empty output", []string{"--host", "web"}, accessScanCurrent, func(v *accessScanFormValues) { v.Output = " " }},
		{"explicit without accounts", []string{"--host", "web"}, accessPreflightSystem, func(v *accessScanFormValues) { v.AccountMode = access.AccountModeExplicit }},
		{"over hard budget", []string{"--host", "web"}, accessPreflightSystem, func(v *accessScanFormValues) { v.MaxAccounts = "10001" }},
		{"source bytes above hard budget", []string{"--host", "web"}, accessScanSystem, func(v *accessScanFormValues) { v.MaxSourceMiB = "17" }},
		{"source bytes above total", []string{"--host", "web"}, accessScanSystem, func(v *accessScanFormValues) { v.MaxSourceMiB = "8"; v.MaxTotalMiB = "4" }},
		{"invalid fail-on severity", []string{"--host", "web"}, accessScanCurrent, func(v *accessScanFormValues) { v.FailOn = "warning" }},
		{"fail-on in dry run", []string{"--host", "web"}, accessScanCurrent, func(v *accessScanFormValues) { v.FailOn = "high"; v.DryRun = true }},
		{"group union on host target", []string{"--host", "web"}, accessScanCurrent, func(v *accessScanFormValues) { v.Groups = "prod,staging" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := base
			test.mutate(&values)
			if _, err := accessScanExtraArgs(test.selector, test.kind, values); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAccessUtilityArgsMatchCLI(t *testing.T) {
	report, err := accessReportExtraArgs(" scan.json ", " report.html ", " access.csv ", " HIGH ")
	if err != nil || !reflect.DeepEqual(report, []string{"report", "scan.json", "--html", "report.html", "--csv", "access.csv", "--fail-on", "high"}) {
		t.Fatalf("report args=%q err=%v", report, err)
	}
	graph, err := accessGraphExtraArgs(" scan.json ", " graph.json ")
	if err != nil || !reflect.DeepEqual(graph, []string{"graph", "scan.json", "--json", "graph.json"}) {
		t.Fatalf("graph args=%q err=%v", graph, err)
	}
	merge, err := accessMergeExtraArgs(" one.json, two.json,one.json ", " merged.json ")
	if err != nil || !reflect.DeepEqual(merge, []string{"merge", "one.json", "two.json", "--out", "merged.json"}) {
		t.Fatalf("merge args=%q err=%v", merge, err)
	}
	identityMap, err := accessIdentityMapExtraArgs(" scan.json ", " identities.yaml ")
	if err != nil || !reflect.DeepEqual(identityMap, []string{"identity-map", "scan.json", "--out", "identities.yaml"}) {
		t.Fatalf("identity map args=%q err=%v", identityMap, err)
	}
	review, err := accessReviewExtraArgs(" scan.json ", " identities.yaml ", " review.json ", " review.html ", " review.csv ", " medium ")
	if err != nil || !reflect.DeepEqual(review, []string{
		"review", "scan.json", "--identities", "identities.yaml",
		"--json", "review.json", "--html", "review.html", "--csv", "review.csv", "--fail-on", "medium",
	}) {
		t.Fatalf("review args=%q err=%v", review, err)
	}
	offboarding, err := accessOffboardingExtraArgs(" former@example.com ", " scan.json ", " review.json ", " offboarding.json ", " offboarding.html ", " offboarding.csv ")
	if err != nil || !reflect.DeepEqual(offboarding, []string{
		"offboarding", "former@example.com", "--scan", "scan.json", "--review", "review.json",
		"--json", "offboarding.json", "--html", "offboarding.html", "--csv", "offboarding.csv",
	}) {
		t.Fatalf("offboarding args=%q err=%v", offboarding, err)
	}
	offboardingCheck, err := accessOffboardingCheckExtraArgs(
		" baseline.json ", " before.json ", " before-review.json ", " after.json ", " after-review.json ",
		" check.json ", " check.html ", " check.csv ",
	)
	if err != nil || !reflect.DeepEqual(offboardingCheck, []string{
		"offboarding-check", "--baseline", "baseline.json",
		"--before-scan", "before.json", "--before-review", "before-review.json",
		"--after-scan", "after.json", "--after-review", "after-review.json",
		"--json", "check.json", "--html", "check.html", "--csv", "check.csv",
	}) {
		t.Fatalf("offboarding check args=%q err=%v", offboardingCheck, err)
	}
	cloudPlan, err := cloudUploadPlanExtraArgs(" scan.json ", " client-a ", " upload-plan.json ", true)
	if err != nil || !reflect.DeepEqual(cloudPlan, []string{
		"upload-plan", "scan.json", "--workspace", "client-a", "--out", "upload-plan.json", "--include-identity-hints",
	}) {
		t.Fatalf("cloud plan args=%q err=%v", cloudPlan, err)
	}
	cloudPush, err := cloudPushExtraArgs(
		" scan.json ", " prod ", " ", " ", " ", " ", " ", " ",
		" review.json ", " ownership-history.json ", " offboarding-history.json ", " 90s ",
		true, false, true,
	)
	if err != nil || !reflect.DeepEqual(cloudPush, []string{
		"push", "scan.json", "--profile", "prod",
		"--ownership-review", "review.json", "--ownership-history", "ownership-history.json",
		"--offboarding-history", "offboarding-history.json", "--include-identity-hints",
		"--timeout", "90s", "--yes",
	}) {
		t.Fatalf("cloud push args=%q err=%v", cloudPush, err)
	}
	manualCloudPush, err := cloudPushExtraArgs(
		" scan.json ", " ", " http://127.0.0.1:8787 ", " systeam ", " fleet ", " ", " ", " CLOUD_TOKEN ",
		" ", " ", " ", " ", false, true, false,
	)
	if err != nil || !reflect.DeepEqual(manualCloudPush, []string{
		"push", "scan.json", "--endpoint", "http://127.0.0.1:8787",
		"--organization", "systeam", "--project", "fleet", "--token-env", "CLOUD_TOKEN",
		"--timeout", "2m", "--allow-http-loopback",
	}) {
		t.Fatalf("manual cloud push args=%q err=%v", manualCloudPush, err)
	}
	cloudInspect, err := cloudInspectExtraArgs(" upload-plan.json ")
	if err != nil || !reflect.DeepEqual(cloudInspect, []string{"inspect", "upload-plan.json"}) {
		t.Fatalf("cloud inspect args=%q err=%v", cloudInspect, err)
	}
	cloudHistory, err := cloudHistoryBuildExtraArgs(" two.json, one.json,one.json ", " history.json ")
	if err != nil || !reflect.DeepEqual(cloudHistory, []string{"history-build", "two.json", "one.json", "--out", "history.json"}) {
		t.Fatalf("cloud history args=%q err=%v", cloudHistory, err)
	}
	cloudHistoryInspect, err := cloudHistoryInspectExtraArgs(" history.json ")
	if err != nil || !reflect.DeepEqual(cloudHistoryInspect, []string{"history-inspect", "history.json"}) {
		t.Fatalf("cloud history inspect args=%q err=%v", cloudHistoryInspect, err)
	}
	ownershipCloudHistory, err := cloudOwnershipHistoryBuildExtraArgs(" history.json ", " review-two.json, review-one.json ", " ownership-history.json ")
	if err != nil || !reflect.DeepEqual(ownershipCloudHistory, []string{"ownership-history-build", "history.json", "review-two.json", "review-one.json", "--out", "ownership-history.json"}) {
		t.Fatalf("cloud ownership history args=%q err=%v", ownershipCloudHistory, err)
	}
	if inspect, err := cloudOwnershipHistoryInspectExtraArgs(" ownership-history.json "); err != nil || !reflect.DeepEqual(inspect, []string{"ownership-history-inspect", "ownership-history.json"}) {
		t.Fatalf("cloud ownership history inspect args=%q err=%v", inspect, err)
	}
	offboardingCloudHistory, err := cloudOffboardingHistoryBuildExtraArgs(" history.json ", " check-two.json, check-one.json ", " offboarding-history.json ")
	if err != nil || !reflect.DeepEqual(offboardingCloudHistory, []string{"offboarding-history-build", "history.json", "check-two.json", "check-one.json", "--out", "offboarding-history.json"}) {
		t.Fatalf("cloud offboarding history args=%q err=%v", offboardingCloudHistory, err)
	}
	if inspect, err := cloudOffboardingHistoryInspectExtraArgs(" offboarding-history.json "); err != nil || !reflect.DeepEqual(inspect, []string{"offboarding-history-inspect", "offboarding-history.json"}) {
		t.Fatalf("cloud offboarding history inspect args=%q err=%v", inspect, err)
	}
	cloudBundle, err := cloudBundleBuildExtraArgs(" history.json ", " review.json ", " ownership-history.json ", " offboarding-history.json ", " workspace-bundle.json ")
	if err != nil || !reflect.DeepEqual(cloudBundle, []string{"bundle-build", "history.json", "--ownership-review", "review.json", "--ownership-history", "ownership-history.json", "--offboarding-history", "offboarding-history.json", "--out", "workspace-bundle.json"}) {
		t.Fatalf("cloud bundle args=%q err=%v", cloudBundle, err)
	}
	cloudBundleMinimal, err := cloudBundleBuildExtraArgs(" history.json ", " ", " ", " ", " workspace-bundle.json ")
	if err != nil || !reflect.DeepEqual(cloudBundleMinimal, []string{"bundle-build", "history.json", "--out", "workspace-bundle.json"}) {
		t.Fatalf("minimal cloud bundle args=%q err=%v", cloudBundleMinimal, err)
	}
	if inspect, err := cloudBundleInspectExtraArgs(" workspace-bundle.json "); err != nil || !reflect.DeepEqual(inspect, []string{"bundle-inspect", "workspace-bundle.json"}) {
		t.Fatalf("cloud bundle inspect args=%q err=%v", inspect, err)
	}
	cloudLogin, err := cloudLoginExtraArgs(" prod ", " https://cloud.example.test ", " ", " ", " client-a ", " cloud-client-a ", " ", " 30s ", false, true)
	if err != nil || !reflect.DeepEqual(cloudLogin, []string{"login", "prod", "--endpoint", "https://cloud.example.test", "--workspace", "client-a", "--token-keyring", "cloud-client-a", "--timeout", "30s"}) {
		t.Fatalf("cloud login args=%q err=%v", cloudLogin, err)
	}
	cloudProjectLogin, err := cloudLoginExtraArgs(" proj ", " https://cloud.example.test ", " systeam ", " fleet ", " ", " cloud-proj ", " ", " 30s ", false, true)
	if err != nil || !reflect.DeepEqual(cloudProjectLogin, []string{"login", "proj", "--endpoint", "https://cloud.example.test", "--organization", "systeam", "--project", "fleet", "--token-keyring", "cloud-proj", "--timeout", "30s"}) {
		t.Fatalf("cloud project login args=%q err=%v", cloudProjectLogin, err)
	}
	cloudStatus, err := cloudStatusExtraArgs(" prod ", " 20s ", true, true)
	if err != nil || !reflect.DeepEqual(cloudStatus, []string{"status", "--timeout", "20s", "--profile", "prod", "--json"}) {
		t.Fatalf("cloud status args=%q err=%v", cloudStatus, err)
	}
	if show := cloudWorkspaceShowArgs(" prod ", true); !reflect.DeepEqual(show, []string{"workspace", "show", "--profile", "prod", "--json"}) {
		t.Fatalf("cloud workspace show args=%q", show)
	}
	if set, err := cloudWorkspaceSetArgs(" prod ", " client-b "); err != nil || !reflect.DeepEqual(set, []string{"workspace", "set", "client-b", "--profile", "prod"}) {
		t.Fatalf("cloud workspace set args=%q err=%v", set, err)
	}
	if setProject, err := cloudProjectSetArgs(" prod ", " systeam ", " fleet "); err != nil || !reflect.DeepEqual(setProject, []string{"project", "set", "fleet", "--organization", "systeam", "--profile", "prod"}) {
		t.Fatalf("cloud project set args=%q err=%v", setProject, err)
	}
	cloudUpload, err := cloudUploadExtraArgs(" workspace-bundle.json ", " ", " https://cloud.example.test ", " ", " ", " cloud-client-a ", " ", " 90s ", false, true)
	if err != nil || !reflect.DeepEqual(cloudUpload, []string{"upload", "workspace-bundle.json", "--endpoint", "https://cloud.example.test", "--token-keyring", "cloud-client-a", "--timeout", "90s"}) {
		t.Fatalf("cloud upload args=%q err=%v", cloudUpload, err)
	}
	cloudProjectUpload, err := cloudUploadExtraArgs(" bundle.json ", " ", " https://cloud.example.test ", " systeam ", " fleet ", " cloud-client-a ", " ", " 90s ", false, true)
	if err != nil || !reflect.DeepEqual(cloudProjectUpload, []string{"upload", "bundle.json", "--endpoint", "https://cloud.example.test", "--token-keyring", "cloud-client-a", "--organization", "systeam", "--project", "fleet", "--timeout", "90s"}) {
		t.Fatalf("manual v2 cloud upload args=%q err=%v", cloudProjectUpload, err)
	}
	cloudUploadLoopback, err := cloudUploadExtraArgs(" bundle.json ", " ", " http://127.0.0.1:8787 ", " ", " ", " ", " CLOUD_TOKEN ", " ", true, true)
	if err != nil || !reflect.DeepEqual(cloudUploadLoopback, []string{"upload", "bundle.json", "--endpoint", "http://127.0.0.1:8787", "--token-env", "CLOUD_TOKEN", "--timeout", "2m", "--allow-http-loopback"}) {
		t.Fatalf("loopback cloud upload args=%q err=%v", cloudUploadLoopback, err)
	}
	cloudProfileUpload, err := cloudUploadExtraArgs(" bundle.json ", " prod ", " ", " ", " ", " ", " ", " 1m ", false, true)
	if err != nil || !reflect.DeepEqual(cloudProfileUpload, []string{"upload", "bundle.json", "--profile", "prod", "--timeout", "1m"}) {
		t.Fatalf("profile cloud upload args=%q err=%v", cloudProfileUpload, err)
	}
	cloudDashboard, err := cloudDashboardExtraArgs(" history.json ", " review.json ", " ownership-history.json ", " offboarding-history.json ", " dashboard.html ", " access-review.csv ", cloudDashboardGateValues{
		FailOn: " HIGH ", RequireFull: true, RequireCurrentOwnership: true, RequireCompleteOffboarding: true,
	})
	if err != nil || !reflect.DeepEqual(cloudDashboard, []string{"dashboard", "history.json", "--ownership-review", "review.json", "--ownership-history", "ownership-history.json", "--offboarding-history", "offboarding-history.json", "--html", "dashboard.html", "--csv", "access-review.csv", "--fail-on", "high", "--require-full", "--require-current-ownership", "--require-complete-offboarding"}) {
		t.Fatalf("cloud dashboard args=%q err=%v", cloudDashboard, err)
	}
	cloudDashboardWithoutOwnership, err := cloudDashboardExtraArgs(" history.json ", " ", " ", " ", " dashboard.html ", " ", cloudDashboardGateValues{})
	if err != nil || !reflect.DeepEqual(cloudDashboardWithoutOwnership, []string{"dashboard", "history.json", "--html", "dashboard.html"}) {
		t.Fatalf("cloud dashboard without ownership args=%q err=%v", cloudDashboardWithoutOwnership, err)
	}
	diff, err := accessDiffExtraArgs("before.json", "after.json")
	if err != nil || !reflect.DeepEqual(diff, []string{"diff", "before.json", "after.json"}) {
		t.Fatalf("diff args=%q err=%v", diff, err)
	}
	lookup, err := accessLookupExtraArgs("where-is-key", "SHA256:abc", "scan.json")
	if err != nil || !reflect.DeepEqual(lookup, []string{"where-is-key", "SHA256:abc", "--scan", "scan.json"}) {
		t.Fatalf("lookup args=%q err=%v", lookup, err)
	}
}

func TestAccessReportAndGraphRequireSnapshot(t *testing.T) {
	if _, err := accessReportExtraArgs(" ", "report.html", "access.csv", ""); err == nil {
		t.Fatal("report accepted an empty snapshot path")
	}
	if _, err := accessGraphExtraArgs(" ", "graph.json"); err == nil {
		t.Fatal("graph accepted an empty snapshot path")
	}
	if _, err := accessMergeExtraArgs("one.json", "merged.json"); err == nil {
		t.Fatal("merge accepted fewer than two snapshots")
	}
	if _, err := accessMergeExtraArgs("one.json,two.json", " "); err == nil {
		t.Fatal("merge accepted an empty output path")
	}
	if _, err := accessIdentityMapExtraArgs("scan.json", " "); err == nil {
		t.Fatal("identity map accepted an empty output path")
	}
	if _, err := accessReviewExtraArgs("scan.json", " ", "", "", "", ""); err == nil {
		t.Fatal("review accepted an empty identity map path")
	}
	if _, err := accessReportExtraArgs("scan.json", "", "", "warning"); err == nil {
		t.Fatal("report accepted an invalid fail-on severity")
	}
	if _, err := accessReviewExtraArgs("scan.json", "identities.yaml", "", "", "", "warning"); err == nil {
		t.Fatal("review accepted an invalid fail-on severity")
	}
	if _, err := accessOffboardingExtraArgs(" ", "scan.json", "review.json", "", "", ""); err == nil {
		t.Fatal("offboarding accepted an empty identity")
	}
	if _, err := accessOffboardingCheckExtraArgs("baseline.json", "before.json", "", "after.json", "after-review.json", "", "", ""); err == nil {
		t.Fatal("offboarding check accepted a missing ownership review")
	}
	if _, err := cloudUploadPlanExtraArgs("scan.json", " ", "plan.json", false); err == nil {
		t.Fatal("cloud upload plan accepted an empty workspace")
	}
	if _, err := cloudPushExtraArgs(" ", "prod", "", "", "", "", "", "", "", "", "", "2m", false, false, false); err == nil {
		t.Fatal("cloud push accepted an empty snapshot path")
	}
	if _, err := cloudPushExtraArgs("scan.json", "prod", "https://cloud.test", "org", "project", "", "token", "", "", "", "", "2m", false, false, false); err == nil {
		t.Fatal("cloud push accepted mixed profile and manual destination flags")
	}
	if _, err := cloudInspectExtraArgs(" "); err == nil {
		t.Fatal("cloud inspect accepted an empty plan path")
	}
	if _, err := cloudHistoryBuildExtraArgs(" ", "history.json"); err == nil {
		t.Fatal("cloud history build accepted empty inputs")
	}
	if _, err := cloudHistoryInspectExtraArgs(" "); err == nil {
		t.Fatal("cloud history inspect accepted an empty path")
	}
	if _, err := cloudOwnershipHistoryBuildExtraArgs("history.json", "", "out.json"); err == nil {
		t.Fatal("cloud ownership history accepted no reviews")
	}
	if _, err := cloudOwnershipHistoryInspectExtraArgs(" "); err == nil {
		t.Fatal("cloud ownership history inspect accepted an empty path")
	}
	cloudDashboardCSVOnly, err := cloudDashboardExtraArgs(" history.json ", " ", " ", " ", " ", " access-review.csv ", cloudDashboardGateValues{})
	if err != nil || !reflect.DeepEqual(cloudDashboardCSVOnly, []string{"dashboard", "history.json", "--csv", "access-review.csv"}) {
		t.Fatalf("cloud dashboard CSV-only args=%q err=%v", cloudDashboardCSVOnly, err)
	}
	if _, err := cloudDashboardExtraArgs("history.json", "", "", "", " ", " ", cloudDashboardGateValues{}); err == nil {
		t.Fatal("cloud dashboard accepted an empty output path")
	}
	if _, err := cloudDashboardExtraArgs("history.json", "", "", "", "dashboard.html", "", cloudDashboardGateValues{FailOn: "warning"}); err == nil {
		t.Fatal("cloud dashboard accepted an invalid fail-on severity")
	}
	if _, err := cloudOffboardingHistoryBuildExtraArgs("history.json", "", "out.json"); err == nil {
		t.Fatal("cloud offboarding history accepted no checks")
	}
	if _, err := cloudBundleBuildExtraArgs("", "", "", "", "bundle.json"); err == nil {
		t.Fatal("cloud bundle accepted no workspace history")
	}
	if _, err := cloudBundleBuildExtraArgs("history.json", "", "", "", ""); err == nil {
		t.Fatal("cloud bundle accepted no output path")
	}
	if _, err := cloudBundleInspectExtraArgs(" "); err == nil {
		t.Fatal("cloud bundle inspect accepted an empty path")
	}
	if _, err := cloudLoginExtraArgs("prod", "https://cloud.example.test", "", "", "client-a", "token", "", "30s", false, false); err == nil {
		t.Fatal("cloud login accepted an unconfirmed network action")
	}
	if _, err := cloudLoginExtraArgs("prod", "https://cloud.example.test", "systeam", "fleet", "client-a", "token", "", "30s", false, true); err == nil {
		t.Fatal("cloud login accepted both a workspace and organization/project")
	}
	if _, err := cloudLoginExtraArgs("prod", "https://cloud.example.test", "systeam", "", "", "token", "", "30s", false, true); err == nil {
		t.Fatal("cloud login accepted an organization without a project")
	}
	if _, err := cloudStatusExtraArgs("prod", "30s", false, false); err == nil {
		t.Fatal("cloud status accepted an unconfirmed network action")
	}
	if _, err := cloudWorkspaceSetArgs("prod", " "); err == nil {
		t.Fatal("cloud workspace set accepted an empty workspace")
	}
	if _, err := cloudProjectSetArgs("prod", "systeam", " "); err == nil {
		t.Fatal("cloud project set accepted an empty project")
	}
	if _, err := cloudProjectSetArgs("prod", " ", "fleet"); err == nil {
		t.Fatal("cloud project set accepted an empty organization")
	}
	if _, err := cloudUploadExtraArgs("bundle.json", "", "https://cloud.example.test", "", "", "cloud-token", "", "2m", false, false); err == nil {
		t.Fatal("cloud upload accepted an unconfirmed network action")
	}
	if _, err := cloudUploadExtraArgs("bundle.json", "", "https://cloud.example.test", "", "", "cloud-token", "", "forever", false, true); err == nil {
		t.Fatal("cloud upload accepted an invalid timeout")
	}
	if _, err := cloudUploadExtraArgs("bundle.json", "", "https://cloud.example.test", "", "", "cloud-token", "CLOUD_TOKEN", "2m", false, true); err == nil {
		t.Fatal("cloud upload accepted two token sources")
	}
	if _, err := cloudUploadExtraArgs("bundle.json", "prod", "https://cloud.example.test", "", "", "cloud-token", "", "2m", false, true); err == nil {
		t.Fatal("cloud upload accepted profile and manual connection together")
	}
	if _, err := cloudUploadExtraArgs("bundle.json", "", "https://cloud.example.test", "systeam", "", "cloud-token", "", "2m", false, true); err == nil {
		t.Fatal("cloud upload accepted an organization without a project")
	}
	if _, err := cloudUploadExtraArgs("bundle.json", "prod", "", "systeam", "fleet", "", "", "2m", false, true); err == nil {
		t.Fatal("cloud upload accepted organization/project for a profile upload")
	}
}

func TestDefaultAccessSnapshotPathIsModeSpecificJSON(t *testing.T) {
	current := defaultAccessSnapshotPath(accessScanCurrent)
	system := defaultAccessSnapshotPath(accessPreflightSystem)
	systemScan := defaultAccessSnapshotPath(accessScanSystem)
	if !strings.HasPrefix(current, "sshmgr-access-") || !strings.HasSuffix(current, ".json") {
		t.Fatalf("unexpected current path %q", current)
	}
	if !strings.HasPrefix(system, "sshmgr-access-system-preflight-") || !strings.HasSuffix(system, ".json") {
		t.Fatalf("unexpected system path %q", system)
	}
	if !strings.HasPrefix(systemScan, "sshmgr-access-system-") || !strings.HasSuffix(systemScan, ".json") {
		t.Fatalf("unexpected system scan path %q", systemScan)
	}
}

func TestAccessMenuAndCloudHistoryFormsRenderOnSmallTerminal(t *testing.T) {
	theme.Set("default")
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	screen.SetSize(80, 24)

	state := newTestState(t, map[string]config.HostConfig{})
	state.app = tview.NewApplication().SetScreen(screen)
	state.pages = tview.NewPages()
	assertScreenContains := func(wants ...string) {
		t.Helper()
		state.app.SetRoot(state.pages, true).ForceDraw()
		cells, width, _ := screen.GetContents()
		var rendered strings.Builder
		for index, cell := range cells {
			if index > 0 && index%width == 0 {
				rendered.WriteByte('\n')
			}
			if len(cell.Runes) == 0 {
				rendered.WriteByte(' ')
			} else {
				rendered.WriteRune(cell.Runes[0])
			}
		}
		for _, want := range wants {
			if !strings.Contains(rendered.String(), want) {
				t.Fatalf("rendered TUI missing %q:\n%s", want, rendered.String())
			}
		}
	}

	state.openAccessMenu()
	assertScreenContains("Audit current scope", "Review latest audit", "Publish evidence", "Invite an identity", "Review pending requests", "Approve a request", "Reconcile access", "Revoke desired access", "Advanced tools")
	state.pages.RemovePage("accessmenu")
	state.openAdvancedAccessMenu()
	assertScreenContains("build offboarding report", "check offboarding outcome", "push snapshot to Cloud", "build Cloud workspace history", "inspect Cloud workspace history", "build Cloud ownership history", "inspect Cloud ownership history", "build Cloud offboarding history", "inspect Cloud offboarding history", "build Cloud ingestion bundle", "inspect Cloud ingestion bundle", "manage Cloud profiles", "upload Cloud ingestion bundle", "render Cloud workspace dashboard")
	state.pages.RemovePage("accessmenu")
	state.openAccessScanForm("host web", []string{"--host", "web"}, accessScanCurrent)
	assertScreenContains("snapshot JSON", "require full coverage", "fail on findings", "preview targets only")
	state.pages.RemovePage("accessscan")
	state.openAccessScanForm("group prod", []string{"--group", "prod"}, accessScanCurrent)
	assertScreenContains("groups (comma-separated union)", "prod", "exclude hosts", "preview targets only")
	state.pages.RemovePage("accessscan")
	state.openAccessReportForm()
	assertScreenContains("snapshot JSON", "fail on findings", "Run")
	state.pages.RemovePage("accessreport")
	state.openAccessReviewForm()
	assertScreenContains("identity map YAML", "fail on findings", "Run")
	state.pages.RemovePage("accessreview")
	state.openCloudPushForm()
	assertScreenContains("manual API endpoint", "organization slug", "project slug", "ownership review JSON", "ownership history JSON", "offboarding history JSON", "include unverified identity hints")
	state.pages.RemovePage("cloudpush")
	state.openCloudHistoryBuildForm()
	assertScreenContains("upload plan JSON files", "workspace history JSON", "Build local history")
	state.pages.RemovePage("cloudhistorybuild")
	state.openCloudHistoryInspectForm()
	assertScreenContains("workspace history JSON", "Inspect local history")
	state.pages.RemovePage("cloudhistoryinspect")
	state.openCloudOwnershipHistoryBuildForm()
	assertScreenContains("workspace history JSON", "ownership review JSON files", "ownership history JSON", "Build ownership history")
	state.pages.RemovePage("cloudownershiphistorybuild")
	state.openCloudOwnershipHistoryInspectForm()
	assertScreenContains("ownership history JSON", "Inspect ownership history")
	state.pages.RemovePage("cloudownershiphistoryinspect")
	state.openCloudDashboardForm()
	assertScreenContains("workspace history JSON", "ownership review JSON", "ownership history JSON", "dashboard HTML", "access review CSV", "fail on findings")
	state.pages.RemovePage("clouddashboard")
	state.openCloudOffboardingHistoryBuildForm()
	assertScreenContains("workspace history JSON", "offboarding check JSON files", "offboarding history JSON", "Build offboarding history")
	state.pages.RemovePage("cloudoffboardinghistorybuild")
	state.openCloudOffboardingHistoryInspectForm()
	assertScreenContains("offboarding history JSON", "Inspect offboarding history")
	state.pages.RemovePage("cloudoffboardinghistoryinspect")
	state.openCloudBundleBuildForm()
	assertScreenContains("workspace history JSON", "ownership review JSON", "ownership history JSON", "offboarding history JSON", "ingestion bundle JSON", "Build ingestion bundle")
	state.pages.RemovePage("cloudbundlebuild")
	state.openCloudBundleInspectForm()
	assertScreenContains("ingestion bundle JSON", "Inspect ingestion bundle")
	state.pages.RemovePage("cloudbundleinspect")
	state.openCloudProfileMenu()
	assertScreenContains("login / configure profile", "remote service status", "show profile/workspace", "list profiles", "use profile", "set workspace")
	state.pages.RemovePage("cloudprofiles")
	state.openCloudLoginForm()
	assertScreenContains("profile name", "Cloud API endpoint", "workspace slug", "existing token keyring entry", "confirm authenticated network login")
	state.pages.RemovePage("cloudlogin")
	state.openCloudStatusForm()
	assertScreenContains("profile (empty = active)", "request timeout", "confirm authenticated status request")
	state.pages.RemovePage("cloudstatus")
	state.openCloudWorkspaceSetForm()
	assertScreenContains("profile (empty = active)", "workspace slug", "Set workspace")
	state.pages.RemovePage("cloudworkspaceset")
	state.openCloudUploadForm()
	assertScreenContains("ingestion bundle JSON", "profile (empty = active/manual)", "manual API endpoint", "token keyring entry", "token env name", "confirm explicit network upload", "Upload validated bundle")
	state.pages.RemovePage("cloudupload")
	state.openAccessOffboardingForm()
	assertScreenContains("identity ID", "ownership review JSON", "offboarding HTML", "Build read-only report")
	state.pages.RemovePage("accessoffboarding")
	state.openAccessOffboardingCheckForm()
	assertScreenContains("baseline report JSON", "after ownership review", "check HTML", "Compare read-only evidence")
}
