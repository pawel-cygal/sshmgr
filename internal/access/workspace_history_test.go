package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func workspacePlanFixture(t *testing.T, scanID, completedAt, fingerprint string) *UploadPlan {
	t.Helper()
	snapshot := fixtureSnapshot()
	snapshot.ScanID = scanID
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = fingerprint
	completed, err := time.Parse(time.RFC3339Nano, completedAt)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Finalize(completed)
	plan, err := BuildUploadPlan(snapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestBuildWorkspaceHistorySortsDeduplicatesAndCalculatesDiff(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	two := workspacePlanFixture(t, "scan_two", "2026-08-12T12:00:01Z", "SHA256:two")
	history, err := BuildWorkspaceHistory(two, one, one)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Plans) != 2 || history.Plans[0].ArtifactID != "scan_one" || history.LatestScanID != "scan_two" {
		t.Fatalf("history order/dedup mismatch: %+v", history)
	}
	if len(history.Transitions) != 1 || !history.Transitions[0].Comparable || len(history.Transitions[0].Added) != 1 || len(history.Transitions[0].Removed) != 1 {
		t.Fatalf("semantic transition mismatch: %+v", history.Transitions)
	}
	if history.Transitions[0].CoverageCaveat == "" {
		t.Fatal("partial-coverage transition lacks a caveat")
	}

	reversed, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := RenderWorkspaceHistoryJSON(history)
	second, _ := RenderWorkspaceHistoryJSON(reversed)
	if !bytes.Equal(first, second) {
		t.Fatal("input order or an exact retry changed deterministic history output")
	}
}

func TestWorkspaceHistoryDoesNotDiffDifferentHostScopes(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	twoSnapshot := fixtureSnapshot()
	twoSnapshot.ScanID = "scan_two"
	twoSnapshot.Hosts[0].Alias = "another-host"
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if transition.Comparable || !strings.Contains(transition.Reason, "host sets differ") || len(transition.Added) != 0 || len(transition.Removed) != 0 {
		t.Fatalf("different scope produced a false access diff: %+v", transition)
	}
}

func TestWorkspaceHistoryExcludesFailedHostsFromAccessDiff(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	twoSnapshot := fixtureSnapshot()
	twoSnapshot.ScanID = "scan_two"
	twoSnapshot.Hosts[0].Coverage = CoverageFailed
	twoSnapshot.Hosts[0].Accounts = nil
	twoSnapshot.Hosts[0].Errors = []ScanError{{Stage: "connect", Message: "connection failed"}}
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if !transition.Comparable || len(transition.Removed) != 0 || len(transition.ExcludedHosts) != 1 || transition.ExcludedHosts[0] != "web-01" {
		t.Fatalf("failed host produced a false removal: %+v", transition)
	}
}

func TestWorkspaceHistoryExcludesIncompleteCollectionFromAccessDiff(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	twoSnapshot := fixtureSnapshot()
	twoSnapshot.ScanID = "scan_two"
	source := &twoSnapshot.Hosts[0].Accounts[0].Sources[0]
	source.ContentInspected = false
	source.Entries = nil
	source.Error = "read budget exhausted"
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if !transition.Comparable || len(transition.Removed) != 0 || len(transition.ExcludedHosts) != 1 || transition.CoverageCaveat == "" {
		t.Fatalf("incomplete collection produced a false removal: %+v", transition)
	}
	path := filepath.Join(t.TempDir(), "incomplete-history.json")
	if err := WriteWorkspaceHistory(path, history); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceHistory(path); err != nil {
		t.Fatalf("incomplete zero-diff history failed strict round trip: %v", err)
	}
}

func TestWorkspaceHistoryExcludesMissingRequestedAccountsFromAccessDiff(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	twoSnapshot := fixtureSnapshot()
	twoSnapshot.ScanID = "scan_two"
	twoSnapshot.Hosts[0].System = &SystemSnapshot{MissingAccounts: []string{"deploy"}}
	twoSnapshot.Hosts[0].Accounts = nil
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if !transition.Comparable || len(transition.Removed) != 0 || len(transition.ExcludedHosts) != 1 {
		t.Fatalf("missing requested account produced a false removal: %+v", transition)
	}
}

func TestWorkspaceHistoryAllowsStableMissingAccountsAndNonexistentSources(t *testing.T) {
	build := func(scanID, fingerprint string, completed time.Time) *UploadPlan {
		snapshot := fixtureSnapshot()
		snapshot.ScanID = scanID
		snapshot.Scope.Mode = "system"
		snapshot.Scope.AccountMode = AccountModeExplicit
		snapshot.Scope.RequestedAccounts = []string{"deploy", "ghost"}
		snapshot.Scope.MaxAccounts = 2
		snapshot.Hosts[0].System = &SystemSnapshot{
			MissingAccounts:    []string{"ghost"},
			SourcesRequested:   2,
			SourcesInspected:   1,
			AccountsEnumerated: true,
		}
		snapshot.Hosts[0].Accounts[0].Sources = append(snapshot.Hosts[0].Accounts[0].Sources, KeySource{
			Type: "authorized_keys_file", Path: ".ssh/authorized_keys2",
		})
		snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = fingerprint
		snapshot.Finalize(completed)
		plan, err := BuildUploadPlan(snapshot, "client-a", false)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	one := build("scan_one", "SHA256:one", testTime.Add(time.Second))
	two := build("scan_two", "SHA256:two", testTime.Add(24*time.Hour+time.Second))
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if !transition.Comparable || len(transition.ExcludedHosts) != 0 || len(transition.Added) != 1 || len(transition.Removed) != 1 {
		t.Fatalf("stable missing metadata incorrectly blocked a valid diff: %+v", transition)
	}
}

func TestWorkspaceHistoryExcludesMalformedKeyEvidenceFromAccessDiff(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	twoSnapshot := fixtureSnapshot()
	twoSnapshot.ScanID = "scan_two"
	entry := &twoSnapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	entry.Fingerprint, entry.Algorithm, entry.Comment = "", "", ""
	entry.ParseError = "malformed authorized_keys entry"
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if !transition.Comparable || len(transition.Removed) != 0 || len(transition.ExcludedHosts) != 1 {
		t.Fatalf("malformed evidence produced a false removal: %+v", transition)
	}
}

func TestWorkspaceHistoryDoesNotPresentPreflightAsAccessDiff(t *testing.T) {
	oneSnapshot := fixtureSnapshot()
	oneSnapshot.ScanID = "scan_one"
	oneSnapshot.Scope.Preflight = true
	oneSnapshot.Hosts[0].Accounts[0].Sources[0].ContentInspected = false
	oneSnapshot.Hosts[0].Accounts[0].Sources[0].Entries = nil
	oneSnapshot.Finalize(testTime.Add(time.Second))
	twoSnapshot, err := cloneSnapshot(oneSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	twoSnapshot.ScanID = "scan_two"
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	one, err := BuildUploadPlan(oneSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if transition.Comparable || !strings.Contains(transition.Reason, "preflight snapshots") {
		t.Fatalf("preflight was presented as an access diff: %+v", transition)
	}
}

func TestWorkspaceHistoryDoesNotCompareDifferentCurrentSSHAccounts(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	twoSnapshot := fixtureSnapshot()
	twoSnapshot.ScanID = "scan_two"
	twoSnapshot.Hosts[0].Accounts[0].Username = "root"
	twoSnapshot.Finalize(testTime.Add(24*time.Hour + time.Second))
	two, err := BuildUploadPlan(twoSnapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	transition := history.Transitions[0]
	if transition.Comparable || !strings.Contains(transition.Reason, "SSH users differ") {
		t.Fatalf("different current SSH accounts were compared: %+v", transition)
	}
}

func TestWorkspaceHistoryRejectsWorkspaceAndScanIDConflicts(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	differentWorkspace, err := BuildUploadPlan(&one.Snapshot, "client-b", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWorkspaceHistory(one, differentWorkspace); err == nil {
		t.Fatal("mixed workspaces were accepted")
	}

	conflict := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:different")
	if _, err := BuildWorkspaceHistory(one, conflict); err == nil || !strings.Contains(err.Error(), "different payload") {
		t.Fatalf("conflicting scan_id was accepted: %v", err)
	}

	privacyConflict, err := BuildUploadPlan(&one.Snapshot, "client-a", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWorkspaceHistory(one, privacyConflict); err == nil || !strings.Contains(err.Error(), "privacy envelope") {
		t.Fatalf("conflicting privacy envelope was accepted: %v", err)
	}
	standardHistory, err := BuildWorkspaceHistory(one)
	if err != nil {
		t.Fatal(err)
	}
	optInHistory, err := BuildWorkspaceHistory(privacyConflict)
	if err != nil {
		t.Fatal(err)
	}
	if standardHistory.HistoryID == optInHistory.HistoryID {
		t.Fatal("history ID does not bind the privacy envelope")
	}
}

func TestWorkspaceHistoryRoundTripPrivateStrictAndTamperResistant(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	two := workspacePlanFixture(t, "scan_two", "2026-08-12T12:00:01Z", "SHA256:two")
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "history.json")
	if err := WriteWorkspaceHistory(path, history); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("history mode = %04o", info.Mode().Perm())
	}
	if _, err := ReadWorkspaceHistory(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(data, []byte(`"schema_version": "1",`), []byte(`"schema_version": "1", "smuggled": true,`), 1)
	unknownPath := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceHistory(unknownPath); err == nil {
		t.Fatal("strict history reader accepted an unknown field")
	}

	history.Transitions[0].Added[0].Account = "tampered"
	if err := ValidateWorkspaceHistory(history); err == nil {
		t.Fatal("tampered derived transition was accepted")
	}
}

func TestWorkspaceHistoryRejectsTamperedEmbeddedPlanEvenWhenResigned(t *testing.T) {
	plan := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	history, err := BuildWorkspaceHistory(plan)
	if err != nil {
		t.Fatal(err)
	}
	embedded := &history.Plans[0]
	embedded.Snapshot.Findings[0].Title = "tampered but structurally valid"
	payload, err := canonicalUploadPayload(&embedded.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	embedded.PayloadSHA256 = "SHA256:" + hex.EncodeToString(digest[:])
	embedded.PayloadBytes = len(payload)
	embedded.Preview = previewUploadFields(&embedded.Snapshot)
	embedded.PlanID = uploadPlanID(embedded.Workspace, embedded.ArtifactID, embedded.PayloadSHA256)
	if err := ValidateWorkspaceHistory(history); err == nil {
		t.Fatal("history accepted a resigned upload plan with stale findings")
	}
}

func TestWorkspaceHistoryV1GoldenFixture(t *testing.T) {
	path := filepath.Join("testdata", "workspace-history-v1.json")
	history, err := ReadWorkspaceHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if history.Workspace != "golden-workspace" || history.LatestScanID != "scan_golden_v1" || len(history.Plans) != 1 {
		t.Fatalf("golden workspace history contract mismatch: %+v", history)
	}
	rendered, err := RenderWorkspaceHistoryJSON(history)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, want) {
		t.Fatal("golden workspace-history encoding changed")
	}
}
