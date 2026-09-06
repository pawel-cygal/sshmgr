package access

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func workspaceOffboardingFixture(t *testing.T) (*WorkspaceHistory, *OffboardingCheck) {
	t.Helper()
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	beforePlan, err := BuildUploadPlan(before, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	afterPlan, err := BuildUploadPlan(after, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(afterPlan, beforePlan)
	if err != nil {
		t.Fatal(err)
	}
	return history, check
}

func TestBuildWorkspaceOffboardingHistorySortsDeduplicatesAndDerivesCurrent(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	result, err := BuildWorkspaceOffboardingHistory(history, check, check)
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkspaceHistoryID != history.HistoryID || result.LatestScanID != history.LatestScanID || len(result.Checks) != 1 || len(result.Latest) != 1 {
		t.Fatalf("offboarding history binding = %+v", result)
	}
	latest := result.Latest[0]
	if !latest.Current || latest.Outcome != OffboardingOutcomeComplete || latest.AfterScanID != history.LatestScanID || latest.AfterCompletedAt == "" {
		t.Fatalf("latest status = %+v", latest)
	}
	if result.Summary != (WorkspaceOffboardingHistorySummary{Identities: 1, Checks: 1, CurrentComplete: 1}) {
		t.Fatalf("summary = %+v", result.Summary)
	}
	first, err := RenderWorkspaceOffboardingHistoryJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := RenderWorkspaceOffboardingHistoryJSON(repeated)
	if !bytes.Equal(first, second) {
		t.Fatal("exact retry changed deterministic offboarding history")
	}
}

func TestWorkspaceOffboardingHistoryMarksLatestIdentityStatusStale(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	thirdSnapshot, err := cloneSnapshot(&history.Plans[len(history.Plans)-1].Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	thirdSnapshot.ScanID = "scan_third"
	thirdSnapshot.Finalize(testTime.Add(48 * time.Hour))
	thirdPlan, err := BuildUploadPlan(thirdSnapshot, history.Workspace, false)
	if err != nil {
		t.Fatal(err)
	}
	plans := []*UploadPlan{&history.Plans[0], &history.Plans[1], thirdPlan}
	history, err = BuildWorkspaceHistory(plans...)
	if err != nil {
		t.Fatal(err)
	}
	result, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	if result.Latest[0].Current || result.Summary.Stale != 1 || result.Summary.CurrentComplete != 0 {
		t.Fatalf("stale status was presented as current: latest=%+v summary=%+v", result.Latest[0], result.Summary)
	}
	if !strings.Contains(RenderWorkspaceOffboardingHistoryText(result), "STALE") {
		t.Fatal("text output does not label stale status")
	}
}

func TestWorkspaceOffboardingHistoryNormalizesMultipleIdentityInputOrder(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	other := *check
	other.Identity.ID = "another@example.com"
	var err error
	other.CheckID, err = offboardingCheckID(&other)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOffboardingCheck(&other); err != nil {
		t.Fatalf("second identity fixture is not standalone-valid: %v", err)
	}
	left, err := BuildWorkspaceOffboardingHistory(history, check, &other)
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildWorkspaceOffboardingHistory(history, &other, check)
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, _ := RenderWorkspaceOffboardingHistoryJSON(left)
	rightJSON, _ := RenderWorkspaceOffboardingHistoryJSON(right)
	if !bytes.Equal(leftJSON, rightJSON) || left.Latest[0].Identity.ID != "another@example.com" || left.Summary.CurrentComplete != 2 {
		t.Fatalf("input order changed canonical output: latest=%+v summary=%+v", left.Latest, left.Summary)
	}
}

func TestWorkspaceOffboardingHistoryRejectsMissingScanAndWrongWorkspace(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	onePlanHistory, err := BuildWorkspaceHistory(&history.Plans[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWorkspaceOffboardingHistory(onePlanHistory, check); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("missing baseline scan accepted: %v", err)
	}
	result, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuilding is the simplest way to obtain another fully valid workspace.
	otherPlans := make([]*UploadPlan, 0, len(history.Plans))
	for index := range history.Plans {
		plan, buildErr := BuildUploadPlan(&history.Plans[index].Snapshot, "client-b", false)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		otherPlans = append(otherPlans, plan)
	}
	otherHistory, err := BuildWorkspaceHistory(otherPlans...)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkspaceOffboardingHistoryAgainstWorkspace(result, otherHistory); err == nil {
		t.Fatal("offboarding history was attached to another workspace")
	}
}

func TestWorkspaceOffboardingHistoryRejectsAmbiguousIdentityAfterScan(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	conflict := *check
	conflict.BaselineReportID = "offboarding_another_valid_baseline"
	var err error
	conflict.CheckID, err = offboardingCheckID(&conflict)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOffboardingCheck(&conflict); err != nil {
		t.Fatalf("conflict fixture is not standalone-valid: %v", err)
	}
	if _, err := BuildWorkspaceOffboardingHistory(history, check, &conflict); err == nil || !strings.Contains(err.Error(), "ambiguous checks") {
		t.Fatalf("ambiguous identity/after-scan checks accepted: %v", err)
	}
}

func TestWorkspaceOffboardingHistoryRejectsKeyAndCredentialMaterialSmuggledThroughText(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	tests := []struct {
		name, value, want string
	}{
		{"raw public key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISmuggled", "raw SSH public key"},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----", "forbidden key material"},
		{"credential", "access_token=supersecret", "credential-like"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			malicious := *check
			malicious.Identity.DisplayName = test.value
			var err error
			malicious.CheckID, err = offboardingCheckID(&malicious)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateOffboardingCheck(&malicious); err != nil {
				t.Fatalf("privacy fixture is not standalone-valid: %v", err)
			}
			if _, err := BuildWorkspaceOffboardingHistory(history, &malicious); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("smuggled %s accepted: %v", test.name, err)
			}
		})
	}
}

func TestWorkspaceOffboardingHistoryStrictPrivateRoundTripAndTamperDetection(t *testing.T) {
	history, check := workspaceOffboardingFixture(t)
	result, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "offboarding-history.json")
	if err := WriteWorkspaceOffboardingHistory(path, result); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private artifact info=%v err=%v", info, err)
	}
	roundTripped, err := ReadWorkspaceOffboardingHistory(path)
	if err != nil || roundTripped.OffboardingHistoryID != result.OffboardingHistoryID {
		t.Fatalf("strict round trip err=%v history=%+v", err, roundTripped)
	}
	data, _ := RenderWorkspaceOffboardingHistoryJSON(result)
	var tampered WorkspaceOffboardingHistory
	if err := json.Unmarshal(data, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Summary.CurrentComplete++
	if err := ValidateWorkspaceOffboardingHistory(&tampered); err == nil {
		t.Fatal("tampered summary was accepted")
	}
	unknown := bytes.Replace(data, []byte(`"schema_version": "1",`), []byte(`"schema_version": "1", "smuggled": true,`), 1)
	unknownPath := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceOffboardingHistory(unknownPath); err == nil {
		t.Fatal("strict reader accepted an unknown field")
	}
	trailingPath := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(trailingPath, append(data, []byte("{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceOffboardingHistory(trailingPath); err == nil {
		t.Fatal("strict reader accepted trailing JSON")
	}
	oversizedPath := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.Create(oversizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxWorkspaceOffboardingHistoryBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceOffboardingHistory(oversizedPath); err == nil {
		t.Fatal("strict reader accepted an oversized artifact")
	}
}

func TestWorkspaceOffboardingHistoryV1GoldenFixture(t *testing.T) {
	path := filepath.Join("testdata", "workspace-offboarding-history-v1.json")
	history, err := ReadWorkspaceOffboardingHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if history.Workspace != "client-a" || len(history.Checks) != 1 || len(history.Latest) != 1 || !history.Latest[0].Current {
		t.Fatalf("golden workspace offboarding history contract mismatch: %+v", history)
	}
	rendered, err := RenderWorkspaceOffboardingHistoryJSON(history)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, want) {
		t.Fatal("golden workspace-offboarding-history encoding changed")
	}
}
