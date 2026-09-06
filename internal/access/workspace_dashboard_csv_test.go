package access

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workspaceDashboardFullAuditFixture(t *testing.T) (*WorkspaceHistory, *OwnershipReview, *WorkspaceOwnershipHistory, *WorkspaceOffboardingHistory) {
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
	ownershipHistory, err := BuildWorkspaceOwnershipHistory(history, afterReview, beforeReview)
	if err != nil {
		t.Fatal(err)
	}
	offboardingHistory, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	return history, afterReview, ownershipHistory, offboardingHistory
}

func TestWorkspaceDashboardCSVExportsFullAuditEvidenceDeterministically(t *testing.T) {
	history, ownership, ownershipHistory, offboardingHistory := workspaceDashboardFullAuditFixture(t)
	first, err := RenderWorkspaceDashboardCSVWithAuditEvidence(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderWorkspaceDashboardCSVWithAuditEvidence(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical audit evidence produced different workspace CSV")
	}
	reader := csv.NewReader(bytes.NewReader(first))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) < 8 || strings.Join(records[0], ",") != strings.Join(workspaceDashboardCSVHeader, ",") {
		t.Fatalf("workspace CSV header/rows = %d / %v", len(records), records[0])
	}
	types := make(map[string]int)
	for _, record := range records[1:] {
		if len(record) != len(workspaceDashboardCSVHeader) {
			t.Fatalf("row %q columns=%d", record[0], len(record))
		}
		types[record[0]]++
	}
	for _, rowType := range []string{
		"workspace_summary", "host_coverage", "ownership_finding", "ownership_review_coverage", "ownership_review",
		"ownership_history_finding", "offboarding_outcome", "offboarding_evidence",
	} {
		if types[rowType] == 0 {
			t.Fatalf("workspace CSV missing %q row: %v", rowType, types)
		}
	}
	text := string(first)
	for _, want := range []string{"former@example.com", "offboarded_identity_access", "mapped_access_not_observed", testFingerprintA} {
		if !strings.Contains(text, want) {
			t.Fatalf("workspace CSV missing %q", want)
		}
	}
	if strings.Contains(text, "ssh-ed25519 AAAA") || strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("workspace CSV contains raw key material")
	}
}

func TestWorkspaceDashboardCSVProtectsFormulaCellsAndUsesPrivateMode(t *testing.T) {
	plan := workspacePlanFixture(t, "scan_formula", "2026-08-12T12:00:01Z", testFingerprintA)
	plan.Snapshot.Hosts[0].Alias = "=cmd|' /C calc'!A0"
	plan.Snapshot.Finalize(testTime)
	var err error
	plan, err = BuildUploadPlan(&plan.Snapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "access-review.csv")
	if err := WriteWorkspaceDashboardCSVWithAuditEvidence(path, history, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("CSV mode info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("'=cmd")) {
		t.Fatalf("formula-like host was not protected:\n%s", data)
	}
	if !bytes.Contains(data, []byte("access_edge")) {
		t.Fatalf("current access edge is missing:\n%s", data)
	}
	if err := WriteWorkspaceDashboardCSVWithAuditEvidence(" ", history, nil, nil, nil); err == nil {
		t.Fatal("empty CSV path was accepted")
	}
}

func TestWorkspaceDashboardCSVUsesSameStrictAuditJoinsAsHTML(t *testing.T) {
	history, _, ownershipHistory, offboardingHistory := workspaceDashboardFullAuditFixture(t)
	otherMap := &IdentityMap{SchemaVersion: IdentityMapSchemaVersion, Identities: []Identity{}, Keys: []IdentityKeyOwnership{}}
	otherReview, err := BuildOwnershipReview(&history.Plans[len(history.Plans)-1].Snapshot, otherMap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderWorkspaceDashboardCSVWithAuditEvidence(history, otherReview, ownershipHistory, offboardingHistory); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("CSV accepted mismatched audit evidence: %v", err)
	}
}

func TestWorkspaceDashboardCSVExposesMissingOwnershipReviewCoverage(t *testing.T) {
	history, before, _ := workspaceOwnershipFixture(t)
	ownershipHistory, err := BuildWorkspaceOwnershipHistory(history, before)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardCSVWithAuditEvidence(history, nil, ownershipHistory, nil)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	foundMissing := false
	for _, record := range records[1:] {
		if record[0] == "ownership_review_coverage" && record[3] == history.LatestScanID && record[8] == "missing" && record[5] == "true" {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatalf("latest missing ownership review is absent from CSV:\n%s", data)
	}
}
