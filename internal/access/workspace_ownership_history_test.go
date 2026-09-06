package access

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workspaceOwnershipFixture(t *testing.T) (*WorkspaceHistory, *OwnershipReview, *OwnershipReview) {
	t.Helper()
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", testFingerprintA)
	two := workspacePlanFixture(t, "scan_two", "2026-08-12T12:00:01Z", testFingerprintB)
	history, err := BuildWorkspaceHistory(two, one)
	if err != nil {
		t.Fatal(err)
	}
	beforeMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities:    []Identity{{ID: "alice@example.com", DisplayName: "Alice", Kind: IdentityKindHuman, Status: IdentityStatusActive}},
		Keys: []IdentityKeyOwnership{{Fingerprint: testFingerprintA, Claims: []OwnershipClaim{{
			IdentityID: "alice@example.com", Status: ClaimStatusClaimed, Source: "manual", RecordedAt: "2026-08-11T13:00:00Z",
		}}}},
	}
	afterMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities:    []Identity{{ID: "alice@example.com", DisplayName: "Alice", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded}},
		Keys: []IdentityKeyOwnership{{Fingerprint: testFingerprintB, Claims: []OwnershipClaim{{
			IdentityID: "alice@example.com", Status: ClaimStatusVerified, Source: "manual",
			RecordedAt: "2026-08-11T13:00:00Z", VerifiedAt: "2026-08-12T13:00:00Z",
		}}}},
	}
	before, err := BuildOwnershipReview(&history.Plans[0].Snapshot, beforeMap)
	if err != nil {
		t.Fatal(err)
	}
	after, err := BuildOwnershipReview(&history.Plans[1].Snapshot, afterMap)
	if err != nil {
		t.Fatal(err)
	}
	return history, before, after
}

func TestBuildWorkspaceOwnershipHistoryNormalizesRetriesAndDerivesTransitions(t *testing.T) {
	history, before, after := workspaceOwnershipFixture(t)
	result, err := BuildWorkspaceOwnershipHistory(history, after, before, before)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Reviews) != 2 || result.Reviews[0].ScanID != "scan_one" || result.Latest.ScanID != "scan_two" || !result.Latest.Current {
		t.Fatalf("ownership review order/latest = %+v / %+v", result.Reviews, result.Latest)
	}
	if result.Summary != (WorkspaceOwnershipHistorySummary{Scans: 2, ReviewedScans: 2, CurrentReview: true}) {
		t.Fatalf("ownership history summary = %+v", result.Summary)
	}
	if len(result.Transitions) != 1 || len(result.Transitions[0].IdentityChanges) != 1 || len(result.Transitions[0].ClaimChanges) != 2 || len(result.Transitions[0].KeyChanges) != 2 {
		t.Fatalf("ownership transition = %+v", result.Transitions)
	}
	transition := result.Transitions[0]
	if transition.IdentityChanges[0].Action != WorkspaceOwnershipChangeChanged || transition.IdentityChanges[0].Before.Status != IdentityStatusActive || transition.IdentityChanges[0].After.Status != IdentityStatusOffboarded {
		t.Fatalf("identity lifecycle transition = %+v", transition.IdentityChanges)
	}
	left, _ := RenderWorkspaceOwnershipHistoryJSON(result)
	reordered, err := BuildWorkspaceOwnershipHistory(history, before, after)
	if err != nil {
		t.Fatal(err)
	}
	right, _ := RenderWorkspaceOwnershipHistoryJSON(reordered)
	if !bytes.Equal(left, right) {
		t.Fatal("input order or exact retry changed workspace ownership history")
	}
}

func TestWorkspaceOwnershipHistoryStripsUnverifiedIdentityHints(t *testing.T) {
	history, before, _ := workspaceOwnershipFixture(t)
	before.Keys[0].IdentityHints = []string{"alice@laptop"}
	if err := ValidateOwnershipReview(before); err != nil {
		t.Fatal(err)
	}
	result, err := BuildWorkspaceOwnershipHistory(history, before)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Keys[0].IdentityHints) != 1 || before.Keys[0].IdentityHints[0] != "alice@laptop" {
		t.Fatal("privacy normalization mutated the standalone ownership review")
	}
	for _, key := range result.Reviews[0].Keys {
		if len(key.IdentityHints) != 0 {
			t.Fatalf("unverified hint crossed privacy boundary: %+v", key.IdentityHints)
		}
	}
	data, _ := RenderWorkspaceOwnershipHistoryJSON(result)
	if bytes.Contains(data, []byte("alice@laptop")) {
		t.Fatal("unverified hint remains in encoded ownership history")
	}
}

func TestWorkspaceOwnershipHistoryMarksLatestReviewStaleAndMissingScans(t *testing.T) {
	history, before, _ := workspaceOwnershipFixture(t)
	result, err := BuildWorkspaceOwnershipHistory(history, before)
	if err != nil {
		t.Fatal(err)
	}
	if result.Latest.Current || result.Summary.CurrentReview || result.Summary.MissingScans != 1 {
		t.Fatalf("stale review was presented as current: latest=%+v summary=%+v", result.Latest, result.Summary)
	}
	if !strings.Contains(RenderWorkspaceOwnershipHistoryText(result), "STALE") {
		t.Fatal("text output does not label stale ownership evidence")
	}
}

func TestWorkspaceOwnershipHistoryRejectsOutsideAndConflictingReviews(t *testing.T) {
	history, before, _ := workspaceOwnershipFixture(t)
	outsidePlan := workspacePlanFixture(t, "scan_outside", "2026-08-13T12:00:01Z", testFingerprintA)
	outsideMap := identityMapFromOwnershipReview(before)
	outside, err := BuildOwnershipReview(&outsidePlan.Snapshot, outsideMap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWorkspaceOwnershipHistory(history, outside); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("outside review accepted: %v", err)
	}
	alternativeMap := &IdentityMap{SchemaVersion: IdentityMapSchemaVersion, Identities: []Identity{}, Keys: []IdentityKeyOwnership{}}
	alternative, err := BuildOwnershipReview(&history.Plans[0].Snapshot, alternativeMap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWorkspaceOwnershipHistory(history, before, alternative); err == nil || !strings.Contains(err.Error(), "conflicting ownership reviews") {
		t.Fatalf("conflicting same-scan review accepted: %v", err)
	}
	left, right := *before, *before
	left.Keys = append([]ReviewedKey(nil), before.Keys...)
	right.Keys = append([]ReviewedKey(nil), before.Keys...)
	left.Keys[0].IdentityHints = []string{"alice@first-laptop"}
	right.Keys[0].IdentityHints = []string{"alice@second-laptop"}
	if err := ValidateOwnershipReview(&left); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnershipReview(&right); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildWorkspaceOwnershipHistory(history, &left, &right); err == nil || !strings.Contains(err.Error(), "conflicting ownership reviews") {
		t.Fatalf("different source-review digests were treated as one retry: %v", err)
	}
}

func TestWorkspaceOwnershipHistoryRejectsForbiddenMaterial(t *testing.T) {
	history, before, _ := workspaceOwnershipFixture(t)
	for _, test := range []struct{ name, value, want string }{
		{"raw key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISmuggled", "raw SSH public key"},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----", "forbidden key material"},
		{"credential", "access_token=supersecret", "credential-like"},
	} {
		t.Run(test.name, func(t *testing.T) {
			maliciousMap := identityMapFromOwnershipReview(before)
			maliciousMap.Identities[0].DisplayName = test.value
			malicious, err := BuildOwnershipReview(&history.Plans[0].Snapshot, maliciousMap)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BuildWorkspaceOwnershipHistory(history, malicious); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("forbidden material accepted: %v", err)
			}
		})
	}
}

func TestWorkspaceOwnershipHistoryStrictPrivateRoundTripAndTamperDetection(t *testing.T) {
	history, before, after := workspaceOwnershipFixture(t)
	result, err := BuildWorkspaceOwnershipHistory(history, before, after)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "ownership-history.json")
	if err := WriteWorkspaceOwnershipHistory(path, result); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private artifact info=%v err=%v", info, err)
	}
	if _, err := ReadWorkspaceOwnershipHistory(path); err != nil {
		t.Fatal(err)
	}
	data, _ := RenderWorkspaceOwnershipHistoryJSON(result)
	var tampered WorkspaceOwnershipHistory
	if err := json.Unmarshal(data, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Summary.MissingScans++
	if err := ValidateWorkspaceOwnershipHistory(&tampered); err == nil {
		t.Fatal("tampered summary was accepted")
	}
	unknown := bytes.Replace(data, []byte(`"schema_version": "1",`), []byte(`"schema_version": "1", "smuggled": true,`), 1)
	unknownPath := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceOwnershipHistory(unknownPath); err == nil {
		t.Fatal("strict reader accepted an unknown field")
	}
	trailingPath := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(trailingPath, append(data, []byte("{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceOwnershipHistory(trailingPath); err == nil {
		t.Fatal("strict reader accepted trailing JSON")
	}
	oversizedPath := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.Create(oversizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxWorkspaceOwnershipHistoryBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceOwnershipHistory(oversizedPath); err == nil {
		t.Fatal("strict reader accepted oversized artifact")
	}
}

func TestWorkspaceOwnershipHistoryV1GoldenFixture(t *testing.T) {
	path := filepath.Join("testdata", "workspace-ownership-history-v1.json")
	history, err := ReadWorkspaceOwnershipHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if history.Workspace != "client-a" || len(history.Reviews) != 2 || len(history.Transitions) != 1 || !history.Latest.Current {
		t.Fatalf("golden workspace ownership history contract mismatch: %+v", history)
	}
	rendered, err := RenderWorkspaceOwnershipHistoryJSON(history)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, want) {
		t.Fatal("golden workspace-ownership-history encoding changed")
	}
}
