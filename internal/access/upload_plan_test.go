package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uploadPlanFixture(t *testing.T, includeHints bool) (*Snapshot, *UploadPlan) {
	t.Helper()
	snapshot := fixtureSnapshot()
	snapshot.Scope.IncludePublicKeys = true
	entry := &snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	entry.PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestFixtureOnly"
	plan, err := BuildUploadPlan(snapshot, "client-a", includeHints)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, plan
}

func TestBuildUploadPlanIsOfflinePrivateAndDoesNotMutateSnapshot(t *testing.T) {
	snapshot, plan := uploadPlanFixture(t, false)
	if snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].PublicKey == "" || !snapshot.Scope.IncludePublicKeys {
		t.Fatal("input snapshot was mutated")
	}
	entry := plan.Snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	if entry.PublicKey != "" || entry.Comment != "" || plan.Snapshot.Scope.IncludePublicKeys {
		t.Fatalf("candidate payload was not redacted: %+v", entry)
	}
	if plan.Preview.RawPublicKeys != 0 || plan.Preview.IdentityHints != 0 || plan.Privacy.PublicKeysIncluded || plan.Privacy.CredentialsIncluded {
		t.Fatalf("privacy contract = %+v / %+v", plan.Privacy, plan.Preview)
	}
	if !strings.HasPrefix(plan.IdempotencyKey, "upload_") || !strings.HasPrefix(plan.PlanID, "plan_") {
		t.Fatalf("stable IDs are missing: %+v", plan)
	}
}

func TestUploadPlanExplicitIdentityHintsAndDeterministicOutput(t *testing.T) {
	_, one := uploadPlanFixture(t, true)
	_, two := uploadPlanFixture(t, true)
	first, err := RenderUploadPlanJSON(one)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderUploadPlanJSON(two)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same snapshot/workspace produced a different upload plan")
	}
	if one.Preview.IdentityHints != 1 || !one.Privacy.IdentityHintsIncluded || !bytes.Contains(first, []byte(`\u003cadmin\u0026ops\u003e`)) {
		t.Fatalf("explicit hint contract not preserved: %+v", one)
	}
}

func TestUploadPlanRedactsIdentityHintsFromDerivedFindings(t *testing.T) {
	snapshot := fixtureSnapshot()
	source := &snapshot.Hosts[0].Accounts[0].Sources[0]
	source.Entries = append(source.Entries, KeyObservation{
		Line: 2, Fingerprint: source.Entries[0].Fingerprint, Algorithm: source.Entries[0].Algorithm, Comment: "second@hint",
	})
	snapshot.Finalize(testTime.Add(2))
	if !hasFindingRule(snapshot.Findings, "ambiguous_identity_hint") {
		t.Fatal("fixture did not create an identity-hint finding")
	}
	plan, err := BuildUploadPlan(snapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderUploadPlanJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("admin&ops")) || bytes.Contains(data, []byte("second@hint")) || hasFindingRule(plan.Snapshot.Findings, "ambiguous_identity_hint") {
		t.Fatalf("redacted hints survived through derived findings: %s", data)
	}
}

func TestUploadPlanRoundTripPrivateAndStrict(t *testing.T) {
	_, plan := uploadPlanFixture(t, false)
	path := filepath.Join(t.TempDir(), "private", "upload-plan.json")
	if err := WriteUploadPlan(path, plan); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("upload plan mode = %04o", info.Mode().Perm())
	}
	readBack, err := ReadUploadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	if readBack.PlanID != plan.PlanID || readBack.PayloadSHA256 != plan.PayloadSHA256 {
		t.Fatalf("round trip mismatch: %+v", readBack)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"schema_version": "1",`), []byte(`"schema_version": "1", "smuggled_secret": "no",`), 1)
	strictPath := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(strictPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUploadPlan(strictPath); err == nil {
		t.Fatal("strict upload-plan reader accepted an unknown field")
	}
}

func TestUploadPlanV1GoldenFixture(t *testing.T) {
	plan, err := ReadUploadPlan(filepath.Join("testdata", "upload-plan-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Workspace != "golden-workspace" || plan.ArtifactID != "scan_golden_v1" || plan.Preview.RawPublicKeys != 0 || plan.Preview.IdentityHints != 0 {
		t.Fatalf("golden upload-plan contract mismatch: %+v", plan)
	}
	rendered, err := RenderUploadPlanJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "upload-plan-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, want) {
		t.Fatal("golden upload-plan encoding changed")
	}
}

func TestValidateUploadPlanRejectsTampering(t *testing.T) {
	tests := map[string]func(*UploadPlan){
		"payload":     func(plan *UploadPlan) { plan.Snapshot.Hosts[0].Alias = "changed" },
		"preview":     func(plan *UploadPlan) { plan.Preview.Hosts++ },
		"workspace":   func(plan *UploadPlan) { plan.Workspace = "../escape" },
		"idempotency": func(plan *UploadPlan) { plan.IdempotencyKey = "upload_wrong" },
		"privacy":     func(plan *UploadPlan) { plan.Privacy.PublicKeysIncluded = true },
		"derived finding": func(plan *UploadPlan) {
			plan.Snapshot.Findings[0].Title = "tampered but structurally valid"
			resignUploadPlan(t, plan)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			_, plan := uploadPlanFixture(t, false)
			mutate(plan)
			if err := ValidateUploadPlan(plan); err == nil {
				t.Fatal("tampered upload plan accepted")
			}
		})
	}
}

func resignUploadPlan(t *testing.T, plan *UploadPlan) {
	t.Helper()
	payload, err := canonicalUploadPayload(&plan.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	plan.PayloadSHA256 = "SHA256:" + hex.EncodeToString(digest[:])
	plan.PayloadBytes = len(payload)
	plan.Preview = previewUploadFields(&plan.Snapshot)
	plan.IdempotencyKey = uploadIdempotencyKey(plan.Workspace, plan.ArtifactID)
	plan.PlanID = uploadPlanID(plan.Workspace, plan.ArtifactID, plan.PayloadSHA256)
}

func TestUploadPlanRejectsKeyMaterialSmuggledThroughText(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Errors = []ScanError{{Stage: "collector", Message: "-----BEGIN OPENSSH PRIVATE KEY-----"}}
	if _, err := BuildUploadPlan(snapshot, "client-a", false); err == nil || !strings.Contains(err.Error(), "forbidden key material") {
		t.Fatalf("private-key marker was not rejected: %v", err)
	}

	snapshot = fixtureSnapshot()
	snapshot.Hosts[0].Errors = []ScanError{{Stage: "collector", Message: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISmuggled"}}
	if _, err := BuildUploadPlan(snapshot, "client-a", false); err == nil || !strings.Contains(err.Error(), "raw SSH public key") {
		t.Fatalf("raw public key outside its field was not rejected: %v", err)
	}

	snapshot = fixtureSnapshot()
	snapshot.Hosts[0].Errors = []ScanError{{Stage: "collector", Message: "access_token=supersecret"}}
	if _, err := BuildUploadPlan(snapshot, "client-a", false); err == nil || !strings.Contains(err.Error(), "credential-like") {
		t.Fatalf("credential assignment was not rejected: %v", err)
	}
}

func TestUploadPlanRejectsRawPublicKeyFieldEvenWithConsistentTamperedEnvelope(t *testing.T) {
	_, plan := uploadPlanFixture(t, false)
	plan.Snapshot.Scope.IncludePublicKeys = false
	plan.Snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITampered"
	if err := ValidateUploadPlan(plan); err == nil {
		t.Fatal("upload plan accepted a raw public-key field")
	}
}

func TestUploadPlanDifferentWorkspaceGetsDifferentStableIDs(t *testing.T) {
	snapshot := fixtureSnapshot()
	one, err := BuildUploadPlan(snapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildUploadPlan(snapshot, "client-b", false)
	if err != nil {
		t.Fatal(err)
	}
	if one.PayloadSHA256 != two.PayloadSHA256 || one.IdempotencyKey == two.IdempotencyKey || one.PlanID == two.PlanID {
		t.Fatalf("workspace binding mismatch: one=%+v two=%+v", one, two)
	}
}

func TestUploadWorkspaceSlugValidation(t *testing.T) {
	for _, workspace := range []string{"", "Client-A", "-client", "client-", "../client", strings.Repeat("a", 65)} {
		if _, err := BuildUploadPlan(fixtureSnapshot(), workspace, false); err == nil {
			t.Errorf("invalid workspace %q accepted", workspace)
		}
	}
}

func hasFindingRule(findings []Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
