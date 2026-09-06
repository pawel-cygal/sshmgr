package access

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workspaceBundleFixture(t *testing.T) (*WorkspaceHistory, *OwnershipReview, *WorkspaceOwnershipHistory, *WorkspaceOffboardingHistory) {
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

func TestWorkspaceBundleBuildIsDeterministicPrivateAndStrictlyJoined(t *testing.T) {
	history, ownership, ownershipHistory, offboardingHistory := workspaceBundleFixture(t)
	bundle, err := BuildWorkspaceBundle(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := BuildWorkspaceBundle(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	first, err := RenderWorkspaceBundleJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderWorkspaceBundleJSON(repeated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical workspace evidence produced a different ingestion bundle")
	}
	if bundle.BundleID == "" || bundle.IdempotencyKey == "" || bundle.PayloadSHA256 == "" || bundle.PayloadBytes == 0 {
		t.Fatalf("transport envelope is incomplete: %+v", bundle)
	}
	if bundle.Preview.Snapshots != 2 || !bundle.Preview.OwnershipReviewAttached || bundle.Preview.OwnershipReviews != 2 || bundle.Preview.OffboardingChecks != 1 || bundle.Preview.TrackedOffboardingIdentities != 1 {
		t.Fatalf("bundle preview = %+v", bundle.Preview)
	}
	if bundle.Privacy.PublicKeysIncluded || bundle.Privacy.CredentialsIncluded || bundle.Preview.RawPublicKeys != 0 {
		t.Fatalf("bundle privacy = %+v / %+v", bundle.Privacy, bundle.Preview)
	}
	for _, key := range bundle.Payload.OwnershipReview.Keys {
		if len(key.IdentityHints) != 0 {
			t.Fatalf("standalone ownership review retained identity hints: %+v", key.IdentityHints)
		}
	}
	encoded := strings.ToLower(string(first))
	for _, forbidden := range []string{"ssh-ed25519 aaa", "password=", "private key"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("bundle contains forbidden material %q", forbidden)
		}
	}

	path := filepath.Join(t.TempDir(), "private", "workspace-bundle.json")
	if err := WriteWorkspaceBundle(path, bundle); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %04o, want 0600", info.Mode().Perm())
	}
	read, err := ReadWorkspaceBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	readJSON, err := RenderWorkspaceBundleJSON(read)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, readJSON) {
		t.Fatal("strict bundle round trip changed bytes")
	}
	text := RenderWorkspaceBundleText(read)
	for _, want := range []string{"Offline Cloud ingestion bundle", "client-a", "Idempotency key", "Network activity:           none", "Ready for explicit `sshmgr cloud upload`"} {
		if !strings.Contains(text, want) {
			t.Fatalf("bundle text missing %q:\n%s", want, text)
		}
	}
}

func TestWorkspaceBundleSupportsHistoryOnlyAndExplicitIdentityHintPrivacy(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.ScanID = "scan_hints"
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = testFingerprintA
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Bits = 256
	snapshot.Finalize(testTime)
	plan, err := BuildUploadPlan(snapshot, "client-a", true)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(plan)
	if err != nil {
		t.Fatal(err)
	}
	review, err := BuildOwnershipReview(snapshot, &IdentityMap{SchemaVersion: IdentityMapSchemaVersion, Identities: []Identity{}, Keys: []IdentityKeyOwnership{}})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildWorkspaceBundle(history, review, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Privacy.IdentityHintsIncluded || bundle.Preview.IdentityHints == 0 || bundle.Payload.OwnershipReview == nil {
		t.Fatalf("history-only privacy/preview = %+v / %+v", bundle.Privacy, bundle.Preview)
	}
	if bundle.Digests.OwnershipReview == bundle.Digests.OwnershipReviewSource {
		t.Fatal("privacy-normalized review digest unexpectedly equals the source digest")
	}
	for _, key := range bundle.Payload.OwnershipReview.Keys {
		if len(key.IdentityHints) != 0 {
			t.Fatalf("normalized ownership review retained identity hints: %+v", key.IdentityHints)
		}
	}
	if bundle.Digests.OwnershipHistory != "" || bundle.Digests.OffboardingHistory != "" {
		t.Fatalf("history-only bundle has phantom digests: %+v", bundle.Digests)
	}
}

func TestWorkspaceBundleRejectsTamperingUnknownFieldsAndTrailingJSON(t *testing.T) {
	history, ownership, ownershipHistory, offboardingHistory := workspaceBundleFixture(t)
	bundle, err := BuildWorkspaceBundle(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}

	tampered := *bundle
	tampered.PayloadSHA256 = "SHA256:" + strings.Repeat("0", 64)
	if err := ValidateWorkspaceBundle(&tampered); err == nil || !strings.Contains(err.Error(), "payload_sha256") {
		t.Fatalf("tampered payload digest was accepted: %v", err)
	}
	tampered = *bundle
	tampered.Preview.LatestHosts++
	if err := ValidateWorkspaceBundle(&tampered); err == nil || !strings.Contains(err.Error(), "preview") {
		t.Fatalf("tampered preview was accepted: %v", err)
	}
	tampered = *bundle
	tampered.Digests.OwnershipReviewSource = "SHA256:" + strings.Repeat("0", 64)
	if err := ValidateWorkspaceBundle(&tampered); err == nil {
		t.Fatal("tampered source ownership digest was accepted")
	}

	data, err := RenderWorkspaceBundleJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	generic["future_field"] = true
	unknown, _ := json.Marshal(generic)
	dir := t.TempDir()
	unknownPath := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceBundle(unknownPath); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field was accepted: %v", err)
	}
	trailingPath := filepath.Join(dir, "trailing.json")
	if err := os.WriteFile(trailingPath, append(data, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkspaceBundle(trailingPath); err == nil || !strings.Contains(err.Error(), "more than one JSON value") {
		t.Fatalf("trailing JSON was accepted: %v", err)
	}
}

func TestWorkspaceBundleRejectsMismatchedEvidenceBeforeWriting(t *testing.T) {
	history, _, ownershipHistory, offboardingHistory := workspaceBundleFixture(t)
	otherHistory, _, otherReview := workspaceOwnershipFixture(t)
	if _, err := BuildWorkspaceBundle(history, otherReview, ownershipHistory, offboardingHistory); err == nil {
		t.Fatal("ownership review from another workspace timeline was accepted")
	}
	if _, err := BuildWorkspaceBundle(otherHistory, nil, ownershipHistory, nil); err == nil {
		t.Fatal("ownership history bound to another workspace history was accepted")
	}
	if err := WriteWorkspaceBundle(" ", &WorkspaceBundle{}); err == nil {
		t.Fatal("empty bundle output path was accepted")
	}
}
