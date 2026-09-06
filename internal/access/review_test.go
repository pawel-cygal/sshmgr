package access

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownershipReviewFixture(t *testing.T) *OwnershipReview {
	t.Helper()
	snapshot := fixtureSnapshot()
	source := &snapshot.Hosts[0].Accounts[0].Sources[0]
	source.Entries[0].Fingerprint = testFingerprintA
	source.Entries[0].Bits = 2048
	source.Entries = append(source.Entries, KeyObservation{
		Line: 2, Fingerprint: testFingerprintB, Algorithm: "ssh-rsa", Bits: 2048, Comment: "unknown@hint",
	})
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{
			{ID: "=alice@example.com", DisplayName: "<Alice>", Kind: IdentityKindHuman, Status: IdentityStatusActive},
			{ID: "former@example.com", DisplayName: "Former", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded},
		},
		Keys: []IdentityKeyOwnership{
			{Fingerprint: testFingerprintA, Claims: []OwnershipClaim{
				{IdentityID: "=alice@example.com", Status: ClaimStatusVerified, Source: "manual", VerifiedAt: "2026-08-12T00:00:00Z"},
				{IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual"},
			}},
			{Fingerprint: testFingerprintB, Claims: []OwnershipClaim{}},
			{Fingerprint: testFingerprintC, Claims: []OwnershipClaim{{IdentityID: "=alice@example.com", Status: ClaimStatusClaimed, Source: "manual"}}},
		},
	}
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	return review
}

func TestBuildOwnershipReviewFindsUnknownSharedAndOffboardedAccess(t *testing.T) {
	review := ownershipReviewFixture(t)
	if review.Summary.ObservedKeys != 2 || review.Summary.OwnedKeys != 1 || review.Summary.UnknownKeys != 1 || review.Summary.SharedKeys != 1 {
		t.Fatalf("ownership summary = %+v", review.Summary)
	}
	if review.Summary.OffboardedAccessKeys != 1 || review.Summary.PossessionVerifiedKeys != 1 || review.Summary.MappedKeysNotObserved != 1 {
		t.Fatalf("risk summary = %+v", review.Summary)
	}
	wantRules := map[string]bool{"unknown_key": false, "shared_key": false, "offboarded_identity_access": false, "identity_map_key_not_observed": false}
	for _, finding := range review.Findings {
		if _, exists := wantRules[finding.RuleID]; exists {
			wantRules[finding.RuleID] = true
		}
	}
	for rule, found := range wantRules {
		if !found {
			t.Errorf("missing %s finding: %+v", rule, review.Findings)
		}
	}
}

func TestMappedOffboardedKeyWithoutObservedAccessIsNotAnOffboardingFinding(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries = nil
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{{
			ID: "former@example.com", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded,
		}},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims: []OwnershipClaim{{
				IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual",
			}},
		}},
	}
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Keys) != 1 || review.Keys[0].Observed || review.Keys[0].OffboardedAccess {
		t.Fatalf("unobserved mapped key = %+v", review.Keys)
	}
	if review.Summary.OffboardedAccessKeys != 0 {
		t.Fatalf("unobserved map entry counted as access: %+v", review.Summary)
	}
	for _, finding := range review.Findings {
		if finding.RuleID == "offboarded_identity_access" {
			t.Fatalf("unobserved map entry emitted access finding: %+v", finding)
		}
	}
}

func TestOwnershipReviewExportsArePrivateSafeAndDeterministic(t *testing.T) {
	review := ownershipReviewFixture(t)
	jsonOne, err := RenderOwnershipReviewJSON(review)
	if err != nil {
		t.Fatal(err)
	}
	jsonTwo, _ := RenderOwnershipReviewJSON(review)
	if !bytes.Equal(jsonOne, jsonTwo) {
		t.Fatal("ownership JSON is not deterministic")
	}
	if bytes.Contains(jsonOne, []byte("public_key")) {
		t.Fatal("ownership review contains public-key material")
	}
	csvData, err := RenderOwnershipReviewCSV(review)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(csvData, []byte(`'=alice@example.com`)) {
		t.Fatalf("CSV identity was not protected from formula execution:\n%s", csvData)
	}
	htmlData, err := RenderOwnershipReviewHTML(review)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(htmlData, []byte("<Alice>")) || !bytes.Contains(htmlData, []byte("&lt;Alice&gt;")) {
		t.Fatal("ownership HTML did not escape display name")
	}
	if bytes.Contains(htmlData, []byte("https://")) || bytes.Contains(htmlData, []byte("<script")) {
		t.Fatal("ownership HTML has a remote or executable dependency")
	}

	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "review.json"), filepath.Join(dir, "review.csv"), filepath.Join(dir, "review.html")}
	if err := WriteOwnershipReviewJSON(paths[0], review); err != nil {
		t.Fatal(err)
	}
	if err := WriteOwnershipReviewCSV(paths[1], review); err != nil {
		t.Fatal(err)
	}
	if err := WriteOwnershipReviewHTML(paths[2], review); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
		}
	}
	readBack, err := ReadOwnershipReview(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if readBack.ReviewID != review.ReviewID {
		t.Fatalf("review round trip = %+v", readBack)
	}
}

func TestValidateOwnershipReviewRejectsInconsistentArtifact(t *testing.T) {
	tests := map[string]func(*OwnershipReview){
		"summary":            func(review *OwnershipReview) { review.Summary.UnknownKeys++ },
		"claim flag":         func(review *OwnershipReview) { review.Keys[0].OffboardedAccess = false },
		"review id":          func(review *OwnershipReview) { review.ReviewID = "review_wrong" },
		"identity lifecycle": func(review *OwnershipReview) { review.Identities[1].Status = IdentityStatusActive },
		"map membership":     func(review *OwnershipReview) { review.Keys[0].IdentityMapEntry = false },
		"unobserved evidence": func(review *OwnershipReview) {
			for index := range review.Keys {
				if !review.Keys[index].Observed {
					review.Keys[index].Occurrences = 1
					return
				}
			}
		},
		"missing finding": func(review *OwnershipReview) { review.Findings = review.Findings[1:] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			review := ownershipReviewFixture(t)
			mutate(review)
			if err := ValidateOwnershipReview(review); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("invalid review accepted")
			}
		})
	}
}

func TestValidateOwnershipReviewAgainstSnapshotBindsObservedAccessButAllowsHintRedaction(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = testFingerprintA
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{{
			ID: "former@example.com", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded,
		}},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims: []OwnershipClaim{{
				IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual",
			}},
		}},
	}
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := cloneSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	redacted.Hosts[0].Accounts[0].Sources[0].Entries[0].Comment = ""
	redacted.Finalize(testTime.Add(2))
	if err := ValidateOwnershipReviewAgainstSnapshot(review, redacted); err != nil {
		t.Fatalf("privacy-preserving identity-hint redaction broke ownership join: %v", err)
	}

	changed, err := cloneSnapshot(redacted)
	if err != nil {
		t.Fatal(err)
	}
	changed.Hosts[0].Accounts[0].Username = "root"
	changed.Finalize(testTime.Add(2))
	if err := ValidateOwnershipReviewAgainstSnapshot(review, changed); err == nil || !strings.Contains(err.Error(), "does not reconcile") {
		t.Fatalf("review was joined to changed access evidence: %v", err)
	}
}
