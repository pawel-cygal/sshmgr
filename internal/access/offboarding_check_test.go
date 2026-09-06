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

func offboardingCheckFixture(t *testing.T) (*OffboardingReport, *Snapshot, *OwnershipReview, *Snapshot, *OwnershipReview) {
	t.Helper()
	before := fixtureSnapshot()
	before.Hosts[0].Coverage = CoverageFull
	entry := &before.Hosts[0].Accounts[0].Sources[0].Entries[0]
	entry.Fingerprint, entry.Bits = testFingerprintA, 256
	before.Finalize(testTime.Add(time.Second))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{{
			ID: "former@example.com", DisplayName: `<Former & Operator>`,
			Kind: IdentityKindHuman, Status: IdentityStatusOffboarded,
		}},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims:      []OwnershipClaim{{IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual"}},
		}},
	}
	beforeReview, err := BuildOwnershipReview(before, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := BuildOffboardingReport(before, beforeReview, "former@example.com")
	if err != nil {
		t.Fatal(err)
	}
	after, err := cloneSnapshot(before)
	if err != nil {
		t.Fatal(err)
	}
	after.ScanID = "scan_after"
	after.Hosts[0].Accounts[0].Sources[0].Entries = nil
	after.Finalize(testTime.Add(24 * time.Hour))
	afterReview, err := BuildOwnershipReview(after, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	return baseline, before, beforeReview, after, afterReview
}

func TestBuildOffboardingCheckRequiresStrictCompleteEvidence(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	if check.Outcome != OffboardingOutcomeComplete || check.Summary.BlockingReasons != 0 || len(check.NotObserved) != 1 || len(check.StillObserved) != 0 {
		t.Fatalf("complete offboarding check = %+v", check)
	}
	if !check.Comparison.Comparable || !check.Comparison.FreshAfterSnapshot || !check.Comparison.ClaimsUnchanged || !check.Comparison.IdentityOffboarded {
		t.Fatalf("comparison guards = %+v", check.Comparison)
	}
	if len(check.Reasons) != 1 || check.Reasons[0].Code != "mapped_access_not_observed" {
		t.Fatalf("complete reasons = %+v", check.Reasons)
	}
	text := RenderOffboardingCheckText(check)
	for _, want := range []string{"Outcome:         complete", "remote changes: false", "No remediation"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Errorf("text missing %q:\n%s", want, text)
		}
	}
}

func TestBuildOffboardingCheckAcceptsStrictBaselineJSONRoundTrip(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := WriteOffboardingReportJSON(path, baseline); err != nil {
		t.Fatal(err)
	}
	readBaseline, err := ReadOffboardingReport(path)
	if err != nil {
		t.Fatal(err)
	}
	check, err := BuildOffboardingCheck(readBaseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	if check.Outcome != OffboardingOutcomeComplete {
		t.Fatalf("round-tripped baseline outcome = %s", check.Outcome)
	}
}

func TestOffboardingCheckReportsStillPresentAndNewEdges(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	after.Hosts[0].Accounts[0].Sources[0].Entries = []KeyObservation{
		{Line: 2, Fingerprint: testFingerprintA, Algorithm: sshAlgorithmFixture, Bits: 256},
	}
	after.Finalize(testTime.Add(24 * time.Hour))
	identityMap := identityMapFromOwnershipReview(afterReview)
	var err error
	afterReview, err = BuildOwnershipReview(after, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	if check.Outcome != OffboardingOutcomePresent || len(check.StillObserved) != 1 || len(check.NewlyObserved) != 0 {
		t.Fatalf("still-present check = %+v", check)
	}

	after.Hosts[0].Accounts = append(after.Hosts[0].Accounts, AccountSnapshot{
		Username: "root", Sources: []KeySource{{
			Type: "authorized_keys_file", Path: "/root/.ssh/authorized_keys", Exists: true, ContentInspected: true,
			Entries: []KeyObservation{{Line: 1, Fingerprint: testFingerprintA, Algorithm: sshAlgorithmFixture, Bits: 256}},
		}},
	})
	after.Finalize(testTime.Add(25 * time.Hour))
	afterReview, err = BuildOwnershipReview(after, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	check, err = BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	if check.Outcome != OffboardingOutcomePresent || len(check.NewlyObserved) != 1 {
		t.Fatalf("new access edge check = %+v", check)
	}
}

func TestOffboardingCheckNeverCallsIncompleteEvidenceComplete(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	tests := map[string]func(){
		"failed coverage": func() {
			after.Hosts[0].Coverage = CoverageFailed
			after.Hosts[0].Errors = []ScanError{{Stage: "connect", Message: "failed"}}
			after.Hosts[0].Accounts = nil
		},
		"dynamic source": func() {
			after.Scope.Mode = "system"
			after.Scope.AccountMode = AccountModeExplicit
			before.Scope.Mode = "system"
			before.Scope.AccountMode = AccountModeExplicit
			before.Hosts[0].System = &SystemSnapshot{SSHD: SSHDConfigSnapshot{AuthorizedKeysCommand: "/bin/keys"}}
			after.Hosts[0].System = &SystemSnapshot{SSHD: SSHDConfigSnapshot{AuthorizedKeysCommand: "/bin/keys"}}
		},
		"same scan": func() { after.ScanID = before.ScanID },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			baselineCopy, beforeCopy, beforeReviewCopy, afterCopy, afterReviewCopy := offboardingCheckFixture(t)
			baseline, before, beforeReview, after, afterReview = baselineCopy, beforeCopy, beforeReviewCopy, afterCopy, afterReviewCopy
			mutate()
			before.Finalize(testTime.Add(time.Second))
			after.Finalize(testTime.Add(24 * time.Hour))
			identityMap := identityMapFromOwnershipReview(beforeReview)
			var err error
			beforeReview, err = BuildOwnershipReview(before, identityMap)
			if err != nil {
				t.Fatal(err)
			}
			baseline, err = BuildOffboardingReport(before, beforeReview, "former@example.com")
			if err != nil {
				t.Fatal(err)
			}
			afterReview, err = BuildOwnershipReview(after, identityMap)
			if err != nil {
				t.Fatal(err)
			}
			check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
			if err != nil {
				t.Fatal(err)
			}
			if check.Outcome == OffboardingOutcomeComplete {
				t.Fatalf("incomplete evidence returned complete: %+v", check)
			}
		})
	}
}

func TestOffboardingCheckRejectsChangedClaimsAndMismatchedBaseline(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	identityMap := identityMapFromOwnershipReview(afterReview)
	identityMap.Keys[0].Claims[0].Source = "changed-source"
	changedReview, err := BuildOwnershipReview(after, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, changedReview)
	if err != nil {
		t.Fatal(err)
	}
	if check.Outcome != OffboardingOutcomeUnknown || check.Comparison.ClaimsUnchanged {
		t.Fatalf("changed claims check = %+v", check)
	}

	before.Hosts[0].Accounts[0].Sources[0].Entries[0].Line = 9
	before.Finalize(testTime.Add(time.Second))
	if _, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview); err == nil {
		t.Fatal("offboarding check accepted a baseline report with mismatched inputs")
	}
}

func TestOffboardingCheckTreatsMissingAfterIdentityAsInconclusive(t *testing.T) {
	baseline, before, beforeReview, after, _ := offboardingCheckFixture(t)
	afterReview, err := BuildOwnershipReview(after, &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities:    []Identity{},
		Keys:          []IdentityKeyOwnership{},
	})
	if err != nil {
		t.Fatal(err)
	}
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	if check.Outcome != OffboardingOutcomeUnknown || check.Comparison.IdentityPresent || check.Comparison.ClaimsUnchanged || len(check.CurrentKeys) != 0 {
		t.Fatalf("missing after identity check = %+v", check)
	}
	jsonData, err := RenderOffboardingCheckJSON(check)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "check.json")
	if err := os.WriteFile(path, jsonData, 0o600); err != nil {
		t.Fatal(err)
	}
	roundTripped, err := ReadOffboardingCheck(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOffboardingCheckAgainstInputs(roundTripped, baseline, before, beforeReview, after, afterReview); err != nil {
		t.Fatalf("round-tripped check did not reconcile: %v", err)
	}
}

func TestOffboardingCheckExportsAreStrictPrivateDeterministicAndSafe(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	one, err := RenderOffboardingCheckJSON(check)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := RenderOffboardingCheckJSON(check)
	if !bytes.Equal(one, two) {
		t.Fatal("offboarding check JSON is not deterministic")
	}
	csvData, err := RenderOffboardingCheckCSV(check)
	if err != nil || !bytes.Contains(csvData, []byte("mapped_access_not_observed")) {
		t.Fatalf("check CSV err=%v:\n%s", err, csvData)
	}
	htmlData, err := RenderOffboardingCheckHTML(check)
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlData)
	for _, want := range []string{"read-only post-scan verification", "complete", "Not observed after rescan", "default-src 'none'", "&lt;Former &amp; Operator&gt;"} {
		if !strings.Contains(html, want) {
			t.Fatalf("check HTML missing %q", want)
		}
	}
	for _, forbidden := range []string{"<Former & Operator>", "<script", `href="http`, `src="http`, "url("} {
		if strings.Contains(strings.ToLower(html), strings.ToLower(forbidden)) {
			t.Fatalf("check HTML contains unsafe token %q", forbidden)
		}
	}

	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "check.json"), filepath.Join(dir, "check.html"), filepath.Join(dir, "check.csv")}
	if err := WriteOffboardingCheckJSON(paths[0], check); err != nil {
		t.Fatal(err)
	}
	if err := WriteOffboardingCheckHTML(paths[1], check); err != nil {
		t.Fatal(err)
	}
	if err := WriteOffboardingCheckCSV(paths[2], check); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private output %s info=%v err=%v", path, info, err)
		}
	}
	readBack, err := ReadOffboardingCheck(paths[0])
	if err != nil || readBack.CheckID != check.CheckID {
		t.Fatalf("strict round trip err=%v report=%+v", err, readBack)
	}

	var tampered OffboardingCheck
	if err := json.Unmarshal(one, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Outcome = OffboardingOutcomePresent
	if err := ValidateOffboardingCheck(&tampered); err == nil {
		t.Fatal("validator accepted a tampered outcome")
	}
	unknown := bytes.Replace(one, []byte(`"schema_version": "1",`), []byte(`"schema_version": "1", "smuggled": true,`), 1)
	unknownPath := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOffboardingCheck(unknownPath); err == nil {
		t.Fatal("strict reader accepted an unknown field")
	}
}
