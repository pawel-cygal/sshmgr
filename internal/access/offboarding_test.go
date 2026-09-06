package access

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func offboardingFixture(t *testing.T) (*Snapshot, *OwnershipReview, *OffboardingReport) {
	t.Helper()
	snapshot := fixtureSnapshot()
	entry := &snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	entry.Fingerprint = testFingerprintA
	entry.Bits = 256
	entry.Options = []string{`from="10.0.0.0/8"`, "no-agent-forwarding"}
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{
			{ID: "active@example.com", DisplayName: `<img src=x onerror=alert(1)>`, Kind: IdentityKindHuman, Status: IdentityStatusActive},
			{ID: "former@example.com", DisplayName: `<Former Operator>`, Kind: IdentityKindHuman, Status: IdentityStatusOffboarded},
		},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims: []OwnershipClaim{
				{IdentityID: "active@example.com", Status: ClaimStatusVerified, Source: "manual", VerifiedAt: "2026-08-12T00:00:00Z"},
				{IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual"},
			},
		}},
	}
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildOffboardingReport(snapshot, review, "former@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, review, report
}

func TestBuildOffboardingReportIsReadOnlyEvidenceWithSharedKeyWarnings(t *testing.T) {
	_, _, report := offboardingFixture(t)
	if report.Identity.Status != IdentityStatusOffboarded || report.Safety.Mode != OffboardingReportMode || report.Safety.RemoteChanges || report.Safety.Executable || report.Safety.SourceDigestsIncluded || !report.Safety.RequiresFreshScan {
		t.Fatalf("offboarding safety contract = %+v identity=%+v", report.Safety, report.Identity)
	}
	if report.Summary.ClaimedKeys != 1 || report.Summary.ObservedKeys != 1 || report.Summary.AccessEdges != 1 || report.Summary.Hosts != 1 || report.Summary.Accounts != 1 || report.Summary.SharedKeys != 1 || report.Summary.UnverifiedClaimKeys != 1 {
		t.Fatalf("offboarding summary = %+v", report.Summary)
	}
	if len(report.Keys) != 1 || len(report.Keys[0].Access) != 1 || !report.Keys[0].Shared || len(report.Keys[0].OtherClaims) != 1 {
		t.Fatalf("offboarding evidence = %+v", report.Keys)
	}
	wants := map[string]bool{
		"offboarded_access_observed": false, "shared_key_claim": false,
		"claim_not_possession_verified": false, "incomplete_coverage": false,
	}
	for _, warning := range report.Warnings {
		if _, exists := wants[warning.Code]; exists {
			wants[warning.Code] = true
		}
	}
	for code, found := range wants {
		if !found {
			t.Errorf("missing warning %s: %+v", code, report.Warnings)
		}
	}
	text := RenderOffboardingReportText(report)
	for _, want := range []string{"report_only", "remote changes: false", "SHARED", "deploy@web-01", "not an executable removal plan"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Errorf("text report missing %q:\n%s", want, text)
		}
	}
}

func TestOffboardingReportSupportsNoClaimsAndMappedButUnobserved(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries = nil
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{
			{ID: "former@example.com", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded},
			{ID: "nobody@example.com", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded},
		},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims:      []OwnershipClaim{{IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual"}},
		}},
	}
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := BuildOffboardingReport(snapshot, review, "former@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Summary.MappedKeysNotObserved != 1 || mapped.Summary.AccessEdges != 0 {
		t.Fatalf("mapped-only report = %+v", mapped.Summary)
	}
	empty, err := BuildOffboardingReport(snapshot, review, "nobody@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if empty.Summary.ClaimedKeys != 0 || len(empty.Warnings) == 0 || empty.Warnings[0].Code != "identity_has_no_claimed_keys" {
		t.Fatalf("no-claim report = %+v", empty)
	}
	emptyCSV, err := RenderOffboardingReportCSV(empty)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(emptyCSV, []byte("identity_has_no_claimed_keys")) || !bytes.Contains(emptyCSV, []byte("nobody@example.com")) {
		t.Fatalf("no-claim CSV lacks identity-level evidence:\n%s", emptyCSV)
	}
	if _, err := BuildOffboardingReport(snapshot, review, "missing@example.com"); err == nil {
		t.Fatal("unknown identity was accepted")
	}
}

func TestOffboardingReportPreservesDynamicSourceCoverageBoundary(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Scope.Mode = "system"
	snapshot.Scope.AccountMode = AccountModeExplicit
	snapshot.Hosts[0].System = &SystemSnapshot{SSHD: SSHDConfigSnapshot{
		AuthorizedKeysCommand: "/usr/local/bin/dynamic-keys",
	}}
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = testFingerprintA
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{{
			ID: "former@example.com", Kind: IdentityKindHuman, Status: IdentityStatusOffboarded,
		}},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims:      []OwnershipClaim{{IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual"}},
		}},
	}
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildOffboardingReport(snapshot, review, "former@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Coverage.DynamicSourceHosts, ",") != "web-01" {
		t.Fatalf("dynamic source hosts = %v", report.Coverage.DynamicSourceHosts)
	}
	found := false
	for _, warning := range report.Warnings {
		found = found || warning.Code == "dynamic_or_certificate_sources"
	}
	if !found || report.Coverage.Caveat == "" {
		t.Fatalf("dynamic source boundary missing: coverage=%+v warnings=%+v", report.Coverage, report.Warnings)
	}
}

func TestOffboardingReportExportsArePrivateDeterministicAndSafe(t *testing.T) {
	_, _, report := offboardingFixture(t)
	jsonOne, err := RenderOffboardingReportJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	jsonTwo, _ := RenderOffboardingReportJSON(report)
	if !bytes.Equal(jsonOne, jsonTwo) {
		t.Fatal("offboarding JSON is not deterministic")
	}
	csvData, err := RenderOffboardingReportCSV(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(csvData, []byte("report_only")) || !bytes.Contains(csvData, []byte("false,false")) {
		t.Fatalf("CSV lacks safety contract:\n%s", csvData)
	}
	htmlData, err := RenderOffboardingReportHTML(report)
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlData)
	for _, want := range []string{"Not an executable removal plan", "default-src 'none'", "&lt;Former Operator&gt;", "shared_key_claim"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	for _, forbidden := range []string{"<Former Operator>", "<script", "<img", `href="http`, `src="http`, "url("} {
		if strings.Contains(strings.ToLower(html), strings.ToLower(forbidden)) {
			t.Fatalf("HTML contains unsafe token %q", forbidden)
		}
	}

	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "report.json"), filepath.Join(dir, "report.html"), filepath.Join(dir, "report.csv")}
	if err := WriteOffboardingReportJSON(paths[0], report); err != nil {
		t.Fatal(err)
	}
	if err := WriteOffboardingReportHTML(paths[1], report); err != nil {
		t.Fatal(err)
	}
	if err := WriteOffboardingReportCSV(paths[2], report); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%04o", path, info.Mode().Perm())
		}
	}
	readBack, err := ReadOffboardingReport(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if readBack.ReportID != report.ReportID {
		t.Fatalf("offboarding round trip = %+v", readBack)
	}
}

func TestValidateOffboardingReportRejectsTamperingAndUnknownFields(t *testing.T) {
	_, _, report := offboardingFixture(t)
	tests := map[string]func(*OffboardingReport){
		"safety":   func(value *OffboardingReport) { value.Safety.Executable = true },
		"summary":  func(value *OffboardingReport) { value.Summary.AccessEdges++ },
		"identity": func(value *OffboardingReport) { value.Identity.Status = IdentityStatusActive },
		"claim":    func(value *OffboardingReport) { value.Keys[0].SelectedClaim.IdentityID = "other@example.com" },
		"access":   func(value *OffboardingReport) { value.Keys[0].Access[0].Account = "root" },
		"warning":  func(value *OffboardingReport) { value.Warnings = value.Warnings[1:] },
		"caveat":   func(value *OffboardingReport) { value.Coverage.Caveat = "trust me" },
		"algorithm": func(value *OffboardingReport) {
			value.Keys[0].Algorithm = "ssh-ed25519\nforged"
		},
		"id": func(value *OffboardingReport) { value.ReportID = "offboarding_wrong" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := RenderOffboardingReportJSON(report)
			if err != nil {
				t.Fatal(err)
			}
			var clone OffboardingReport
			if err := json.Unmarshal(data, &clone); err != nil {
				t.Fatal(err)
			}
			mutate(&clone)
			if err := ValidateOffboardingReport(&clone); err == nil {
				t.Fatal("tampered offboarding report was accepted")
			}
		})
	}

	data, err := RenderOffboardingReportJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(data, []byte(`"schema_version": "1",`), []byte(`"schema_version": "1", "smuggled": true,`), 1)
	path := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOffboardingReport(path); err == nil {
		t.Fatal("strict reader accepted unknown field")
	}
}

func TestBuildOffboardingReportRejectsTerminalControlText(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = testFingerprintA
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{{
			ID: "former@example.com", DisplayName: "Former\x1b[2JOperator",
			Kind: IdentityKindHuman, Status: IdentityStatusOffboarded,
		}},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims:      []OwnershipClaim{{IdentityID: "former@example.com", Status: ClaimStatusClaimed, Source: "manual"}},
		}},
	}
	// The existing ownership contract predates terminal export and can carry
	// this byte. The offboarding boundary must refuse to print it.
	review, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildOffboardingReport(snapshot, review, "former@example.com"); err == nil {
		t.Fatal("offboarding report accepted terminal control text")
	}
}
