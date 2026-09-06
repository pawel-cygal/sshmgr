package access

import (
	"bytes"
	htmlstd "html"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceDashboardRendersLatestStateAndTimelineDeterministically(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	two := workspacePlanFixture(t, "scan_two", "2026-08-12T12:00:01Z", "SHA256:two")
	history, err := BuildWorkspaceHistory(two, one)
	if err != nil {
		t.Fatal(err)
	}

	first, err := RenderWorkspaceDashboardHTML(history)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderWorkspaceDashboardHTML(history)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical workspace history produced different dashboard HTML")
	}
	html := string(first)
	for _, want := range []string{
		"sshmgr Cloud · local preview", "client-a", "Overview", "Findings",
		"Access Graph", "Timeline", "scan_one", "scan_two", "SHA256:one", "SHA256:two",
		"Network activity: none", "Content-Security-Policy", "default-src 'none'", "+1", "−1",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}

	// Current-state graph rows are derived solely from the latest snapshot.
	graph, err := BuildAccessGraph(&history.Plans[len(history.Plans)-1].Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	keys := workspaceDashboardKeys(graph)
	if len(keys) != 1 || keys[0].Fingerprint != "SHA256:two" {
		t.Fatalf("current access graph was not latest-only: %+v", keys)
	}
}

func TestWorkspaceDashboardEscapesUntrustedSnapshotTextAndHasNoRemoteAssets(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.ScanID = "scan_hostile"
	snapshot.Hosts[0].Alias = `<script>alert("host")</script>`
	snapshot.Hosts[0].Accounts[0].Username = `<img src=x onerror=alert("account")>`
	snapshot.Hosts[0].Accounts[0].Sources[0].Path = `</code><iframe src="https://attacker.invalid">`
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Comment = `<svg onload=alert("hint")>`
	snapshot.Finalize(testTime.Add(2))
	plan, err := BuildUploadPlan(snapshot, "hostile-workspace", true)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(plan)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTML(history)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, forbidden := range []string{"<script", "<img", "<iframe", "<svg", `href="http`, `src="http`, "url("} {
		if strings.Contains(strings.ToLower(html), forbidden) {
			t.Fatalf("dashboard contains executable or remote HTML token %q", forbidden)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img", "&lt;iframe", "&lt;svg"} {
		if !strings.Contains(html, escaped) {
			t.Fatalf("dashboard did not preserve hostile value as escaped text %q", escaped)
		}
	}
}

func TestWorkspaceDashboardWriteUsesPrivateMode(t *testing.T) {
	plan := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", "SHA256:one")
	history, err := BuildWorkspaceHistory(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "dashboard.html")
	if err := WriteWorkspaceDashboardHTML(path, history); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("dashboard mode = %04o, want 0600", info.Mode().Perm())
	}
	if err := WriteWorkspaceDashboardHTML(" ", history); err == nil {
		t.Fatal("empty dashboard output path was accepted")
	}
}

func TestWorkspaceDashboardRejectsInvalidHistory(t *testing.T) {
	if _, err := RenderWorkspaceDashboardHTML(nil); err == nil {
		t.Fatal("nil history was accepted")
	}
	if got := RenderWorkspaceDashboardText(&WorkspaceHistory{}, "dashboard.html"); got != "" {
		t.Fatalf("empty history text = %q", got)
	}
}

func TestWorkspaceDashboardJoinsLatestOwnershipAndOffboardingEvidence(t *testing.T) {
	snapshot := fixtureSnapshot()
	entry := &snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	entry.Fingerprint = testFingerprintA
	entry.Bits = 256
	snapshot.Finalize(testTime.Add(2))
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{
			{ID: "active@example.com", DisplayName: `<img src=x onerror=alert(1)>`, Kind: IdentityKindHuman, Status: IdentityStatusActive},
			{ID: "former@example.com", DisplayName: `<Former>`, Kind: IdentityKindHuman, Status: IdentityStatusOffboarded},
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
	plan, err := BuildUploadPlan(snapshot, "client-a", false)
	if err != nil {
		t.Fatal(err)
	}
	history, err := BuildWorkspaceHistory(plan)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTMLWithOwnership(history, review)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := RenderWorkspaceDashboardHTMLWithOwnership(history, review)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, repeated) {
		t.Fatal("identical ownership join produced different dashboard HTML")
	}
	html := string(data)
	for _, want := range []string{
		"Ownership &amp; Offboarding", "Ownership findings", "Identity ownership", "Offboarding evidence",
		"offboarded_identity_access",
		"Explicit path: identity → SSH fingerprint → OS account → host.",
		"active@example.com", "former@example.com", "possession_verified",
		"Read-only evidence:", "deploy", "web-01", "&lt;img src=x onerror=alert(1)&gt;", "&lt;Former&gt;",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("ownership dashboard missing %q", want)
		}
	}
	for _, forbidden := range []string{"<img", "<Former>"} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("ownership dashboard did not escape %q", forbidden)
		}
	}
}

func TestWorkspaceDashboardRejectsOwnershipFromAnotherLatestSnapshot(t *testing.T) {
	one := workspacePlanFixture(t, "scan_one", "2026-08-11T12:00:01Z", testFingerprintA)
	two := workspacePlanFixture(t, "scan_two", "2026-08-12T12:00:01Z", testFingerprintA)
	history, err := BuildWorkspaceHistory(one, two)
	if err != nil {
		t.Fatal(err)
	}
	identityMap := &IdentityMap{SchemaVersion: IdentityMapSchemaVersion, Identities: []Identity{}, Keys: []IdentityKeyOwnership{{Fingerprint: testFingerprintA, Claims: []OwnershipClaim{}}}}
	review, err := BuildOwnershipReview(&one.Snapshot, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderWorkspaceDashboardHTMLWithOwnership(history, review); err == nil || !strings.Contains(err.Error(), "does not match latest") {
		t.Fatalf("stale ownership review was attached: %v", err)
	}
}

func TestWorkspaceDashboardRendersBoundCurrentOffboardingHistory(t *testing.T) {
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
	history, err := BuildWorkspaceHistory(beforePlan, afterPlan)
	if err != nil {
		t.Fatal(err)
	}
	offboardingHistory, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTMLWithEvidence(history, afterReview, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := RenderWorkspaceDashboardHTMLWithEvidence(history, afterReview, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, repeated) {
		t.Fatal("identical offboarding evidence produced different dashboard HTML")
	}
	html := string(data)
	for _, want := range []string{
		"Current offboarding outcomes", "Offboarding outcome history", "former@example.com",
		"complete", "mapped_access_not_observed", check.AfterScanID, check.CheckID,
		"offboarding: <code>former@example.com</code> · complete", "not universal proof of removal",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("offboarding dashboard missing %q", want)
		}
	}
	if strings.Contains(html, ">STALE<") {
		t.Fatal("current offboarding result was marked stale")
	}
}

func TestWorkspaceDashboardKeepsEveryStillPresentEdgeVisibleWithoutOwnership(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	after.Hosts[0].Accounts[0].Sources[0].Entries = []KeyObservation{{
		Line: 3, Fingerprint: testFingerprintA, Algorithm: sshAlgorithmFixture, Bits: 256,
	}}
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
	beforePlan, _ := BuildUploadPlan(before, "client-a", false)
	afterPlan, _ := BuildUploadPlan(after, "client-a", false)
	history, err := BuildWorkspaceHistory(beforePlan, afterPlan)
	if err != nil {
		t.Fatal(err)
	}
	offboardingHistory, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTMLWithEvidence(history, nil, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	unescaped := htmlstd.UnescapeString(html)
	for _, want := range []string{"Still observed", testFingerprintA, "deploy", "web-01", ".ssh/authorized_keys:3"} {
		if !strings.Contains(unescaped, want) {
			t.Fatalf("still-present evidence missing %q", want)
		}
	}
}

func TestWorkspaceDashboardNeverPresentsStaleCompleteAsCurrent(t *testing.T) {
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
	history, err = BuildWorkspaceHistory(&history.Plans[0], &history.Plans[1], thirdPlan)
	if err != nil {
		t.Fatal(err)
	}
	offboardingHistory, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTMLWithEvidence(history, nil, offboardingHistory)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{"Stale evidence exists.", ">STALE<", "stale identities"} {
		if !strings.Contains(html, want) {
			t.Fatalf("stale dashboard missing %q", want)
		}
	}
	if offboardingHistory.Summary.CurrentComplete != 0 {
		t.Fatal("stale complete was counted as current")
	}
}

func TestWorkspaceDashboardRejectsMismatchedCurrentOffboardingReview(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	beforePlan, _ := BuildUploadPlan(before, "client-a", false)
	afterPlan, _ := BuildUploadPlan(after, "client-a", false)
	history, err := BuildWorkspaceHistory(beforePlan, afterPlan)
	if err != nil {
		t.Fatal(err)
	}
	offboardingHistory, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	identityMap := identityMapFromOwnershipReview(afterReview)
	identityMap.Identities = append(identityMap.Identities, Identity{ID: "other@example.com", Kind: IdentityKindHuman, Status: IdentityStatusActive})
	otherReview, err := BuildOwnershipReview(after, identityMap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderWorkspaceDashboardHTMLWithEvidence(history, otherReview, offboardingHistory); err == nil || !strings.Contains(err.Error(), "does not match the attached ownership review") {
		t.Fatalf("mismatched current review was attached: %v", err)
	}
}

func TestWorkspaceDashboardRendersOwnershipHistoryAndTransitions(t *testing.T) {
	history, before, after := workspaceOwnershipFixture(t)
	ownershipHistory, err := BuildWorkspaceOwnershipHistory(history, after, before)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, after, ownershipHistory, nil)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, after, ownershipHistory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, repeated) {
		t.Fatal("identical ownership history produced different dashboard HTML")
	}
	html := string(data)
	for _, want := range []string{
		"Ownership review coverage", "Ownership review history", "Ownership changes",
		"2</div>reviewed scans", "identity ·", "claim ·", "key-state changes",
		"alice@example.com", "active", "offboarded", "ownership review: <code>",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("ownership history dashboard missing %q", want)
		}
	}
	if strings.Contains(html, "alice@laptop") {
		t.Fatal("unverified identity hint appeared in ownership history dashboard")
	}
}

func TestWorkspaceDashboardWarnsWhenOwnershipHistoryIsStale(t *testing.T) {
	history, before, _ := workspaceOwnershipFixture(t)
	ownershipHistory, err := BuildWorkspaceOwnershipHistory(history, before)
	if err != nil {
		t.Fatal(err)
	}
	data, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, nil, ownershipHistory, nil)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, want := range []string{"Ownership evidence is stale.", "Ownership review gaps exist.", ">STALE<"} {
		if !strings.Contains(html, want) {
			t.Fatalf("stale ownership dashboard missing %q", want)
		}
	}
}

func TestWorkspaceDashboardRejectsLatestReviewMissingFromOwnershipHistory(t *testing.T) {
	history, before, after := workspaceOwnershipFixture(t)
	ownershipHistory, err := BuildWorkspaceOwnershipHistory(history, before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, after, ownershipHistory, nil); err == nil || !strings.Contains(err.Error(), "does not contain the latest") {
		t.Fatalf("latest ownership review absent from history was accepted: %v", err)
	}
}

func TestWorkspaceDashboardStrictlyJoinsOwnershipAndOffboardingHistories(t *testing.T) {
	baseline, before, beforeReview, after, afterReview := offboardingCheckFixture(t)
	check, err := BuildOffboardingCheck(baseline, before, beforeReview, after, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	beforePlan, _ := BuildUploadPlan(before, "client-a", false)
	afterPlan, _ := BuildUploadPlan(after, "client-a", false)
	history, err := BuildWorkspaceHistory(beforePlan, afterPlan)
	if err != nil {
		t.Fatal(err)
	}
	ownershipHistory, err := BuildWorkspaceOwnershipHistory(history, beforeReview, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	offboardingHistory, err := BuildWorkspaceOffboardingHistory(history, check)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, afterReview, ownershipHistory, offboardingHistory); err != nil {
		t.Fatalf("matching audit evidence rejected: %v", err)
	}

	alternativeMap := identityMapFromOwnershipReview(beforeReview)
	alternativeMap.Identities = append(alternativeMap.Identities, Identity{ID: "audit@example.com", Kind: IdentityKindHuman, Status: IdentityStatusActive})
	alternativeBefore, err := BuildOwnershipReview(before, alternativeMap)
	if err != nil {
		t.Fatal(err)
	}
	alternativeHistory, err := BuildWorkspaceOwnershipHistory(history, alternativeBefore, afterReview)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderWorkspaceDashboardHTMLWithAuditEvidence(history, afterReview, alternativeHistory, offboardingHistory); err == nil || !strings.Contains(err.Error(), "does not match the attached ownership history") {
		t.Fatalf("offboarding evidence mismatched with ownership history was accepted: %v", err)
	}
}
