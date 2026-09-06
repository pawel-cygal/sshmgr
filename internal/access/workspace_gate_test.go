package access

import (
	"strings"
	"testing"
)

func TestWorkspaceDashboardGatePassesCompleteCurrentEvidence(t *testing.T) {
	history, ownership, ownershipHistory, offboardingHistory := workspaceDashboardFullAuditFixture(t)
	result, err := EvaluateWorkspaceDashboardGate(history, ownership, ownershipHistory, offboardingHistory, WorkspaceDashboardGatePolicy{
		FailOnSeverity: SeverityCritical, RequireFullCoverage: true,
		RequireCurrentOwnership: true, RequireCompleteOffboarding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Failed() || !result.CurrentOwnershipReview || !result.OffboardingHistoryAttached || result.IncompleteHosts != 0 || result.IncompleteOffboarding != 0 {
		t.Fatalf("complete evidence failed workspace gate: %+v", result)
	}
}

func TestWorkspaceDashboardGateCombinesSnapshotAndCurrentOwnershipFindings(t *testing.T) {
	history, ownership, ownershipHistory, offboardingHistory := workspaceDashboardFullAuditFixture(t)
	wantSnapshot, err := CountFindingsAtOrAbove(history.Plans[len(history.Plans)-1].Snapshot.Findings, SeverityInfo)
	if err != nil {
		t.Fatal(err)
	}
	wantOwnership, err := CountFindingsAtOrAbove(ownership.Findings, SeverityInfo)
	if err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateWorkspaceDashboardGate(history, ownership, ownershipHistory, offboardingHistory, WorkspaceDashboardGatePolicy{FailOnSeverity: SeverityInfo})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failed() || result.SnapshotFindingsMatched != wantSnapshot || result.OwnershipFindingsMatched != wantOwnership || wantSnapshot+wantOwnership == 0 {
		t.Fatalf("combined findings gate = %+v; want %d + %d", result, wantSnapshot, wantOwnership)
	}
	historyOnly, err := EvaluateWorkspaceDashboardGate(history, nil, ownershipHistory, offboardingHistory, WorkspaceDashboardGatePolicy{FailOnSeverity: SeverityInfo})
	if err != nil {
		t.Fatal(err)
	}
	if !historyOnly.CurrentOwnershipReview || historyOnly.OwnershipFindingsMatched != wantOwnership {
		t.Fatalf("ownership-history-only gate = %+v; want %d ownership findings", historyOnly, wantOwnership)
	}
	if text := RenderWorkspaceDashboardGateFailure(result); !strings.Contains(text, "workspace review gate failed") || !strings.Contains(text, "exiting with status 2") {
		t.Fatalf("failure text = %q", text)
	}
}

func TestWorkspaceDashboardGateRequiresAttachedCurrentEvidence(t *testing.T) {
	history, _, _, _ := workspaceDashboardFullAuditFixture(t)
	result, err := EvaluateWorkspaceDashboardGate(history, nil, nil, nil, WorkspaceDashboardGatePolicy{
		RequireCurrentOwnership: true, RequireCompleteOffboarding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failed() || len(result.Violations) != 2 || result.CurrentOwnershipReview || result.OffboardingHistoryAttached {
		t.Fatalf("missing evidence gate = %+v", result)
	}
}

func TestWorkspaceDashboardGateRequiresFullLatestCoverage(t *testing.T) {
	plan := workspacePlanFixture(t, "scan_partial", "2026-08-13T12:00:01Z", testFingerprintA)
	plan.Snapshot.Hosts[0].Coverage = CoveragePartial
	plan.Snapshot.Hosts[0].Limitations = []string{"fixture coverage boundary"}
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
	result, err := EvaluateWorkspaceDashboardGate(history, nil, nil, nil, WorkspaceDashboardGatePolicy{RequireFullCoverage: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failed() || result.IncompleteHosts != 1 || !strings.Contains(result.Violations[0], "partial or failed") {
		t.Fatalf("coverage gate = %+v", result)
	}
}

func TestWorkspaceDashboardGateRejectsInvalidPolicyAndMismatchedEvidence(t *testing.T) {
	history, ownership, ownershipHistory, offboardingHistory := workspaceDashboardFullAuditFixture(t)
	if _, err := EvaluateWorkspaceDashboardGate(history, ownership, ownershipHistory, offboardingHistory, WorkspaceDashboardGatePolicy{FailOnSeverity: "warning"}); err == nil {
		t.Fatal("invalid severity was accepted")
	}
	otherHistory, _, _ := workspaceOwnershipFixture(t)
	if _, err := EvaluateWorkspaceDashboardGate(otherHistory, ownership, ownershipHistory, offboardingHistory, WorkspaceDashboardGatePolicy{}); err == nil {
		t.Fatal("mismatched workspace evidence was accepted")
	}
}
