package access

import (
	"fmt"
	"strings"
)

// WorkspaceDashboardGatePolicy is an opt-in local policy over the same strict
// evidence joins used by workspace dashboard HTML and CSV exports.
type WorkspaceDashboardGatePolicy struct {
	FailOnSeverity             string
	RequireFullCoverage        bool
	RequireCurrentOwnership    bool
	RequireCompleteOffboarding bool
}

type WorkspaceDashboardGateResult struct {
	FailOnSeverity             string
	SnapshotFindingsMatched    int
	OwnershipFindingsMatched   int
	IncompleteHosts            int
	CurrentOwnershipReview     bool
	OffboardingHistoryAttached bool
	IncompleteOffboarding      int
	Violations                 []string
}

func (result WorkspaceDashboardGateResult) Failed() bool {
	return len(result.Violations) > 0
}

// EvaluateWorkspaceDashboardGate reuses the dashboard projection validator so
// policy decisions can never be made over evidence that HTML/CSV would reject.
func EvaluateWorkspaceDashboardGate(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory, policy WorkspaceDashboardGatePolicy) (WorkspaceDashboardGateResult, error) {
	data, err := buildWorkspaceDashboardData(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		return WorkspaceDashboardGateResult{}, err
	}
	threshold, err := NormalizeFailOnSeverity(policy.FailOnSeverity)
	if err != nil {
		return WorkspaceDashboardGateResult{}, err
	}
	result := WorkspaceDashboardGateResult{
		FailOnSeverity:             threshold,
		IncompleteHosts:            data.Latest.Summary.HostsPartial + data.Latest.Summary.HostsFailed,
		CurrentOwnershipReview:     ownership != nil || (ownershipHistory != nil && ownershipHistory.Summary.CurrentReview),
		OffboardingHistoryAttached: offboardingHistory != nil,
	}
	if offboardingHistory != nil {
		result.IncompleteOffboarding = offboardingHistory.Summary.CurrentStillPresent + offboardingHistory.Summary.CurrentInconclusive + offboardingHistory.Summary.Stale
	}
	if threshold != "" {
		result.SnapshotFindingsMatched, err = CountFindingsAtOrAbove(data.Latest.Findings, threshold)
		if err != nil {
			return WorkspaceDashboardGateResult{}, err
		}
		ownershipFindings := currentWorkspaceOwnershipFindings(ownership, ownershipHistory, data.History.LatestScanID)
		result.OwnershipFindingsMatched, err = CountFindingsAtOrAbove(ownershipFindings, threshold)
		if err != nil {
			return WorkspaceDashboardGateResult{}, err
		}
		matched := result.SnapshotFindingsMatched + result.OwnershipFindingsMatched
		if matched > 0 {
			result.Violations = append(result.Violations, fmt.Sprintf("%d finding(s) meet severity %s or higher", matched, threshold))
		}
	}
	if policy.RequireFullCoverage && result.IncompleteHosts > 0 {
		result.Violations = append(result.Violations, fmt.Sprintf("%d latest-snapshot host(s) have partial or failed coverage", result.IncompleteHosts))
	}
	if policy.RequireCurrentOwnership && !result.CurrentOwnershipReview {
		result.Violations = append(result.Violations, "current ownership review is missing")
	}
	if policy.RequireCompleteOffboarding {
		if offboardingHistory == nil {
			result.Violations = append(result.Violations, "offboarding history is missing")
		} else if result.IncompleteOffboarding > 0 {
			result.Violations = append(result.Violations, fmt.Sprintf("%d tracked offboarding outcome(s) are stale, still present, or inconclusive", result.IncompleteOffboarding))
		}
	}
	return result, nil
}

func RenderWorkspaceDashboardGateFailure(result WorkspaceDashboardGateResult) string {
	if !result.Failed() {
		return ""
	}
	return "[sshmgr] workspace review gate failed: " + strings.Join(result.Violations, "; ") + "; exiting with status 2\n"
}

func currentWorkspaceOwnershipFindings(ownership *OwnershipReview, history *WorkspaceOwnershipHistory, latestScanID string) []Finding {
	if ownership != nil {
		return ownership.Findings
	}
	if history == nil || !history.Summary.CurrentReview {
		return nil
	}
	for index := range history.Reviews {
		if history.Reviews[index].ScanID == latestScanID {
			return history.Reviews[index].Findings
		}
	}
	return nil
}
