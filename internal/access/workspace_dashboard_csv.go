package access

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var workspaceDashboardCSVHeader = []string{
	"row_type", "workspace", "history_id", "scan_id", "completed_at", "current",
	"review_id", "check_id", "action", "severity", "rule_id", "identity",
	"identity_status", "verification", "fingerprint", "algorithm", "bits",
	"host", "coverage", "account", "source", "line", "before_value",
	"after_value", "outcome", "details",
}

type workspaceDashboardCSVRow struct {
	category int
	key      string
	values   []string
}

func RenderWorkspaceDashboardCSVWithAuditEvidence(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) ([]byte, error) {
	data, err := buildWorkspaceDashboardData(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		return nil, err
	}
	rows := buildWorkspaceDashboardCSVRows(data)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].category != rows[j].category {
			return rows[i].category < rows[j].category
		}
		if rows[i].key != rows[j].key {
			return rows[i].key < rows[j].key
		}
		return strings.Join(rows[i].values, "\x00") < strings.Join(rows[j].values, "\x00")
	})
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	if err := writer.Write(workspaceDashboardCSVHeader); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if len(row.values) != len(workspaceDashboardCSVHeader) {
			return nil, fmt.Errorf("workspace dashboard CSV row %q has %d columns; expected %d", row.values[0], len(row.values), len(workspaceDashboardCSVHeader))
		}
		for index := range row.values {
			row.values[index] = spreadsheetSafeCSVCell(row.values[index])
		}
		if err := writer.Write(row.values); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	if output.Len() > maxWorkspaceDashboardBytes {
		return nil, fmt.Errorf("workspace dashboard CSV is %d bytes; limit is %d", output.Len(), maxWorkspaceDashboardBytes)
	}
	return output.Bytes(), nil
}

func WriteWorkspaceDashboardCSVWithAuditEvidence(path string, history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("workspace dashboard CSV output path is empty")
	}
	data, err := RenderWorkspaceDashboardCSVWithAuditEvidence(history, ownership, ownershipHistory, offboardingHistory)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func buildWorkspaceDashboardCSVRows(data *workspaceDashboardData) []workspaceDashboardCSVRow {
	var rows []workspaceDashboardCSVRow
	appendRow := func(category int, key string, values ...string) {
		rows = append(rows, workspaceDashboardCSVRow{category: category, key: key, values: values})
	}
	base := func(rowType, scanID, completedAt string, current bool) []string {
		return []string{rowType, data.History.Workspace, data.History.HistoryID, scanID, completedAt, strconv.FormatBool(current)}
	}
	latestCompletedAt := data.Latest.CompletedAt
	summary := base("workspace_summary", data.Latest.ScanID, latestCompletedAt, true)
	summary = append(summary, ownershipReviewIDOrEmpty(data.Ownership), "", "snapshot", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", fmt.Sprintf("hosts=%d;full=%d;partial=%d;failed=%d;accounts=%d;entries=%d;keys=%d;findings=%d", data.Latest.Summary.HostsRequested, data.Latest.Summary.HostsFull, data.Latest.Summary.HostsPartial, data.Latest.Summary.HostsFailed, data.Latest.Summary.AccountsObserved, data.Latest.Summary.AuthorizedKeyEntries, data.Latest.Summary.UniqueFingerprints, data.Latest.Summary.FindingsTotal))
	appendRow(0, "summary", summary...)

	for _, host := range data.Coverage {
		record := base("host_coverage", data.Latest.ScanID, latestCompletedAt, true)
		record = append(record, "", "", "", "", "", "", "", "", "", "", "", host.Alias, host.Coverage, "", "", "", "", "", "", fmt.Sprintf("accounts=%d;entries=%d", host.Accounts, host.Entries))
		appendRow(10, host.Alias, record...)
	}
	for _, finding := range data.Latest.Findings {
		record := base("finding", data.Latest.ScanID, latestCompletedAt, true)
		record = append(record, "", "", "", finding.Severity, finding.RuleID, "", "", "", finding.Fingerprint, "", "", finding.Host, workspaceFindingCoverageForScan(data, data.Latest.ScanID, finding.Host), finding.Account, "", "", "", "", "", workspaceFindingDetails(finding))
		appendRow(20, finding.RuleID+"\x00"+finding.Host+"\x00"+finding.Account+"\x00"+finding.Fingerprint, record...)
	}
	if data.Ownership != nil {
		for _, finding := range data.Ownership.Findings {
			record := base("ownership_finding", data.Latest.ScanID, latestCompletedAt, true)
			record = append(record, data.Ownership.ReviewID, "", "", finding.Severity, finding.RuleID, "", "", "", finding.Fingerprint, "", "", finding.Host, workspaceFindingCoverageForScan(data, data.Latest.ScanID, finding.Host), finding.Account, "", "", "", "", "", workspaceFindingDetails(finding))
			appendRow(30, finding.RuleID+"\x00"+finding.Fingerprint, record...)
		}
	}
	for _, key := range data.Keys {
		identities, statuses, verifications, _ := ownershipClaimColumns(key.Claims)
		for _, edge := range key.Access {
			record := base("access_edge", data.Latest.ScanID, latestCompletedAt, true)
			ownershipStatus := key.OwnershipStatus
			if ownershipStatus == "" {
				ownershipStatus = "not_attached"
			}
			record = append(record, ownershipReviewIDOrEmpty(data.Ownership), "", "observed", "", "", strings.Join(identities, ";"), strings.Join(statuses, ";"), strings.Join(verifications, ";"), key.Fingerprint, key.Algorithm, strconv.Itoa(key.Bits), edge.Host, edge.Coverage, edge.Account, edge.Source, strconv.Itoa(edge.Line), "", "", "", "ownership="+ownershipStatus)
			appendRow(40, edge.Host+"\x00"+edge.Account+"\x00"+key.Fingerprint+"\x00"+edge.Source+fmt.Sprintf("\x00%012d", edge.Line), record...)
		}
	}
	completed := make(map[string]string, len(data.History.Artifacts))
	for _, artifact := range data.History.Artifacts {
		completed[artifact.ScanID] = artifact.CompletedAt
	}
	for _, transition := range data.History.Transitions {
		for _, change := range []struct {
			action string
			edges  []AccessEdge
		}{{"added", transition.Added}, {"removed", transition.Removed}} {
			for _, edge := range change.edges {
				record := base("access_change", transition.AfterScanID, completed[transition.AfterScanID], transition.AfterScanID == data.History.LatestScanID)
				record = append(record, "", "", change.action, "", "", "", "", "", edge.Fingerprint, edge.Algorithm, strconv.Itoa(edge.Bits), edge.Host, "", edge.Account, "", "", transition.BeforeScanID, transition.AfterScanID, "", "")
				appendRow(50, transition.AfterScanID+"\x00"+change.action+"\x00"+edge.Host+"\x00"+edge.Account+"\x00"+edge.Fingerprint, record...)
			}
		}
		for _, change := range transition.CoverageChanges {
			record := base("coverage_change", transition.AfterScanID, completed[transition.AfterScanID], transition.AfterScanID == data.History.LatestScanID)
			record = append(record, "", "", "changed", "", "", "", "", "", "", "", "", change.Host, change.After, "", "", "", change.Before, change.After, "", "")
			appendRow(60, transition.AfterScanID+"\x00"+change.Host, record...)
		}
	}
	appendWorkspaceOwnershipCSVRows(&rows, data, base, completed)
	appendWorkspaceOffboardingCSVRows(&rows, data, base, completed)
	return rows
}

func appendWorkspaceOwnershipCSVRows(rows *[]workspaceDashboardCSVRow, data *workspaceDashboardData, base func(string, string, string, bool) []string, completed map[string]string) {
	if data.OwnershipHistory == nil {
		return
	}
	appendRow := func(category int, key string, values ...string) {
		*rows = append(*rows, workspaceDashboardCSVRow{category: category, key: key, values: values})
	}
	for _, scan := range data.OwnershipHistory.Scans {
		action := "missing"
		if scan.Reviewed {
			action = "reviewed"
		}
		record := base("ownership_review_coverage", scan.ScanID, scan.CompletedAt, scan.ScanID == data.History.LatestScanID)
		record = append(record, scan.ReviewID, "", action, "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "review_sha256="+scan.ReviewSHA256)
		appendRow(65, scan.ScanID, record...)
	}
	for _, review := range data.OwnershipHistory.Reviews {
		record := base("ownership_review", review.ScanID, completed[review.ScanID], review.ScanID == data.History.LatestScanID)
		record = append(record, review.ReviewID, "", "reviewed", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", fmt.Sprintf("active=%d;offboarded=%d;owned=%d;unknown=%d;shared=%d", review.Summary.ActiveIdentities, review.Summary.OffboardedIdentities, review.Summary.OwnedKeys, review.Summary.UnknownKeys, review.Summary.SharedKeys))
		appendRow(70, review.ScanID, record...)
		for _, finding := range review.Findings {
			record := base("ownership_history_finding", review.ScanID, completed[review.ScanID], review.ScanID == data.History.LatestScanID)
			record = append(record, review.ReviewID, "", "", finding.Severity, finding.RuleID, "", "", "", finding.Fingerprint, "", "", finding.Host, workspaceFindingCoverageForScan(data, review.ScanID, finding.Host), finding.Account, "", "", "", "", "", workspaceFindingDetails(finding))
			appendRow(75, review.ScanID+"\x00"+finding.RuleID+"\x00"+finding.Fingerprint, record...)
		}
	}
	for _, transition := range data.OwnershipHistory.Transitions {
		current := transition.AfterScanID == data.History.LatestScanID
		for _, change := range transition.IdentityChanges {
			record := base("identity_change", transition.AfterScanID, completed[transition.AfterScanID], current)
			record = append(record, transition.AfterReviewID, "", change.Action, "", "", change.IdentityID, identityStatus(change.After, change.Before), "", "", "", "", "", "", "", "", "", formatIdentity(change.Before), formatIdentity(change.After), "", "")
			appendRow(80, transition.AfterScanID+"\x00"+change.IdentityID, record...)
		}
		for _, change := range transition.ClaimChanges {
			record := base("claim_change", transition.AfterScanID, completed[transition.AfterScanID], current)
			record = append(record, transition.AfterReviewID, "", change.Action, "", "", change.IdentityID, claimIdentityStatus(change.After, change.Before), claimVerification(change.After, change.Before), change.Fingerprint, "", "", "", "", "", "", "", formatClaim(change.Before), formatClaim(change.After), "", "")
			appendRow(90, transition.AfterScanID+"\x00"+change.Fingerprint+"\x00"+change.IdentityID, record...)
		}
		for _, change := range transition.KeyChanges {
			record := base("key_state_change", transition.AfterScanID, completed[transition.AfterScanID], current)
			record = append(record, transition.AfterReviewID, "", change.Action, "", "", "", "", "", change.Fingerprint, keyAlgorithm(change.After, change.Before), keyBits(change.After, change.Before), "", "", "", "", "", formatReviewedKey(change.Before), formatReviewedKey(change.After), "", "")
			appendRow(100, transition.AfterScanID+"\x00"+change.Fingerprint, record...)
		}
	}
}

func appendWorkspaceOffboardingCSVRows(rows *[]workspaceDashboardCSVRow, data *workspaceDashboardData, base func(string, string, string, bool) []string, completed map[string]string) {
	if data.OffboardingHistory == nil {
		return
	}
	appendRow := func(category int, key string, values ...string) {
		*rows = append(*rows, workspaceDashboardCSVRow{category: category, key: key, values: values})
	}
	checks := make(map[string]OffboardingCheck, len(data.OffboardingHistory.Checks))
	for _, check := range data.OffboardingHistory.Checks {
		checks[check.CheckID] = check
	}
	for _, latest := range data.OffboardingHistory.Latest {
		check := checks[latest.CheckID]
		record := base("offboarding_outcome", latest.AfterScanID, latest.AfterCompletedAt, latest.Current)
		record = append(record, check.AfterReviewID, latest.CheckID, "checked", "", "", latest.Identity.ID, latest.Identity.Status, "", "", "", "", "", "", "", "", "", check.BeforeScanID, latest.AfterScanID, latest.Outcome, fmt.Sprintf("baseline=%d;still=%d;not_observed=%d;new=%d;blocking=%d;reasons=%s", latest.BaselineAccess, latest.StillObserved, latest.NotObserved, latest.NewlyObserved, latest.BlockingReasons, strings.Join(latest.ReasonCodes, ";")))
		appendRow(110, latest.Identity.ID, record...)
	}
	for _, check := range data.OffboardingHistory.Checks {
		groups := []struct {
			classification string
			edges          []OffboardingCheckEdge
		}{{"still_observed", check.StillObserved}, {"not_observed", check.NotObserved}, {"newly_observed", check.NewlyObserved}}
		for _, group := range groups {
			for _, edge := range group.edges {
				for _, evidence := range edge.Evidence {
					record := base("offboarding_evidence", check.AfterScanID, completed[check.AfterScanID], check.AfterScanID == data.History.LatestScanID)
					record = append(record, check.AfterReviewID, check.CheckID, group.classification, "", "", check.Identity.ID, check.Identity.Status, "", edge.Fingerprint, "", "", edge.Host, evidence.Coverage, edge.Account, evidence.Source, strconv.Itoa(evidence.Line), check.BeforeScanID, check.AfterScanID, check.Outcome, "options="+strings.Join(evidence.Options, ";"))
					appendRow(120, check.AfterScanID+"\x00"+check.Identity.ID+"\x00"+group.classification+"\x00"+edge.Host+"\x00"+edge.Account+"\x00"+edge.Fingerprint+"\x00"+evidence.Source+fmt.Sprintf("\x00%012d", evidence.Line), record...)
				}
			}
		}
	}
}

func ownershipReviewIDOrEmpty(review *OwnershipReview) string {
	if review == nil {
		return ""
	}
	return review.ReviewID
}

func workspaceFindingCoverageForScan(data *workspaceDashboardData, scanID, host string) string {
	if host == "" {
		return ""
	}
	for index := range data.History.Plans {
		if data.History.Plans[index].ArtifactID != scanID {
			continue
		}
		for _, value := range data.History.Plans[index].Snapshot.Hosts {
			if value.Alias == host {
				return value.Coverage
			}
		}
		break
	}
	return ""
}

func workspaceFindingDetails(finding Finding) string {
	parts := []string{finding.Title}
	parts = append(parts, finding.Evidence...)
	if finding.Occurrences > 0 {
		parts = append(parts, fmt.Sprintf("occurrences: %d", finding.Occurrences))
	}
	if len(finding.Hosts) > 0 {
		parts = append(parts, "hosts: "+strings.Join(finding.Hosts, ";"))
	}
	if finding.CoverageCaveat != "" {
		parts = append(parts, "caveat: "+finding.CoverageCaveat)
	}
	if finding.RecommendedAction != "" {
		parts = append(parts, "action: "+finding.RecommendedAction)
	}
	return strings.Join(parts, " | ")
}

func identityStatus(values ...*Identity) string {
	for _, value := range values {
		if value != nil {
			return value.Status
		}
	}
	return ""
}

func formatIdentity(value *Identity) string {
	if value == nil {
		return ""
	}
	return strings.Join([]string{value.ID, value.DisplayName, value.Kind, value.Status}, ";")
}

func claimIdentityStatus(values ...*WorkspaceOwnershipClaimState) string {
	for _, value := range values {
		if value != nil {
			return value.Claim.IdentityStatus
		}
	}
	return ""
}

func claimVerification(values ...*WorkspaceOwnershipClaimState) string {
	for _, value := range values {
		if value != nil {
			return value.Claim.Verification
		}
	}
	return ""
}

func formatClaim(value *WorkspaceOwnershipClaimState) string {
	if value == nil {
		return ""
	}
	claim := value.Claim
	return strings.Join([]string{claim.IdentityID, claim.IdentityStatus, claim.Verification, claim.Source, claim.RecordedAt, claim.VerifiedAt}, ";")
}

func keyAlgorithm(values ...*WorkspaceReviewedKeyState) string {
	for _, value := range values {
		if value != nil {
			return value.Algorithm
		}
	}
	return ""
}

func keyBits(values ...*WorkspaceReviewedKeyState) string {
	for _, value := range values {
		if value != nil {
			return strconv.Itoa(value.Bits)
		}
	}
	return ""
}

func formatReviewedKey(value *WorkspaceReviewedKeyState) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("ownership=%s;observed=%t;edges=%d;offboarded=%t;verified=%t;hosts=%s;accounts=%s", value.OwnershipStatus, value.Observed, value.Occurrences, value.OffboardedAccess, value.PossessionVerified, strings.Join(value.Hosts, ";"), strings.Join(value.Accounts, ";"))
}
