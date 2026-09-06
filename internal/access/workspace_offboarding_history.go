package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	WorkspaceOffboardingHistorySchemaVersion = "1"
	maxWorkspaceOffboardingHistoryBytes      = 256 << 20
)

// WorkspaceOffboardingHistory is a strict companion to the frozen
// WorkspaceHistory v1 contract. It projects validated offboarding checks onto
// one immutable workspace timeline without changing that timeline's schema.
type WorkspaceOffboardingHistory struct {
	SchemaVersion        string                             `json:"schema_version"`
	OffboardingHistoryID string                             `json:"offboarding_history_id"`
	Workspace            string                             `json:"workspace"`
	WorkspaceHistoryID   string                             `json:"workspace_history_id"`
	LatestScanID         string                             `json:"latest_scan_id"`
	Scans                []WorkspaceOffboardingScan         `json:"scans"`
	Summary              WorkspaceOffboardingHistorySummary `json:"summary"`
	Latest               []WorkspaceOffboardingLatest       `json:"latest"`
	Checks               []OffboardingCheck                 `json:"checks"`
}

type WorkspaceOffboardingScan struct {
	ScanID      string `json:"scan_id"`
	CompletedAt string `json:"completed_at"`
}

type WorkspaceOffboardingHistorySummary struct {
	Identities          int `json:"identities"`
	Checks              int `json:"checks"`
	CurrentComplete     int `json:"current_complete"`
	CurrentStillPresent int `json:"current_still_present"`
	CurrentInconclusive int `json:"current_inconclusive"`
	Stale               int `json:"stale"`
}

type WorkspaceOffboardingLatest struct {
	Identity         Identity `json:"identity"`
	CheckID          string   `json:"check_id"`
	AfterScanID      string   `json:"after_scan_id"`
	AfterCompletedAt string   `json:"after_completed_at"`
	Outcome          string   `json:"outcome"`
	Current          bool     `json:"current"`
	BaselineAccess   int      `json:"baseline_access_edges"`
	StillObserved    int      `json:"still_observed_edges"`
	NotObserved      int      `json:"not_observed_edges"`
	NewlyObserved    int      `json:"newly_observed_edges"`
	BlockingReasons  int      `json:"blocking_reasons"`
	ReasonCodes      []string `json:"reason_codes"`
}

func BuildWorkspaceOffboardingHistory(history *WorkspaceHistory, checks ...*OffboardingCheck) (*WorkspaceOffboardingHistory, error) {
	if err := ValidateWorkspaceHistory(history); err != nil {
		return nil, fmt.Errorf("workspace history: %w", err)
	}
	if len(checks) == 0 {
		return nil, errors.New("workspace offboarding history requires at least one offboarding check")
	}
	unique := make(map[string]OffboardingCheck, len(checks))
	encoded := make(map[string][]byte, len(checks))
	totalBytes := 0
	for index, check := range checks {
		if err := ValidateOffboardingCheck(check); err != nil {
			return nil, fmt.Errorf("input offboarding check %d: %w", index+1, err)
		}
		data, err := RenderOffboardingCheckJSON(check)
		if err != nil {
			return nil, fmt.Errorf("render input offboarding check %d: %w", index+1, err)
		}
		totalBytes += len(data)
		if totalBytes > maxWorkspaceOffboardingHistoryBytes {
			return nil, fmt.Errorf("workspace offboarding history input is %d bytes; limit is %d", totalBytes, maxWorkspaceOffboardingHistoryBytes)
		}
		if previous, exists := encoded[check.CheckID]; exists {
			if !bytes.Equal(previous, data) {
				return nil, fmt.Errorf("check_id %q is reused with different content", check.CheckID)
			}
			continue
		}
		var clone OffboardingCheck
		if err := json.Unmarshal(data, &clone); err != nil {
			return nil, fmt.Errorf("clone input offboarding check %d: %w", index+1, err)
		}
		unique[check.CheckID], encoded[check.CheckID] = clone, data
	}

	result := &WorkspaceOffboardingHistory{
		SchemaVersion:      WorkspaceOffboardingHistorySchemaVersion,
		Workspace:          history.Workspace,
		WorkspaceHistoryID: history.HistoryID,
		LatestScanID:       history.LatestScanID,
		Scans:              workspaceOffboardingScans(history),
		Checks:             make([]OffboardingCheck, 0, len(unique)),
	}
	for _, check := range unique {
		result.Checks = append(result.Checks, check)
	}
	normalizeWorkspaceOffboardingChecks(result)
	result.Latest = deriveWorkspaceOffboardingLatest(result)
	result.Summary = deriveWorkspaceOffboardingSummary(result.Latest, len(result.Checks))
	result.OffboardingHistoryID = workspaceOffboardingHistoryID(result)
	if err := ValidateWorkspaceOffboardingHistoryAgainstWorkspace(result, history); err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateWorkspaceOffboardingHistory(history *WorkspaceOffboardingHistory) error {
	if history == nil {
		return invalidWorkspaceOffboardingHistory("history is nil")
	}
	if history.SchemaVersion != WorkspaceOffboardingHistorySchemaVersion {
		return invalidWorkspaceOffboardingHistory("unsupported schema_version %q", history.SchemaVersion)
	}
	if err := validateWorkspaceSlug(history.Workspace); err != nil {
		return invalidWorkspaceOffboardingHistory("%v", err)
	}
	for label, value := range map[string]string{
		"offboarding_history_id": history.OffboardingHistoryID,
		"workspace_history_id":   history.WorkspaceHistoryID,
		"latest_scan_id":         history.LatestScanID,
	} {
		if err := validIdentityText(value, false); err != nil || hasUnsafeOffboardingRune(value) {
			return invalidWorkspaceOffboardingHistory("%s is invalid", label)
		}
	}
	if len(history.Scans) == 0 {
		return invalidWorkspaceOffboardingHistory("at least one workspace scan is required")
	}
	scanPositions := make(map[string]int, len(history.Scans))
	for index, scan := range history.Scans {
		if err := validIdentityText(scan.ScanID, false); err != nil || hasUnsafeOffboardingRune(scan.ScanID) {
			return invalidWorkspaceOffboardingHistory("scans[%d].scan_id is invalid", index)
		}
		completed, err := time.Parse(time.RFC3339Nano, scan.CompletedAt)
		if err != nil {
			return invalidWorkspaceOffboardingHistory("scans[%d].completed_at is invalid", index)
		}
		if _, exists := scanPositions[scan.ScanID]; exists {
			return invalidWorkspaceOffboardingHistory("duplicate scan_id %q", scan.ScanID)
		}
		if index > 0 {
			previous := history.Scans[index-1]
			previousTime, _ := time.Parse(time.RFC3339Nano, previous.CompletedAt)
			if previousTime.After(completed) || previousTime.Equal(completed) && previous.ScanID >= scan.ScanID {
				return invalidWorkspaceOffboardingHistory("scans are not in canonical chronological order")
			}
		}
		scanPositions[scan.ScanID] = index
	}
	if history.LatestScanID != history.Scans[len(history.Scans)-1].ScanID {
		return invalidWorkspaceOffboardingHistory("latest_scan_id does not match the workspace timeline")
	}
	if history.Checks == nil || len(history.Checks) == 0 {
		return invalidWorkspaceOffboardingHistory("at least one offboarding check is required")
	}
	seenChecks := make(map[string]struct{}, len(history.Checks))
	seenIdentityScan := make(map[string]string, len(history.Checks))
	previousOrder := ""
	for index := range history.Checks {
		check := &history.Checks[index]
		if err := ValidateOffboardingCheck(check); err != nil {
			return invalidWorkspaceOffboardingHistory("checks[%d]: %v", index, err)
		}
		beforePosition, beforeExists := scanPositions[check.BeforeScanID]
		afterPosition, afterExists := scanPositions[check.AfterScanID]
		if !beforeExists || !afterExists {
			return invalidWorkspaceOffboardingHistory("checks[%d] references a scan outside the workspace history", index)
		}
		if beforePosition >= afterPosition {
			return invalidWorkspaceOffboardingHistory("checks[%d] does not move forward in the workspace timeline", index)
		}
		if _, exists := seenChecks[check.CheckID]; exists {
			return invalidWorkspaceOffboardingHistory("duplicate check_id %q", check.CheckID)
		}
		seenChecks[check.CheckID] = struct{}{}
		identityScan := check.Identity.ID + "\x00" + check.AfterScanID
		if previous, exists := seenIdentityScan[identityScan]; exists {
			return invalidWorkspaceOffboardingHistory("identity %q has ambiguous checks %q and %q for after scan %q", check.Identity.ID, previous, check.CheckID, check.AfterScanID)
		}
		seenIdentityScan[identityScan] = check.CheckID
		order := fmt.Sprintf("%012d\x00%s\x00%s", afterPosition, check.Identity.ID, check.CheckID)
		if previousOrder != "" && order <= previousOrder {
			return invalidWorkspaceOffboardingHistory("checks are not in canonical workspace/identity order")
		}
		previousOrder = order
	}
	expectedLatest := deriveWorkspaceOffboardingLatest(history)
	if !reflect.DeepEqual(history.Latest, expectedLatest) {
		return invalidWorkspaceOffboardingHistory("latest identity outcomes do not reconcile")
	}
	expectedSummary := deriveWorkspaceOffboardingSummary(expectedLatest, len(history.Checks))
	if history.Summary != expectedSummary {
		return invalidWorkspaceOffboardingHistory("summary does not reconcile")
	}
	if expectedID := workspaceOffboardingHistoryID(history); history.OffboardingHistoryID != expectedID {
		return invalidWorkspaceOffboardingHistory("offboarding_history_id does not match content")
	}
	encoded, err := json.Marshal(history)
	if err != nil {
		return invalidWorkspaceOffboardingHistory("cannot encode content: %v", err)
	}
	if len(encoded) > maxWorkspaceOffboardingHistoryBytes {
		return invalidWorkspaceOffboardingHistory("encoded content is %d bytes; limit is %d", len(encoded), maxWorkspaceOffboardingHistoryBytes)
	}
	if err := rejectForbiddenUploadMaterial(encoded); err != nil {
		return invalidWorkspaceOffboardingHistory("privacy boundary: %v", err)
	}
	return nil
}

func ValidateWorkspaceOffboardingHistoryAgainstWorkspace(offboarding *WorkspaceOffboardingHistory, history *WorkspaceHistory) error {
	if err := ValidateWorkspaceOffboardingHistory(offboarding); err != nil {
		return err
	}
	if err := ValidateWorkspaceHistory(history); err != nil {
		return err
	}
	if offboarding.Workspace != history.Workspace || offboarding.WorkspaceHistoryID != history.HistoryID ||
		offboarding.LatestScanID != history.LatestScanID || !reflect.DeepEqual(offboarding.Scans, workspaceOffboardingScans(history)) {
		return errors.New("workspace offboarding history does not reconcile with the selected workspace history")
	}
	return nil
}

func RenderWorkspaceOffboardingHistoryJSON(history *WorkspaceOffboardingHistory) ([]byte, error) {
	if err := ValidateWorkspaceOffboardingHistory(history); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal workspace offboarding history: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxWorkspaceOffboardingHistoryBytes {
		return nil, fmt.Errorf("workspace offboarding history is %d bytes; limit is %d", len(data), maxWorkspaceOffboardingHistoryBytes)
	}
	return data, nil
}

func WriteWorkspaceOffboardingHistory(path string, history *WorkspaceOffboardingHistory) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("workspace offboarding history output path is empty")
	}
	data, err := RenderWorkspaceOffboardingHistoryJSON(history)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadWorkspaceOffboardingHistory(path string) (*WorkspaceOffboardingHistory, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace offboarding history %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > maxWorkspaceOffboardingHistoryBytes {
		return nil, fmt.Errorf("workspace offboarding history is %d bytes; limit is %d", stat.Size(), maxWorkspaceOffboardingHistoryBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceOffboardingHistoryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read workspace offboarding history: %w", err)
	}
	if len(data) > maxWorkspaceOffboardingHistoryBytes {
		return nil, fmt.Errorf("workspace offboarding history exceeds %d bytes", maxWorkspaceOffboardingHistoryBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var history WorkspaceOffboardingHistory
	if err := decoder.Decode(&history); err != nil {
		return nil, fmt.Errorf("parse workspace offboarding history: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("workspace offboarding history contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing workspace offboarding history data: %w", err)
	}
	if err := ValidateWorkspaceOffboardingHistory(&history); err != nil {
		return nil, err
	}
	return &history, nil
}

func RenderWorkspaceOffboardingHistoryText(history *WorkspaceOffboardingHistory) string {
	if history == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Offline Cloud offboarding history  %s\n\n", history.OffboardingHistoryID)
	fmt.Fprintf(&output, "Workspace:         %s\n", history.Workspace)
	fmt.Fprintf(&output, "Workspace history: %s\n", history.WorkspaceHistoryID)
	fmt.Fprintf(&output, "Checks / identities: %d / %d\n", history.Summary.Checks, history.Summary.Identities)
	fmt.Fprintf(&output, "Current complete / present / inconclusive: %d / %d / %d\n", history.Summary.CurrentComplete, history.Summary.CurrentStillPresent, history.Summary.CurrentInconclusive)
	fmt.Fprintf(&output, "Stale identities:  %d\n", history.Summary.Stale)
	fmt.Fprintln(&output, "Network activity:  none")
	fmt.Fprintln(&output, "\nLatest identity outcomes")
	for _, latest := range history.Latest {
		freshness := "current"
		if !latest.Current {
			freshness = "STALE"
		}
		fmt.Fprintf(&output, "  %s  %s  %s  after=%s  blocking=%d\n", latest.Identity.ID, latest.Outcome, freshness, latest.AfterScanID, latest.BlockingReasons)
	}
	fmt.Fprintln(&output, "\nThis is a private local read-only artifact; Cloud upload and remediation remain disabled.")
	return output.String()
}

func workspaceOffboardingScans(history *WorkspaceHistory) []WorkspaceOffboardingScan {
	values := make([]WorkspaceOffboardingScan, 0, len(history.Artifacts))
	for _, artifact := range history.Artifacts {
		values = append(values, WorkspaceOffboardingScan{ScanID: artifact.ScanID, CompletedAt: artifact.CompletedAt})
	}
	return values
}

func normalizeWorkspaceOffboardingChecks(history *WorkspaceOffboardingHistory) {
	positions := make(map[string]int, len(history.Scans))
	for index, scan := range history.Scans {
		positions[scan.ScanID] = index
	}
	sort.Slice(history.Checks, func(i, j int) bool {
		left, right := history.Checks[i], history.Checks[j]
		if positions[left.AfterScanID] != positions[right.AfterScanID] {
			return positions[left.AfterScanID] < positions[right.AfterScanID]
		}
		if left.Identity.ID != right.Identity.ID {
			return left.Identity.ID < right.Identity.ID
		}
		return left.CheckID < right.CheckID
	})
}

func deriveWorkspaceOffboardingLatest(history *WorkspaceOffboardingHistory) []WorkspaceOffboardingLatest {
	completed := make(map[string]string, len(history.Scans))
	latestChecks := make(map[string]OffboardingCheck)
	for _, scan := range history.Scans {
		completed[scan.ScanID] = scan.CompletedAt
	}
	for _, check := range history.Checks {
		latestChecks[check.Identity.ID] = check
	}
	identities := make([]string, 0, len(latestChecks))
	for identityID := range latestChecks {
		identities = append(identities, identityID)
	}
	sort.Strings(identities)
	values := make([]WorkspaceOffboardingLatest, 0, len(identities))
	for _, identityID := range identities {
		check := latestChecks[identityID]
		reasonCodes := make([]string, 0, len(check.Reasons))
		for _, reason := range check.Reasons {
			reasonCodes = append(reasonCodes, reason.Code)
		}
		values = append(values, WorkspaceOffboardingLatest{
			Identity: check.Identity, CheckID: check.CheckID, AfterScanID: check.AfterScanID,
			AfterCompletedAt: completed[check.AfterScanID], Outcome: check.Outcome,
			Current:        check.AfterScanID == history.LatestScanID,
			BaselineAccess: check.Summary.BaselineAccess, StillObserved: check.Summary.StillObserved,
			NotObserved: check.Summary.NotObserved, NewlyObserved: check.Summary.NewlyObserved,
			BlockingReasons: check.Summary.BlockingReasons, ReasonCodes: reasonCodes,
		})
	}
	return values
}

func deriveWorkspaceOffboardingSummary(latest []WorkspaceOffboardingLatest, checks int) WorkspaceOffboardingHistorySummary {
	summary := WorkspaceOffboardingHistorySummary{Identities: len(latest), Checks: checks}
	for _, status := range latest {
		if !status.Current {
			summary.Stale++
			continue
		}
		switch status.Outcome {
		case OffboardingOutcomeComplete:
			summary.CurrentComplete++
		case OffboardingOutcomePresent:
			summary.CurrentStillPresent++
		case OffboardingOutcomeUnknown:
			summary.CurrentInconclusive++
		}
	}
	return summary
}

func workspaceOffboardingHistoryID(history *WorkspaceOffboardingHistory) string {
	clone := *history
	clone.OffboardingHistoryID = ""
	data, _ := json.Marshal(clone)
	hash := sha256.Sum256(data)
	return "offboarding_history_" + hex.EncodeToString(hash[:12])
}

func invalidWorkspaceOffboardingHistory(format string, args ...any) error {
	return fmt.Errorf("invalid workspace offboarding history v%s: %s", WorkspaceOffboardingHistorySchemaVersion, fmt.Sprintf(format, args...))
}
