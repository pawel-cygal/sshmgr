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
	WorkspaceOwnershipHistorySchemaVersion = "1"
	maxWorkspaceOwnershipHistoryBytes      = 256 << 20

	WorkspaceOwnershipChangeAdded   = "added"
	WorkspaceOwnershipChangeRemoved = "removed"
	WorkspaceOwnershipChangeChanged = "changed"
)

// WorkspaceOwnershipHistory is a strict, privacy-normalized companion to one
// frozen WorkspaceHistory v1 timeline. It never contains raw public keys or
// unverified authorized_keys comments.
type WorkspaceOwnershipHistory struct {
	SchemaVersion      string                           `json:"schema_version"`
	OwnershipHistoryID string                           `json:"ownership_history_id"`
	Workspace          string                           `json:"workspace"`
	WorkspaceHistoryID string                           `json:"workspace_history_id"`
	LatestScanID       string                           `json:"latest_scan_id"`
	Scans              []WorkspaceOwnershipScan         `json:"scans"`
	Summary            WorkspaceOwnershipHistorySummary `json:"summary"`
	Latest             WorkspaceOwnershipLatest         `json:"latest"`
	Reviews            []OwnershipReview                `json:"reviews"`
	Transitions        []WorkspaceOwnershipTransition   `json:"transitions,omitempty"`
}

type WorkspaceOwnershipScan struct {
	ScanID       string `json:"scan_id"`
	CompletedAt  string `json:"completed_at"`
	Reviewed     bool   `json:"reviewed"`
	ReviewID     string `json:"review_id,omitempty"`
	ReviewSHA256 string `json:"review_sha256,omitempty"`
}

type WorkspaceOwnershipHistorySummary struct {
	Scans         int  `json:"scans"`
	ReviewedScans int  `json:"reviewed_scans"`
	MissingScans  int  `json:"missing_scans"`
	CurrentReview bool `json:"current_review"`
}

type WorkspaceOwnershipLatest struct {
	ReviewID          string           `json:"review_id"`
	ReviewSHA256      string           `json:"review_sha256"`
	ScanID            string           `json:"scan_id"`
	CompletedAt       string           `json:"completed_at"`
	Current           bool             `json:"current"`
	IdentityMapDigest string           `json:"identity_map_digest"`
	Summary           OwnershipSummary `json:"summary"`
}

type WorkspaceOwnershipTransition struct {
	BeforeReviewID  string                          `json:"before_review_id"`
	AfterReviewID   string                          `json:"after_review_id"`
	BeforeScanID    string                          `json:"before_scan_id"`
	AfterScanID     string                          `json:"after_scan_id"`
	IdentityChanges []WorkspaceIdentityChange       `json:"identity_changes,omitempty"`
	ClaimChanges    []WorkspaceOwnershipClaimChange `json:"claim_changes,omitempty"`
	KeyChanges      []WorkspaceReviewedKeyChange    `json:"key_changes,omitempty"`
}

type WorkspaceIdentityChange struct {
	Action     string    `json:"action"`
	IdentityID string    `json:"identity_id"`
	Before     *Identity `json:"before,omitempty"`
	After      *Identity `json:"after,omitempty"`
}

type WorkspaceOwnershipClaimState struct {
	Fingerprint string                 `json:"fingerprint"`
	Claim       ResolvedOwnershipClaim `json:"claim"`
}

type WorkspaceOwnershipClaimChange struct {
	Action      string                        `json:"action"`
	Fingerprint string                        `json:"fingerprint"`
	IdentityID  string                        `json:"identity_id"`
	Before      *WorkspaceOwnershipClaimState `json:"before,omitempty"`
	After       *WorkspaceOwnershipClaimState `json:"after,omitempty"`
}

type WorkspaceReviewedKeyState struct {
	Fingerprint        string   `json:"fingerprint"`
	Observed           bool     `json:"observed"`
	IdentityMapEntry   bool     `json:"identity_map_entry"`
	OwnershipStatus    string   `json:"ownership_status"`
	OffboardedAccess   bool     `json:"offboarded_access"`
	PossessionVerified bool     `json:"possession_verified"`
	Algorithm          string   `json:"algorithm,omitempty"`
	Bits               int      `json:"bits,omitempty"`
	Occurrences        int      `json:"occurrences"`
	Hosts              []string `json:"hosts,omitempty"`
	Accounts           []string `json:"accounts,omitempty"`
}

type WorkspaceReviewedKeyChange struct {
	Action      string                     `json:"action"`
	Fingerprint string                     `json:"fingerprint"`
	Before      *WorkspaceReviewedKeyState `json:"before,omitempty"`
	After       *WorkspaceReviewedKeyState `json:"after,omitempty"`
}

func BuildWorkspaceOwnershipHistory(history *WorkspaceHistory, reviews ...*OwnershipReview) (*WorkspaceOwnershipHistory, error) {
	if err := ValidateWorkspaceHistory(history); err != nil {
		return nil, fmt.Errorf("workspace history: %w", err)
	}
	if len(reviews) == 0 {
		return nil, errors.New("workspace ownership history requires at least one ownership review")
	}
	snapshots := workspaceSnapshotsByScan(history)
	unique := make(map[string]OwnershipReview, len(reviews))
	sourceDigests := make(map[string]string, len(reviews))
	totalBytes := 0
	for index, review := range reviews {
		if err := ValidateOwnershipReview(review); err != nil {
			return nil, fmt.Errorf("input ownership review %d: %w", index+1, err)
		}
		snapshot := snapshots[review.ScanID]
		if snapshot == nil {
			return nil, fmt.Errorf("input ownership review %d references scan %q outside the workspace history", index+1, review.ScanID)
		}
		if err := ValidateOwnershipReviewAgainstSnapshot(review, snapshot); err != nil {
			return nil, fmt.Errorf("input ownership review %d: %w", index+1, err)
		}
		sourceDigest, err := offboardingDigest(review)
		if err != nil {
			return nil, fmt.Errorf("digest input ownership review %d: %w", index+1, err)
		}
		clone, err := privacyNormalizeWorkspaceOwnershipReview(review)
		if err != nil {
			return nil, fmt.Errorf("normalize input ownership review %d: %w", index+1, err)
		}
		data, err := RenderOwnershipReviewJSON(clone)
		if err != nil {
			return nil, fmt.Errorf("render input ownership review %d: %w", index+1, err)
		}
		totalBytes += len(data)
		if totalBytes > maxWorkspaceOwnershipHistoryBytes {
			return nil, fmt.Errorf("workspace ownership history input is %d bytes; limit is %d", totalBytes, maxWorkspaceOwnershipHistoryBytes)
		}
		if previous, exists := unique[clone.ScanID]; exists {
			if !reflect.DeepEqual(previous, *clone) || sourceDigests[clone.ScanID] != sourceDigest {
				return nil, fmt.Errorf("scan_id %q has conflicting ownership reviews %q and %q", clone.ScanID, previous.ReviewID, clone.ReviewID)
			}
			continue
		}
		unique[clone.ScanID] = *clone
		sourceDigests[clone.ScanID] = sourceDigest
	}

	result := &WorkspaceOwnershipHistory{
		SchemaVersion: WorkspaceOwnershipHistorySchemaVersion,
		Workspace:     history.Workspace, WorkspaceHistoryID: history.HistoryID,
		LatestScanID: history.LatestScanID,
	}
	for _, artifact := range history.Artifacts {
		review, reviewed := unique[artifact.ScanID]
		scan := WorkspaceOwnershipScan{ScanID: artifact.ScanID, CompletedAt: artifact.CompletedAt, Reviewed: reviewed}
		if reviewed {
			scan.ReviewID = review.ReviewID
			scan.ReviewSHA256 = sourceDigests[artifact.ScanID]
			result.Reviews = append(result.Reviews, review)
		}
		result.Scans = append(result.Scans, scan)
	}
	result.Latest = deriveWorkspaceOwnershipLatest(result)
	result.Summary = deriveWorkspaceOwnershipSummary(result)
	result.Transitions = deriveWorkspaceOwnershipTransitions(result.Reviews)
	result.OwnershipHistoryID = workspaceOwnershipHistoryID(result)
	if err := ValidateWorkspaceOwnershipHistoryAgainstWorkspace(result, history); err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateWorkspaceOwnershipHistory(history *WorkspaceOwnershipHistory) error {
	if history == nil {
		return invalidWorkspaceOwnershipHistory("history is nil")
	}
	if history.SchemaVersion != WorkspaceOwnershipHistorySchemaVersion {
		return invalidWorkspaceOwnershipHistory("unsupported schema_version %q", history.SchemaVersion)
	}
	if err := validateWorkspaceSlug(history.Workspace); err != nil {
		return invalidWorkspaceOwnershipHistory("%v", err)
	}
	for label, value := range map[string]string{
		"ownership_history_id": history.OwnershipHistoryID,
		"workspace_history_id": history.WorkspaceHistoryID,
		"latest_scan_id":       history.LatestScanID,
	} {
		if err := validIdentityText(value, false); err != nil || hasUnsafeOffboardingRune(value) {
			return invalidWorkspaceOwnershipHistory("%s is invalid", label)
		}
	}
	if len(history.Scans) == 0 || len(history.Reviews) == 0 {
		return invalidWorkspaceOwnershipHistory("at least one workspace scan and ownership review are required")
	}
	scanPositions := make(map[string]int, len(history.Scans))
	for index, scan := range history.Scans {
		if err := validIdentityText(scan.ScanID, false); err != nil || hasUnsafeOffboardingRune(scan.ScanID) {
			return invalidWorkspaceOwnershipHistory("scans[%d].scan_id is invalid", index)
		}
		completed, err := time.Parse(time.RFC3339Nano, scan.CompletedAt)
		if err != nil {
			return invalidWorkspaceOwnershipHistory("scans[%d].completed_at is invalid", index)
		}
		if _, exists := scanPositions[scan.ScanID]; exists {
			return invalidWorkspaceOwnershipHistory("duplicate scan_id %q", scan.ScanID)
		}
		if scan.Reviewed != (scan.ReviewID != "" && scan.ReviewSHA256 != "") {
			return invalidWorkspaceOwnershipHistory("scans[%d] review marker does not reconcile", index)
		}
		if scan.ReviewSHA256 != "" && !validOffboardingDigest(scan.ReviewSHA256) {
			return invalidWorkspaceOwnershipHistory("scans[%d].review_sha256 is invalid", index)
		}
		if index > 0 {
			previous := history.Scans[index-1]
			previousTime, _ := time.Parse(time.RFC3339Nano, previous.CompletedAt)
			if previousTime.After(completed) || previousTime.Equal(completed) && previous.ScanID >= scan.ScanID {
				return invalidWorkspaceOwnershipHistory("scans are not in canonical chronological order")
			}
		}
		scanPositions[scan.ScanID] = index
	}
	if history.LatestScanID != history.Scans[len(history.Scans)-1].ScanID {
		return invalidWorkspaceOwnershipHistory("latest_scan_id does not match the workspace timeline")
	}
	previousPosition := -1
	seenReviews := make(map[string]string, len(history.Reviews))
	for index := range history.Reviews {
		review := &history.Reviews[index]
		if err := ValidateOwnershipReview(review); err != nil {
			return invalidWorkspaceOwnershipHistory("reviews[%d]: %v", index, err)
		}
		for keyIndex := range review.Keys {
			if len(review.Keys[keyIndex].IdentityHints) != 0 {
				return invalidWorkspaceOwnershipHistory("reviews[%d] contains unverified identity hints", index)
			}
		}
		position, exists := scanPositions[review.ScanID]
		if !exists {
			return invalidWorkspaceOwnershipHistory("reviews[%d] references a scan outside the workspace history", index)
		}
		if position <= previousPosition {
			return invalidWorkspaceOwnershipHistory("reviews are not in canonical workspace order")
		}
		previousPosition = position
		if previous, exists := seenReviews[review.ScanID]; exists {
			return invalidWorkspaceOwnershipHistory("scan_id %q has duplicate reviews %q and %q", review.ScanID, previous, review.ReviewID)
		}
		seenReviews[review.ScanID] = review.ReviewID
	}
	for index, scan := range history.Scans {
		reviewID, reviewed := seenReviews[scan.ScanID]
		if scan.Reviewed != reviewed || scan.ReviewID != reviewID || reviewed && scan.ReviewSHA256 == "" {
			return invalidWorkspaceOwnershipHistory("scans[%d] does not reconcile with embedded reviews", index)
		}
	}
	if expected := deriveWorkspaceOwnershipLatest(history); !reflect.DeepEqual(history.Latest, expected) {
		return invalidWorkspaceOwnershipHistory("latest ownership review does not reconcile")
	}
	if expected := deriveWorkspaceOwnershipSummary(history); history.Summary != expected {
		return invalidWorkspaceOwnershipHistory("summary does not reconcile")
	}
	if expected := deriveWorkspaceOwnershipTransitions(history.Reviews); !reflect.DeepEqual(history.Transitions, expected) {
		return invalidWorkspaceOwnershipHistory("ownership transitions do not reconcile")
	}
	if expected := workspaceOwnershipHistoryID(history); history.OwnershipHistoryID != expected {
		return invalidWorkspaceOwnershipHistory("ownership_history_id does not match content")
	}
	encoded, err := json.Marshal(history)
	if err != nil {
		return invalidWorkspaceOwnershipHistory("cannot encode content: %v", err)
	}
	if len(encoded) > maxWorkspaceOwnershipHistoryBytes {
		return invalidWorkspaceOwnershipHistory("encoded content is %d bytes; limit is %d", len(encoded), maxWorkspaceOwnershipHistoryBytes)
	}
	if err := rejectForbiddenUploadMaterial(encoded); err != nil {
		return invalidWorkspaceOwnershipHistory("privacy boundary: %v", err)
	}
	return nil
}

func ValidateWorkspaceOwnershipHistoryAgainstWorkspace(ownership *WorkspaceOwnershipHistory, history *WorkspaceHistory) error {
	if err := ValidateWorkspaceOwnershipHistory(ownership); err != nil {
		return err
	}
	if err := ValidateWorkspaceHistory(history); err != nil {
		return err
	}
	if ownership.Workspace != history.Workspace || ownership.WorkspaceHistoryID != history.HistoryID || ownership.LatestScanID != history.LatestScanID {
		return errors.New("workspace ownership history does not reconcile with the selected workspace history")
	}
	wantScans := make([]WorkspaceOwnershipScan, 0, len(history.Artifacts))
	for _, artifact := range history.Artifacts {
		wantScans = append(wantScans, WorkspaceOwnershipScan{ScanID: artifact.ScanID, CompletedAt: artifact.CompletedAt})
	}
	for _, review := range ownership.Reviews {
		for index := range wantScans {
			if wantScans[index].ScanID == review.ScanID {
				wantScans[index].Reviewed = true
				wantScans[index].ReviewID = review.ReviewID
				for _, scan := range ownership.Scans {
					if scan.ScanID == review.ScanID {
						wantScans[index].ReviewSHA256 = scan.ReviewSHA256
						break
					}
				}
				break
			}
		}
		snapshot := workspaceSnapshotsByScan(history)[review.ScanID]
		if snapshot == nil {
			return errors.New("workspace ownership history references a missing workspace snapshot")
		}
		if err := ValidateOwnershipReviewAgainstSnapshot(&review, snapshot); err != nil {
			return fmt.Errorf("workspace ownership review %q: %w", review.ReviewID, err)
		}
	}
	if !reflect.DeepEqual(ownership.Scans, wantScans) {
		return errors.New("workspace ownership history scan index does not reconcile with the selected workspace history")
	}
	return nil
}

func RenderWorkspaceOwnershipHistoryJSON(history *WorkspaceOwnershipHistory) ([]byte, error) {
	if err := ValidateWorkspaceOwnershipHistory(history); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal workspace ownership history: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxWorkspaceOwnershipHistoryBytes {
		return nil, fmt.Errorf("workspace ownership history is %d bytes; limit is %d", len(data), maxWorkspaceOwnershipHistoryBytes)
	}
	return data, nil
}

func WriteWorkspaceOwnershipHistory(path string, history *WorkspaceOwnershipHistory) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("workspace ownership history output path is empty")
	}
	data, err := RenderWorkspaceOwnershipHistoryJSON(history)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadWorkspaceOwnershipHistory(path string) (*WorkspaceOwnershipHistory, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace ownership history %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > maxWorkspaceOwnershipHistoryBytes {
		return nil, fmt.Errorf("workspace ownership history is %d bytes; limit is %d", stat.Size(), maxWorkspaceOwnershipHistoryBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceOwnershipHistoryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read workspace ownership history: %w", err)
	}
	if len(data) > maxWorkspaceOwnershipHistoryBytes {
		return nil, fmt.Errorf("workspace ownership history exceeds %d bytes", maxWorkspaceOwnershipHistoryBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var history WorkspaceOwnershipHistory
	if err := decoder.Decode(&history); err != nil {
		return nil, fmt.Errorf("parse workspace ownership history: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("workspace ownership history contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing workspace ownership history data: %w", err)
	}
	if err := ValidateWorkspaceOwnershipHistory(&history); err != nil {
		return nil, err
	}
	return &history, nil
}

func RenderWorkspaceOwnershipHistoryText(history *WorkspaceOwnershipHistory) string {
	if history == nil {
		return ""
	}
	freshness := "current"
	if !history.Latest.Current {
		freshness = "STALE"
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Offline Cloud ownership history  %s\n\n", history.OwnershipHistoryID)
	fmt.Fprintf(&output, "Workspace:         %s\n", history.Workspace)
	fmt.Fprintf(&output, "Workspace history: %s\n", history.WorkspaceHistoryID)
	fmt.Fprintf(&output, "Reviewed / missing scans: %d / %d\n", history.Summary.ReviewedScans, history.Summary.MissingScans)
	fmt.Fprintf(&output, "Latest review:     %s (%s, %s)\n", history.Latest.ReviewID, history.Latest.ScanID, freshness)
	fmt.Fprintf(&output, "Unknown / shared / offboarded: %d / %d / %d\n", history.Latest.Summary.UnknownKeys, history.Latest.Summary.SharedKeys, history.Latest.Summary.OffboardedAccessKeys)
	fmt.Fprintf(&output, "Transitions:       %d\n", len(history.Transitions))
	fmt.Fprintln(&output, "Network activity:  none")
	fmt.Fprintln(&output, "\nThis is a private local read-only artifact; unverified key comments, Cloud upload, and remediation remain disabled.")
	return output.String()
}

func workspaceSnapshotsByScan(history *WorkspaceHistory) map[string]*Snapshot {
	values := make(map[string]*Snapshot, len(history.Plans))
	for index := range history.Plans {
		values[history.Plans[index].ArtifactID] = &history.Plans[index].Snapshot
	}
	return values
}

func privacyNormalizeWorkspaceOwnershipReview(review *OwnershipReview) (*OwnershipReview, error) {
	data, err := json.Marshal(review)
	if err != nil {
		return nil, err
	}
	var clone OwnershipReview
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	for index := range clone.Keys {
		clone.Keys[index].IdentityHints = nil
	}
	if err := ValidateOwnershipReview(&clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func deriveWorkspaceOwnershipLatest(history *WorkspaceOwnershipHistory) WorkspaceOwnershipLatest {
	review := history.Reviews[len(history.Reviews)-1]
	completedAt := ""
	reviewSHA256 := ""
	for _, scan := range history.Scans {
		if scan.ScanID == review.ScanID {
			completedAt = scan.CompletedAt
			reviewSHA256 = scan.ReviewSHA256
			break
		}
	}
	return WorkspaceOwnershipLatest{
		ReviewID: review.ReviewID, ReviewSHA256: reviewSHA256, ScanID: review.ScanID, CompletedAt: completedAt,
		Current: review.ScanID == history.LatestScanID, IdentityMapDigest: review.IdentityMapDigest,
		Summary: review.Summary,
	}
}

func deriveWorkspaceOwnershipSummary(history *WorkspaceOwnershipHistory) WorkspaceOwnershipHistorySummary {
	return WorkspaceOwnershipHistorySummary{
		Scans: len(history.Scans), ReviewedScans: len(history.Reviews),
		MissingScans:  len(history.Scans) - len(history.Reviews),
		CurrentReview: history.Reviews[len(history.Reviews)-1].ScanID == history.LatestScanID,
	}
}

func deriveWorkspaceOwnershipTransitions(reviews []OwnershipReview) []WorkspaceOwnershipTransition {
	transitions := make([]WorkspaceOwnershipTransition, 0, len(reviews)-1)
	for index := 1; index < len(reviews); index++ {
		before, after := &reviews[index-1], &reviews[index]
		transitions = append(transitions, WorkspaceOwnershipTransition{
			BeforeReviewID: before.ReviewID, AfterReviewID: after.ReviewID,
			BeforeScanID: before.ScanID, AfterScanID: after.ScanID,
			IdentityChanges: workspaceIdentityChanges(before, after),
			ClaimChanges:    workspaceClaimChanges(before, after),
			KeyChanges:      workspaceReviewedKeyChanges(before, after),
		})
	}
	return transitions
}

func workspaceIdentityChanges(before, after *OwnershipReview) []WorkspaceIdentityChange {
	left, right := make(map[string]Identity), make(map[string]Identity)
	for _, value := range before.Identities {
		left[value.ID] = value
	}
	for _, value := range after.Identities {
		right[value.ID] = value
	}
	ids := sortedStringMapUnion(left, right)
	var changes []WorkspaceIdentityChange
	for _, id := range ids {
		old, oldOK := left[id]
		current, currentOK := right[id]
		change := WorkspaceIdentityChange{IdentityID: id}
		switch {
		case !oldOK:
			change.Action, change.After = WorkspaceOwnershipChangeAdded, cloneIdentityValue(current)
		case !currentOK:
			change.Action, change.Before = WorkspaceOwnershipChangeRemoved, cloneIdentityValue(old)
		case old != current:
			change.Action, change.Before, change.After = WorkspaceOwnershipChangeChanged, cloneIdentityValue(old), cloneIdentityValue(current)
		default:
			continue
		}
		changes = append(changes, change)
	}
	return changes
}

func workspaceClaimChanges(before, after *OwnershipReview) []WorkspaceOwnershipClaimChange {
	left, right := indexWorkspaceClaims(before), indexWorkspaceClaims(after)
	ids := sortedStringMapUnion(left, right)
	var changes []WorkspaceOwnershipClaimChange
	for _, id := range ids {
		old, oldOK := left[id]
		current, currentOK := right[id]
		change := WorkspaceOwnershipClaimChange{Fingerprint: current.Fingerprint, IdentityID: current.Claim.IdentityID}
		if !currentOK {
			change.Fingerprint, change.IdentityID = old.Fingerprint, old.Claim.IdentityID
		}
		switch {
		case !oldOK:
			change.Action, change.After = WorkspaceOwnershipChangeAdded, cloneWorkspaceClaimState(current)
		case !currentOK:
			change.Action, change.Before = WorkspaceOwnershipChangeRemoved, cloneWorkspaceClaimState(old)
		case !reflect.DeepEqual(old, current):
			change.Action, change.Before, change.After = WorkspaceOwnershipChangeChanged, cloneWorkspaceClaimState(old), cloneWorkspaceClaimState(current)
		default:
			continue
		}
		changes = append(changes, change)
	}
	return changes
}

func workspaceReviewedKeyChanges(before, after *OwnershipReview) []WorkspaceReviewedKeyChange {
	left, right := indexWorkspaceReviewedKeys(before), indexWorkspaceReviewedKeys(after)
	ids := sortedStringMapUnion(left, right)
	var changes []WorkspaceReviewedKeyChange
	for _, id := range ids {
		old, oldOK := left[id]
		current, currentOK := right[id]
		change := WorkspaceReviewedKeyChange{Fingerprint: id}
		switch {
		case !oldOK:
			change.Action, change.After = WorkspaceOwnershipChangeAdded, cloneWorkspaceReviewedKeyState(current)
		case !currentOK:
			change.Action, change.Before = WorkspaceOwnershipChangeRemoved, cloneWorkspaceReviewedKeyState(old)
		case !reflect.DeepEqual(old, current):
			change.Action, change.Before, change.After = WorkspaceOwnershipChangeChanged, cloneWorkspaceReviewedKeyState(old), cloneWorkspaceReviewedKeyState(current)
		default:
			continue
		}
		changes = append(changes, change)
	}
	return changes
}

func indexWorkspaceClaims(review *OwnershipReview) map[string]WorkspaceOwnershipClaimState {
	values := make(map[string]WorkspaceOwnershipClaimState)
	for _, key := range review.Keys {
		for _, claim := range key.Claims {
			values[key.Fingerprint+"\x00"+claim.IdentityID] = WorkspaceOwnershipClaimState{Fingerprint: key.Fingerprint, Claim: claim}
		}
	}
	return values
}

func indexWorkspaceReviewedKeys(review *OwnershipReview) map[string]WorkspaceReviewedKeyState {
	values := make(map[string]WorkspaceReviewedKeyState, len(review.Keys))
	for _, key := range review.Keys {
		values[key.Fingerprint] = WorkspaceReviewedKeyState{
			Fingerprint: key.Fingerprint, Observed: key.Observed, IdentityMapEntry: key.IdentityMapEntry,
			OwnershipStatus: key.OwnershipStatus, OffboardedAccess: key.OffboardedAccess,
			PossessionVerified: key.PossessionVerified, Algorithm: key.Algorithm, Bits: key.Bits,
			Occurrences: key.Occurrences, Hosts: append([]string(nil), key.Hosts...), Accounts: append([]string(nil), key.Accounts...),
		}
	}
	return values
}

func sortedStringMapUnion[A, B any](left map[string]A, right map[string]B) []string {
	values := make(map[string]struct{}, len(left)+len(right))
	for key := range left {
		values[key] = struct{}{}
	}
	for key := range right {
		values[key] = struct{}{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneIdentityValue(value Identity) *Identity {
	clone := value
	return &clone
}

func cloneWorkspaceClaimState(value WorkspaceOwnershipClaimState) *WorkspaceOwnershipClaimState {
	clone := value
	return &clone
}

func cloneWorkspaceReviewedKeyState(value WorkspaceReviewedKeyState) *WorkspaceReviewedKeyState {
	clone := value
	clone.Hosts = append([]string(nil), value.Hosts...)
	clone.Accounts = append([]string(nil), value.Accounts...)
	return &clone
}

func workspaceOwnershipHistoryID(history *WorkspaceOwnershipHistory) string {
	clone := *history
	clone.OwnershipHistoryID = ""
	data, _ := json.Marshal(clone)
	hash := sha256.Sum256(data)
	return "ownership_history_" + hex.EncodeToString(hash[:12])
}

func invalidWorkspaceOwnershipHistory(format string, args ...any) error {
	return fmt.Errorf("invalid workspace ownership history v%s: %s", WorkspaceOwnershipHistorySchemaVersion, fmt.Sprintf(format, args...))
}
