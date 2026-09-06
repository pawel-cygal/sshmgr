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
	WorkspaceHistorySchemaVersion = "1"
	maxWorkspaceHistoryBytes      = 256 << 20
)

// WorkspaceHistory is an offline model of the immutable snapshot history a
// future WebPanel would ingest. It embeds only already validated upload plans;
// building and reading it performs no network operation.
type WorkspaceHistory struct {
	SchemaVersion string                `json:"schema_version"`
	HistoryID     string                `json:"history_id"`
	Workspace     string                `json:"workspace"`
	LatestScanID  string                `json:"latest_scan_id"`
	Artifacts     []WorkspaceArtifact   `json:"artifacts"`
	Transitions   []WorkspaceTransition `json:"transitions,omitempty"`
	Plans         []UploadPlan          `json:"plans"`
}

type WorkspaceArtifact struct {
	ScanID          string             `json:"scan_id"`
	PlanID          string             `json:"plan_id"`
	CompletedAt     string             `json:"completed_at"`
	PayloadSHA256   string             `json:"payload_sha256"`
	PayloadBytes    int                `json:"payload_bytes"`
	Privacy         UploadPrivacy      `json:"privacy"`
	Preview         UploadFieldPreview `json:"preview"`
	SnapshotSummary Summary            `json:"snapshot_summary"`
}

type WorkspaceTransition struct {
	BeforeScanID    string           `json:"before_scan_id"`
	AfterScanID     string           `json:"after_scan_id"`
	Comparable      bool             `json:"comparable"`
	Reason          string           `json:"reason,omitempty"`
	CoverageCaveat  string           `json:"coverage_caveat,omitempty"`
	ExcludedHosts   []string         `json:"diff_excluded_hosts,omitempty"`
	Added           []AccessEdge     `json:"added,omitempty"`
	Removed         []AccessEdge     `json:"removed,omitempty"`
	CoverageChanges []CoverageChange `json:"coverage_changes,omitempty"`
}

// BuildWorkspaceHistory validates upload plans, binds them to one workspace,
// and creates a deterministic chronological history. Exact retries are
// idempotently deduplicated. Reusing a scan_id for another payload is rejected.
func BuildWorkspaceHistory(plans ...*UploadPlan) (*WorkspaceHistory, error) {
	if len(plans) == 0 {
		return nil, errors.New("workspace history requires at least one upload plan")
	}
	unique := make(map[string]*UploadPlan, len(plans))
	workspace := ""
	totalPlanBytes := 0
	for index, plan := range plans {
		if err := ValidateUploadPlan(plan); err != nil {
			return nil, fmt.Errorf("input upload plan %d: %w", index+1, err)
		}
		if workspace == "" {
			workspace = plan.Workspace
		} else if plan.Workspace != workspace {
			return nil, fmt.Errorf("input upload plan %d belongs to workspace %q, expected %q", index+1, plan.Workspace, workspace)
		}
		if previous, exists := unique[plan.ArtifactID]; exists {
			if !reflect.DeepEqual(previous, plan) {
				return nil, fmt.Errorf("scan_id %q is reused with a different payload or privacy envelope", plan.ArtifactID)
			}
			continue
		}
		planJSON, err := RenderUploadPlanJSON(plan)
		if err != nil {
			return nil, fmt.Errorf("render input upload plan %d: %w", index+1, err)
		}
		totalPlanBytes += len(planJSON)
		if totalPlanBytes > maxWorkspaceHistoryBytes {
			return nil, fmt.Errorf("workspace history input is %d bytes; limit is %d", totalPlanBytes, maxWorkspaceHistoryBytes)
		}
		clone, err := cloneUploadPlan(plan)
		if err != nil {
			return nil, fmt.Errorf("clone input upload plan %d: %w", index+1, err)
		}
		unique[plan.ArtifactID] = clone
	}

	ordered := make([]UploadPlan, 0, len(unique))
	for _, plan := range unique {
		ordered = append(ordered, *plan)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, ordered[i].Snapshot.CompletedAt)
		right, _ := time.Parse(time.RFC3339Nano, ordered[j].Snapshot.CompletedAt)
		if !left.Equal(right) {
			return left.Before(right)
		}
		return ordered[i].ArtifactID < ordered[j].ArtifactID
	})

	history := buildWorkspaceHistoryCanonical(workspace, ordered)
	if err := ValidateWorkspaceHistory(history); err != nil {
		return nil, err
	}
	return history, nil
}

func buildWorkspaceHistoryCanonical(workspace string, plans []UploadPlan) *WorkspaceHistory {
	history := &WorkspaceHistory{
		SchemaVersion: WorkspaceHistorySchemaVersion,
		Workspace:     workspace,
		Plans:         plans,
		Artifacts:     make([]WorkspaceArtifact, 0, len(plans)),
	}
	for index := range plans {
		plan := &plans[index]
		history.Artifacts = append(history.Artifacts, WorkspaceArtifact{
			ScanID: plan.ArtifactID, PlanID: plan.PlanID,
			CompletedAt:   plan.Snapshot.CompletedAt,
			PayloadSHA256: plan.PayloadSHA256, PayloadBytes: plan.PayloadBytes,
			Privacy: plan.Privacy, Preview: plan.Preview, SnapshotSummary: plan.Snapshot.Summary,
		})
		if index > 0 {
			history.Transitions = append(history.Transitions, workspaceTransition(&plans[index-1].Snapshot, &plan.Snapshot))
		}
	}
	if len(plans) > 0 {
		history.LatestScanID = plans[len(plans)-1].ArtifactID
	}
	history.HistoryID = workspaceHistoryID(workspace, plans)
	return history
}

func ValidateWorkspaceHistory(history *WorkspaceHistory) error {
	if history == nil {
		return invalidWorkspaceHistory("history is nil")
	}
	if history.SchemaVersion != WorkspaceHistorySchemaVersion {
		return invalidWorkspaceHistory("unsupported schema_version %q", history.SchemaVersion)
	}
	if err := validateWorkspaceSlug(history.Workspace); err != nil {
		return invalidWorkspaceHistory("%v", err)
	}
	if len(history.Plans) == 0 {
		return invalidWorkspaceHistory("at least one plan is required")
	}
	seen := make(map[string]struct{}, len(history.Plans))
	for index := range history.Plans {
		plan := &history.Plans[index]
		if err := ValidateUploadPlan(plan); err != nil {
			return invalidWorkspaceHistory("plans[%d]: %v", index, err)
		}
		if plan.Workspace != history.Workspace {
			return invalidWorkspaceHistory("plans[%d] belongs to workspace %q", index, plan.Workspace)
		}
		if _, exists := seen[plan.ArtifactID]; exists {
			return invalidWorkspaceHistory("duplicate scan_id %q", plan.ArtifactID)
		}
		seen[plan.ArtifactID] = struct{}{}
		if index > 0 {
			previous := history.Plans[index-1]
			previousTime, _ := time.Parse(time.RFC3339Nano, previous.Snapshot.CompletedAt)
			currentTime, _ := time.Parse(time.RFC3339Nano, plan.Snapshot.CompletedAt)
			if previousTime.After(currentTime) ||
				(previousTime.Equal(currentTime) && previous.ArtifactID >= plan.ArtifactID) {
				return invalidWorkspaceHistory("plans are not in canonical chronological order")
			}
		}
	}
	canonical := buildWorkspaceHistoryCanonical(history.Workspace, history.Plans)
	if !reflect.DeepEqual(canonical, history) {
		return invalidWorkspaceHistory("derived history metadata or transitions do not reconcile")
	}
	return nil
}

func workspaceTransition(before, after *Snapshot) WorkspaceTransition {
	transition := WorkspaceTransition{BeforeScanID: before.ScanID, AfterScanID: after.ScanID}
	if reason := incomparableSnapshotReason(before, after); reason != "" {
		transition.Reason = reason
		return transition
	}
	transition.Comparable = true
	diff := SemanticDiff(before, after)
	unsafeHosts := unsafeTransitionHosts(before, after)
	transition.ExcludedHosts = unsafeHosts
	transition.Added = excludeAccessEdges(diff.Added, unsafeHosts)
	transition.Removed = excludeAccessEdges(diff.Removed, unsafeHosts)
	transition.CoverageChanges = diff.CoverageChanges
	if len(unsafeHosts) > 0 {
		transition.CoverageCaveat = "Hosts with failed or incomplete key collection were excluded from access-edge changes; rescan them before drawing an access conclusion."
	} else if before.Summary.HostsFull != before.Summary.HostsRequested || after.Summary.HostsFull != after.Summary.HostsRequested {
		transition.CoverageCaveat = "One or both scans lack full coverage; access-edge changes may reflect an observation gap."
	}
	return transition
}

func unsafeTransitionHosts(before, after *Snapshot) []string {
	unsafe := func(snapshot *Snapshot) map[string]bool {
		values := make(map[string]bool, len(snapshot.Hosts))
		for _, host := range snapshot.Hosts {
			incomplete := host.Coverage == CoverageFailed || len(host.Errors) > 0
			if host.System != nil {
				incomplete = incomplete || host.System.AccountsTruncated || host.System.SourcesTruncated ||
					host.System.ContentBudgetHit
			}
			for _, account := range host.Accounts {
				for _, source := range account.Sources {
					if source.Error != "" || (source.Exists && !source.ContentInspected) {
						incomplete = true
					}
					for _, entry := range source.Entries {
						if entry.ParseError != "" {
							incomplete = true
						}
					}
				}
			}
			values[host.Alias] = incomplete
		}
		return values
	}
	beforeUnsafe := unsafe(before)
	afterUnsafe := unsafe(after)
	missingAccounts := func(snapshot *Snapshot) map[string][]string {
		values := make(map[string][]string, len(snapshot.Hosts))
		for _, host := range snapshot.Hosts {
			if host.System == nil {
				continue
			}
			values[host.Alias] = append([]string(nil), host.System.MissingAccounts...)
			sort.Strings(values[host.Alias])
		}
		return values
	}
	beforeMissing := missingAccounts(before)
	afterMissing := missingAccounts(after)
	var excluded []string
	for host, state := range beforeUnsafe {
		if state || afterUnsafe[host] || !reflect.DeepEqual(beforeMissing[host], afterMissing[host]) {
			excluded = append(excluded, host)
		}
	}
	sort.Strings(excluded)
	return excluded
}

func excludeAccessEdges(edges []AccessEdge, excludedHosts []string) []AccessEdge {
	if len(excludedHosts) == 0 {
		return edges
	}
	excluded := make(map[string]struct{}, len(excludedHosts))
	for _, host := range excludedHosts {
		excluded[host] = struct{}{}
	}
	filtered := make([]AccessEdge, 0, len(edges))
	for _, edge := range edges {
		if _, skip := excluded[edge.Host]; !skip {
			filtered = append(filtered, edge)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func incomparableSnapshotReason(before, after *Snapshot) string {
	if before.Scope.Mode != after.Scope.Mode || before.Scope.Preflight != after.Scope.Preflight ||
		before.Scope.AccountMode != after.Scope.AccountMode || before.Scope.MaxAccounts != after.Scope.MaxAccounts ||
		before.Scope.MaxSourceBytes != after.Scope.MaxSourceBytes ||
		before.Scope.MaxTotalSourceBytes != after.Scope.MaxTotalSourceBytes ||
		!equalStringSets(before.Scope.RequestedAccounts, after.Scope.RequestedAccounts) {
		return "scan policies differ; access changes were not calculated"
	}
	if before.Scope.Preflight {
		return "preflight snapshots contain no key observations; access changes were not calculated"
	}
	beforeHosts := make([]string, 0, len(before.Hosts))
	afterHosts := make([]string, 0, len(after.Hosts))
	for _, host := range before.Hosts {
		beforeHosts = append(beforeHosts, host.Alias)
	}
	for _, host := range after.Hosts {
		afterHosts = append(afterHosts, host.Alias)
	}
	sort.Strings(beforeHosts)
	sort.Strings(afterHosts)
	if !reflect.DeepEqual(beforeHosts, afterHosts) {
		return "observed host sets differ; absent hosts were not treated as removed access"
	}
	if before.Scope.Mode == "current" && currentAccountScopeChanged(before, after) {
		return "current-account SSH users differ; access changes were not calculated"
	}
	return ""
}

func currentAccountScopeChanged(before, after *Snapshot) bool {
	excluded := make(map[string]struct{})
	for _, host := range unsafeTransitionHosts(before, after) {
		excluded[host] = struct{}{}
	}
	accountSets := func(snapshot *Snapshot) map[string][]string {
		sets := make(map[string][]string, len(snapshot.Hosts))
		for _, host := range snapshot.Hosts {
			if _, skip := excluded[host.Alias]; skip {
				continue
			}
			for _, account := range host.Accounts {
				sets[host.Alias] = append(sets[host.Alias], account.Username)
			}
			sort.Strings(sets[host.Alias])
		}
		return sets
	}
	return !reflect.DeepEqual(accountSets(before), accountSets(after))
}

func equalStringSets(left, right []string) bool {
	toSet := func(values []string) map[string]struct{} {
		set := make(map[string]struct{}, len(values))
		for _, value := range values {
			set[value] = struct{}{}
		}
		return set
	}
	return reflect.DeepEqual(toSet(left), toSet(right))
}

func RenderWorkspaceHistoryJSON(history *WorkspaceHistory) ([]byte, error) {
	if err := ValidateWorkspaceHistory(history); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal workspace history: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxWorkspaceHistoryBytes {
		return nil, fmt.Errorf("workspace history is %d bytes; limit is %d", len(data), maxWorkspaceHistoryBytes)
	}
	return data, nil
}

func WriteWorkspaceHistory(path string, history *WorkspaceHistory) error {
	data, err := RenderWorkspaceHistoryJSON(history)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadWorkspaceHistory(path string) (*WorkspaceHistory, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace history %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > maxWorkspaceHistoryBytes {
		return nil, fmt.Errorf("workspace history is %d bytes; limit is %d", stat.Size(), maxWorkspaceHistoryBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceHistoryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read workspace history: %w", err)
	}
	if len(data) > maxWorkspaceHistoryBytes {
		return nil, fmt.Errorf("workspace history exceeds %d bytes", maxWorkspaceHistoryBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var history WorkspaceHistory
	if err := decoder.Decode(&history); err != nil {
		return nil, fmt.Errorf("parse workspace history: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("workspace history contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing workspace history data: %w", err)
	}
	if err := ValidateWorkspaceHistory(&history); err != nil {
		return nil, err
	}
	return &history, nil
}

func RenderWorkspaceHistoryText(history *WorkspaceHistory) string {
	if history == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Offline Cloud workspace history  %s\n\n", history.HistoryID)
	fmt.Fprintf(&output, "Workspace:       %s\n", history.Workspace)
	fmt.Fprintf(&output, "Snapshots:       %d\n", len(history.Plans))
	fmt.Fprintf(&output, "Latest scan:     %s\n", history.LatestScanID)
	fmt.Fprintln(&output, "Network activity: none")
	fmt.Fprintln(&output, "\nTimeline")
	for index, artifact := range history.Artifacts {
		fmt.Fprintf(&output, "  %s  %s  hosts=%d findings=%d\n", artifact.CompletedAt, artifact.ScanID, artifact.Preview.Hosts, artifact.Preview.Findings)
		if index == 0 {
			continue
		}
		transition := history.Transitions[index-1]
		if !transition.Comparable {
			fmt.Fprintf(&output, "    change: not comparable — %s\n", transition.Reason)
			continue
		}
		fmt.Fprintf(&output, "    change: +%d / -%d access edges; %d coverage changes\n", len(transition.Added), len(transition.Removed), len(transition.CoverageChanges))
		if len(transition.ExcludedHosts) > 0 {
			fmt.Fprintf(&output, "    diff excluded incomplete hosts: %s\n", strings.Join(transition.ExcludedHosts, ", "))
		}
		if transition.CoverageCaveat != "" {
			fmt.Fprintf(&output, "    caution: %s\n", transition.CoverageCaveat)
		}
	}
	fmt.Fprintln(&output, "\nThis is a private local artifact; upload requires a separately built and validated workspace bundle.")
	return output.String()
}

func cloneUploadPlan(plan *UploadPlan) (*UploadPlan, error) {
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	var clone UploadPlan
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func workspaceHistoryID(workspace string, plans []UploadPlan) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(workspace))
	for _, plan := range plans {
		_, _ = hash.Write([]byte{'\x00'})
		_, _ = hash.Write([]byte(plan.PlanID))
		_, _ = hash.Write([]byte{'\x00'})
		_, _ = hash.Write([]byte(plan.PayloadSHA256))
		privacy, _ := json.Marshal(plan.Privacy)
		_, _ = hash.Write([]byte{'\x00'})
		_, _ = hash.Write(privacy)
	}
	return "history_" + hex.EncodeToString(hash.Sum(nil)[:12])
}

func invalidWorkspaceHistory(format string, args ...any) error {
	return fmt.Errorf("invalid workspace history v%s: %s", WorkspaceHistorySchemaVersion, fmt.Sprintf(format, args...))
}
