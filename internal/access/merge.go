package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MergeSnapshots combines disjoint validated snapshots into one deterministic
// fleet artifact. It never guesses how to reconcile two observations of the
// same host; callers must use diff for repeated scans instead.
func MergeSnapshots(scannerVersion string, snapshots ...*Snapshot) (*Snapshot, error) {
	if len(snapshots) < 2 {
		return nil, fmt.Errorf("merge requires at least two access snapshots")
	}
	for index, snapshot := range snapshots {
		if err := ValidateSnapshot(snapshot); err != nil {
			return nil, fmt.Errorf("input snapshot %d: %w", index+1, err)
		}
	}

	first := snapshots[0]
	started, _ := time.Parse(time.RFC3339Nano, first.StartedAt)
	completed, _ := time.Parse(time.RFC3339Nano, first.CompletedAt)
	accountNames := map[string]bool{}
	hostExclusions := map[string]bool{}
	tagExclusions := map[string]bool{}
	excludedMatched := map[string]bool{}
	lineage := map[string]bool{}
	hostAliases := map[string]string{}
	maxAccounts := 0
	var hosts []HostSnapshot

	for index, snapshot := range snapshots {
		if err := compatibleMergeScope(first.Scope, snapshot.Scope); err != nil {
			return nil, fmt.Errorf("input snapshot %d (%s): %w", index+1, snapshot.ScanID, err)
		}
		inputStarted, _ := time.Parse(time.RFC3339Nano, snapshot.StartedAt)
		inputCompleted, _ := time.Parse(time.RFC3339Nano, snapshot.CompletedAt)
		if inputStarted.Before(started) {
			started = inputStarted
		}
		if inputCompleted.After(completed) {
			completed = inputCompleted
		}
		if snapshot.Scope.MaxAccounts > maxAccounts {
			maxAccounts = snapshot.Scope.MaxAccounts
		}
		addStrings(accountNames, snapshot.Scope.RequestedAccounts)
		addStrings(hostExclusions, snapshot.Scope.HostExclusions)
		addStrings(tagExclusions, snapshot.Scope.TagExclusions)
		addStrings(excludedMatched, snapshot.Scope.ExcludedMatchedHosts)
		sourceIDs := snapshot.SourceScanIDs
		if len(sourceIDs) == 0 {
			sourceIDs = []string{snapshot.ScanID}
		}
		for _, sourceID := range sourceIDs {
			if _, exists := lineage[sourceID]; exists {
				return nil, fmt.Errorf("input snapshot %d repeats source scan %q", index+1, sourceID)
			}
			lineage[sourceID] = true
		}
		for _, host := range snapshot.Hosts {
			if previous, exists := hostAliases[host.Alias]; exists {
				return nil, fmt.Errorf("host %q is present in both %s and %s; use access diff for repeated observations", host.Alias, previous, snapshot.ScanID)
			}
			hostAliases[host.Alias] = snapshot.ScanID
			clone, err := cloneHostSnapshot(host)
			if err != nil {
				return nil, fmt.Errorf("clone host %q: %w", host.Alias, err)
			}
			hosts = append(hosts, clone)
		}
	}

	sourceScanIDs := sortedSet(lineage)
	merged := &Snapshot{
		SchemaVersion:  SchemaVersion,
		ScanID:         mergedScanID(sourceScanIDs),
		SourceScanIDs:  sourceScanIDs,
		ScannerVersion: scannerVersion,
		StartedAt:      started.UTC().Format(time.RFC3339Nano),
		Scope: Scope{
			Mode:                 first.Scope.Mode,
			Selector:             "merge:" + strconv.Itoa(len(sourceScanIDs)) + " scans",
			AccountMode:          first.Scope.AccountMode,
			RequestedAccounts:    sortedSet(accountNames),
			MaxAccounts:          maxAccounts,
			MaxSourceBytes:       first.Scope.MaxSourceBytes,
			MaxTotalSourceBytes:  first.Scope.MaxTotalSourceBytes,
			HostExclusions:       sortedSet(hostExclusions),
			TagExclusions:        sortedSet(tagExclusions),
			ExcludedMatchedHosts: sortedSet(excludedMatched),
			Preflight:            first.Scope.Preflight,
			IncludePublicKeys:    first.Scope.IncludePublicKeys,
		},
		Hosts: hosts,
	}
	merged.Finalize(completed)
	if err := ValidateSnapshot(merged); err != nil {
		return nil, fmt.Errorf("merged artifact: %w", err)
	}
	return merged, nil
}

func compatibleMergeScope(reference, candidate Scope) error {
	if reference.Mode != candidate.Mode {
		return fmt.Errorf("scope mode mismatch: %s != %s", reference.Mode, candidate.Mode)
	}
	if reference.Preflight != candidate.Preflight {
		return fmt.Errorf("preflight and key-content snapshots cannot be merged")
	}
	if reference.IncludePublicKeys != candidate.IncludePublicKeys {
		return fmt.Errorf("include_public_keys mismatch")
	}
	if reference.AccountMode != candidate.AccountMode {
		return fmt.Errorf("account_mode mismatch: %s != %s", reference.AccountMode, candidate.AccountMode)
	}
	if reference.MaxSourceBytes != candidate.MaxSourceBytes || reference.MaxTotalSourceBytes != candidate.MaxTotalSourceBytes {
		return fmt.Errorf("system source budget mismatch")
	}
	return nil
}

func cloneHostSnapshot(host HostSnapshot) (HostSnapshot, error) {
	data, err := json.Marshal(host)
	if err != nil {
		return HostSnapshot{}, err
	}
	var clone HostSnapshot
	if err := json.Unmarshal(data, &clone); err != nil {
		return HostSnapshot{}, err
	}
	return clone, nil
}

func addStrings(target map[string]bool, values []string) {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			target[value] = true
		}
	}
}

func mergedScanID(sourceScanIDs []string) string {
	digest := sha256.Sum256([]byte(strings.Join(sourceScanIDs, "\x00")))
	return "merge_" + hex.EncodeToString(digest[:12])
}
