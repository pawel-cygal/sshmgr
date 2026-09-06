package access

import (
	"encoding/json"
	"strings"
	"testing"
)

func disjointMergeFixtures(t *testing.T) (*Snapshot, *Snapshot) {
	t.Helper()
	left := fixtureSnapshot()
	left.ScanID = "scan_left"
	left.Scope.HostExclusions = []string{"protected"}

	right := fixtureSnapshot()
	right.ScanID = "scan_right"
	right.Hosts[0].Alias = "db-01"
	right.Hosts[0].Groups = []string{"database"}
	right.Hosts[0].Accounts[0].Username = "root"
	right.Scope.HostExclusions = []string{"legacy"}
	right.Finalize(testTime.Add(2))
	return left, right
}

func TestMergeSnapshotsIsDeterministicAndReanalyzesFleet(t *testing.T) {
	left, right := disjointMergeFixtures(t)
	merged, err := MergeSnapshots("merge-test", right, left)
	if err != nil {
		t.Fatal(err)
	}
	if merged.ScanID != "merge_3dd5bf1ed6ef2eeb57ce1b33" {
		t.Fatalf("stable merge id changed: %s", merged.ScanID)
	}
	if strings.Join(merged.SourceScanIDs, ",") != "scan_left,scan_right" {
		t.Fatalf("lineage = %v", merged.SourceScanIDs)
	}
	if merged.Summary.HostsRequested != 2 || merged.Summary.AccountsObserved != 2 || merged.Summary.AuthorizedKeyEntries != 2 || merged.Summary.UniqueFingerprints != 1 {
		t.Fatalf("merged summary = %+v", merged.Summary)
	}
	if strings.Join(merged.Scope.HostExclusions, ",") != "legacy,protected" {
		t.Fatalf("merged exclusions = %v", merged.Scope.HostExclusions)
	}
	if merged.Hosts[0].Alias != "db-01" || merged.Hosts[1].Alias != "web-01" {
		t.Fatalf("merged hosts not normalized: %+v", merged.Hosts)
	}
	foundReuse := false
	for _, finding := range merged.Findings {
		foundReuse = foundReuse || finding.RuleID == "reused_key"
	}
	if !foundReuse {
		t.Fatal("merge did not reanalyze cross-host key reuse")
	}

	reversed, err := MergeSnapshots("merge-test", left, right)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(merged)
	want, _ := json.Marshal(reversed)
	if string(got) != string(want) {
		t.Fatalf("merge depends on input order\n%s\n%s", got, want)
	}
	if left.Hosts[0].Alias != "web-01" || right.Hosts[0].Alias != "db-01" {
		t.Fatal("merge mutated its inputs")
	}
}

func TestMergeSnapshotsUnionsSystemAccountScope(t *testing.T) {
	left, right := disjointMergeFixtures(t)
	for _, snapshot := range []*Snapshot{left, right} {
		snapshot.Scope.Mode = "system"
		snapshot.Scope.AccountMode = AccountModeExplicit
		snapshot.Scope.MaxSourceBytes = 1 << 20
		snapshot.Scope.MaxTotalSourceBytes = 4 << 20
	}
	left.Scope.RequestedAccounts = []string{"root", "ubuntu"}
	left.Scope.MaxAccounts = 2
	right.Scope.RequestedAccounts = []string{"root", "deploy"}
	right.Scope.MaxAccounts = 3
	merged, err := MergeSnapshots("merge-test", left, right)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(merged.Scope.RequestedAccounts, ",") != "deploy,root,ubuntu" || merged.Scope.MaxAccounts != 3 {
		t.Fatalf("merged account policy = %+v", merged.Scope)
	}
}

func TestMergeSnapshotsFlattensLineage(t *testing.T) {
	left, right := disjointMergeFixtures(t)
	firstMerge, err := MergeSnapshots("merge-test", left, right)
	if err != nil {
		t.Fatal(err)
	}
	third := fixtureSnapshot()
	third.ScanID = "scan_third"
	third.Hosts[0].Alias = "cache-01"
	third.Finalize(testTime.Add(3))

	merged, err := MergeSnapshots("merge-test", firstMerge, third)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(merged.SourceScanIDs, ",") != "scan_left,scan_right,scan_third" {
		t.Fatalf("flattened lineage = %v", merged.SourceScanIDs)
	}
	for _, sourceID := range merged.SourceScanIDs {
		if sourceID == firstMerge.ScanID {
			t.Fatal("nested merge ID leaked into source scan lineage")
		}
	}
}

func TestMergeSnapshotsRejectsAmbiguousOrIncompatibleInputs(t *testing.T) {
	left, right := disjointMergeFixtures(t)
	duplicate := *right
	duplicate.Hosts = append([]HostSnapshot(nil), right.Hosts...)
	duplicate.Hosts[0].Alias = left.Hosts[0].Alias
	duplicate.Finalize(testTime.Add(2))
	if _, err := MergeSnapshots("test", left, &duplicate); err == nil || !strings.Contains(err.Error(), "present in both") {
		t.Fatalf("duplicate host was not rejected: %v", err)
	}

	incompatible := *right
	incompatible.Scope = right.Scope
	incompatible.Scope.Preflight = true
	if _, err := MergeSnapshots("test", left, &incompatible); err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("incompatible scope was not rejected: %v", err)
	}
	if _, err := MergeSnapshots("test", left); err == nil {
		t.Fatal("single-snapshot merge accepted")
	}

	overlappingLineage := *right
	overlappingLineage.ScanID = "scan_other"
	overlappingLineage.SourceScanIDs = []string{left.ScanID}
	if _, err := MergeSnapshots("test", left, &overlappingLineage); err == nil || !strings.Contains(err.Error(), "repeats source scan") {
		t.Fatalf("overlapping lineage was not rejected: %v", err)
	}
}
