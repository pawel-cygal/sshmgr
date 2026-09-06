package access

import "testing"

func TestSemanticDiffIgnoresLineCommentAndDuplicateChanges(t *testing.T) {
	before := &Snapshot{ScanID: "before", Hosts: []HostSnapshot{
		{
			Alias: "web", Coverage: CoveragePartial,
			Accounts: []AccountSnapshot{
				{Username: "deploy", Sources: []KeySource{
					{Entries: []KeyObservation{
						{Line: 1, Fingerprint: "SHA256:same", Comment: "old"},
						{Line: 2, Fingerprint: "SHA256:removed"},
					}},
				}},
			},
		},
	}}
	after := &Snapshot{ScanID: "after", Hosts: []HostSnapshot{
		{
			Alias: "web", Coverage: CoverageFull,
			Accounts: []AccountSnapshot{
				{Username: "deploy", Sources: []KeySource{
					{Entries: []KeyObservation{
						{Line: 20, Fingerprint: "SHA256:same", Comment: "new"},
						{Line: 21, Fingerprint: "SHA256:same", Comment: "duplicate"},
						{Line: 22, Fingerprint: "SHA256:added"},
					}},
				}},
			},
		},
	}}
	diff := SemanticDiff(before, after)
	if len(diff.Added) != 1 || diff.Added[0].Fingerprint != "SHA256:added" {
		t.Fatalf("added edges: %+v", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Fingerprint != "SHA256:removed" {
		t.Fatalf("removed edges: %+v", diff.Removed)
	}
	if len(diff.CoverageChanges) != 1 || diff.CoverageChanges[0].Before != CoveragePartial || diff.CoverageChanges[0].After != CoverageFull {
		t.Fatalf("coverage changes: %+v", diff.CoverageChanges)
	}
}
