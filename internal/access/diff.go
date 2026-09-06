package access

import (
	"fmt"
	"sort"
	"strings"
)

// AccessEdge is the semantic grant identity used for snapshot diffs. Line
// order and comments are deliberately excluded, so metadata-only edits do not
// appear as newly granted access.
type AccessEdge struct {
	Host        string `json:"host"`
	Account     string `json:"account"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm,omitempty"`
	Bits        int    `json:"bits,omitempty"`
}

type CoverageChange struct {
	Host   string `json:"host"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type Diff struct {
	BeforeScanID    string           `json:"before_scan_id"`
	AfterScanID     string           `json:"after_scan_id"`
	Added           []AccessEdge     `json:"added"`
	Removed         []AccessEdge     `json:"removed"`
	CoverageChanges []CoverageChange `json:"coverage_changes,omitempty"`
}

func SemanticDiff(before, after *Snapshot) Diff {
	diff := Diff{}
	if before != nil {
		diff.BeforeScanID = before.ScanID
	}
	if after != nil {
		diff.AfterScanID = after.ScanID
	}
	beforeEdges := accessEdges(before)
	afterEdges := accessEdges(after)
	for key, edge := range afterEdges {
		if _, existed := beforeEdges[key]; !existed {
			diff.Added = append(diff.Added, edge)
		}
	}
	for key, edge := range beforeEdges {
		if _, remains := afterEdges[key]; !remains {
			diff.Removed = append(diff.Removed, edge)
		}
	}
	sortEdges(diff.Added)
	sortEdges(diff.Removed)

	beforeCoverage := hostCoverage(before)
	afterCoverage := hostCoverage(after)
	for host, afterState := range afterCoverage {
		if beforeState, present := beforeCoverage[host]; present && beforeState != afterState {
			diff.CoverageChanges = append(diff.CoverageChanges, CoverageChange{Host: host, Before: beforeState, After: afterState})
		}
	}
	sort.Slice(diff.CoverageChanges, func(i, j int) bool { return diff.CoverageChanges[i].Host < diff.CoverageChanges[j].Host })
	return diff
}

func RenderDiffText(diff Diff) string {
	var output strings.Builder
	fmt.Fprintf(&output, "SSH Access Diff\n  Before: %s\n  After:  %s\n", diff.BeforeScanID, diff.AfterScanID)
	fmt.Fprintf(&output, "\nAccess edges\n  Added:   %d\n  Removed: %d\n", len(diff.Added), len(diff.Removed))
	for _, edge := range diff.Added {
		fmt.Fprintf(&output, "  + %s@%s  %s\n", edge.Account, edge.Host, edge.Fingerprint)
	}
	for _, edge := range diff.Removed {
		fmt.Fprintf(&output, "  - %s@%s  %s\n", edge.Account, edge.Host, edge.Fingerprint)
	}
	if len(diff.CoverageChanges) > 0 {
		fmt.Fprintf(&output, "\nCoverage changes\n")
		for _, change := range diff.CoverageChanges {
			fmt.Fprintf(&output, "  %s: %s -> %s\n", change.Host, change.Before, change.After)
		}
	}
	return output.String()
}

func accessEdges(snapshot *Snapshot) map[string]AccessEdge {
	edges := map[string]AccessEdge{}
	if snapshot == nil {
		return edges
	}
	for _, host := range snapshot.Hosts {
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				for _, observation := range source.Entries {
					if observation.Fingerprint == "" || observation.ParseError != "" {
						continue
					}
					edge := AccessEdge{
						Host: host.Alias, Account: account.Username, Fingerprint: observation.Fingerprint,
						Algorithm: observation.Algorithm, Bits: observation.Bits,
					}
					edges[edgeKey(edge)] = edge
				}
			}
		}
	}
	return edges
}

func edgeKey(edge AccessEdge) string {
	return edge.Host + "\x00" + edge.Account + "\x00" + edge.Fingerprint
}

func sortEdges(edges []AccessEdge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Host != edges[j].Host {
			return edges[i].Host < edges[j].Host
		}
		if edges[i].Account != edges[j].Account {
			return edges[i].Account < edges[j].Account
		}
		return edges[i].Fingerprint < edges[j].Fingerprint
	})
}

func hostCoverage(snapshot *Snapshot) map[string]string {
	coverage := map[string]string{}
	if snapshot == nil {
		return coverage
	}
	for _, host := range snapshot.Hosts {
		coverage[host.Alias] = host.Coverage
	}
	return coverage
}
