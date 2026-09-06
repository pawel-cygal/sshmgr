package access

import (
	"fmt"
	"strings"
)

const GraphSchemaVersion = "1"

// ValidateAccessGraph enforces the normalized graph v1 endpoint types,
// deterministic node identities, referential integrity, and summary counts.
func ValidateAccessGraph(graph *AccessGraph) error {
	if graph == nil {
		return invalidGraph("graph is nil")
	}
	if graph.SchemaVersion != GraphSchemaVersion {
		return invalidGraph("unsupported schema_version %q (supported: %s)", graph.SchemaVersion, GraphSchemaVersion)
	}
	if strings.TrimSpace(graph.ScanID) == "" {
		return invalidGraph("scan_id is required")
	}

	derived := AccessGraphStats{}
	nodes := make(map[string]AccessGraphNode, len(graph.Nodes))
	for index, node := range graph.Nodes {
		if strings.TrimSpace(node.ID) == "" || strings.TrimSpace(node.Label) == "" {
			return invalidGraph("nodes[%d] requires id and label", index)
		}
		if _, exists := nodes[node.ID]; exists {
			return invalidGraph("duplicate node id %q", node.ID)
		}
		var expectedID string
		switch node.Kind {
		case GraphNodeIdentityHint:
			if node.Verification != "unverified_comment" {
				return invalidGraph("identity hint %q has invalid verification %q", node.Label, node.Verification)
			}
			expectedID = graphNodeID(node.Kind, node.Label)
			derived.IdentityHints++
		case GraphNodeKey:
			if node.Fingerprint == "" || normalizeFingerprint(node.Fingerprint) != node.Fingerprint || node.Label != node.Fingerprint {
				return invalidGraph("key node %q has an invalid normalized fingerprint", node.ID)
			}
			if strings.TrimSpace(node.Algorithm) == "" || node.Bits < 0 {
				return invalidGraph("key node %q requires algorithm and non-negative bits", node.ID)
			}
			expectedID = graphNodeID(node.Kind, node.Fingerprint)
			derived.Keys++
		case GraphNodeAccount:
			if strings.TrimSpace(node.Host) == "" || strings.TrimSpace(node.Account) == "" || node.Label != node.Account+"@"+node.Host {
				return invalidGraph("account node %q has inconsistent host/account fields", node.ID)
			}
			expectedID = graphNodeID(node.Kind, node.Host+"\x00"+node.Account)
			derived.Accounts++
		case GraphNodeHost:
			if node.Host == "" || node.Label != node.Host || !validCoverage(node.Coverage) {
				return invalidGraph("host node %q has inconsistent host/coverage fields", node.ID)
			}
			expectedID = graphNodeID(node.Kind, node.Host)
			derived.Hosts++
			switch node.Coverage {
			case CoverageFull:
				derived.HostsFull++
			case CoveragePartial:
				derived.HostsPartial++
			case CoverageFailed:
				derived.HostsFailed++
			}
		default:
			return invalidGraph("nodes[%d] has invalid kind %q", index, node.Kind)
		}
		if node.ID != expectedID {
			return invalidGraph("node %q does not match stable id %q", node.ID, expectedID)
		}
		nodes[node.ID] = node
	}

	seenEdges := map[string]struct{}{}
	onHost := map[string]int{}
	for index, edge := range graph.Edges {
		from, fromExists := nodes[edge.From]
		to, toExists := nodes[edge.To]
		if !fromExists || !toExists {
			return invalidGraph("edges[%d] references a missing node", index)
		}
		edgeID := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", edge.Kind, edge.From, edge.To, edge.Source, edge.Line)
		if _, exists := seenEdges[edgeID]; exists {
			return invalidGraph("edges[%d] duplicates an existing edge", index)
		}
		seenEdges[edgeID] = struct{}{}
		switch edge.Kind {
		case GraphEdgeClaims:
			if from.Kind != GraphNodeIdentityHint || to.Kind != GraphNodeKey || edge.Source != "" || edge.Line != 0 {
				return invalidGraph("edges[%d] is not a valid identity_hint -> key claim", index)
			}
			derived.ClaimEdges++
		case GraphEdgeAuthorizes:
			if from.Kind != GraphNodeKey || to.Kind != GraphNodeAccount || strings.TrimSpace(edge.Source) == "" || edge.Line < 1 {
				return invalidGraph("edges[%d] is not a valid key -> account authorization", index)
			}
			derived.AccessEdges++
		case GraphEdgeOnHost:
			if from.Kind != GraphNodeAccount || to.Kind != GraphNodeHost || from.Host != to.Host || edge.Source != "" || edge.Line != 0 {
				return invalidGraph("edges[%d] is not a valid account -> host relation", index)
			}
			onHost[from.ID]++
		default:
			return invalidGraph("edges[%d] has invalid kind %q", index, edge.Kind)
		}
	}
	for _, node := range nodes {
		if node.Kind == GraphNodeAccount && onHost[node.ID] != 1 {
			return invalidGraph("account node %q must have exactly one on_host edge", node.ID)
		}
	}
	if graph.Summary != derived {
		return invalidGraph("summary does not reconcile: got %+v, derived %+v", graph.Summary, derived)
	}
	return nil
}

func validCoverage(coverage string) bool {
	return coverage == CoverageFull || coverage == CoveragePartial || coverage == CoverageFailed
}

func invalidGraph(format string, args ...any) error {
	return fmt.Errorf("invalid access graph v%s: %s", GraphSchemaVersion, fmt.Sprintf(format, args...))
}
