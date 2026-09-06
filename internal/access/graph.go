package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	GraphNodeIdentityHint = "identity_hint"
	GraphNodeKey          = "key"
	GraphNodeAccount      = "account"
	GraphNodeHost         = "host"

	GraphEdgeClaims     = "claims"
	GraphEdgeAuthorizes = "authorizes"
	GraphEdgeOnHost     = "on_host"
)

type AccessGraph struct {
	SchemaVersion string            `json:"schema_version"`
	ScanID        string            `json:"scan_id"`
	Summary       AccessGraphStats  `json:"summary"`
	Nodes         []AccessGraphNode `json:"nodes"`
	Edges         []AccessGraphEdge `json:"edges"`
}

type AccessGraphStats struct {
	Hosts         int `json:"hosts"`
	HostsFull     int `json:"hosts_full"`
	HostsPartial  int `json:"hosts_partial"`
	HostsFailed   int `json:"hosts_failed"`
	Accounts      int `json:"accounts"`
	Keys          int `json:"keys"`
	IdentityHints int `json:"identity_hints"`
	AccessEdges   int `json:"access_edges"`
	ClaimEdges    int `json:"claim_edges"`
}

type AccessGraphNode struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Label        string `json:"label"`
	Host         string `json:"host,omitempty"`
	Account      string `json:"account,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Bits         int    `json:"bits,omitempty"`
	Coverage     string `json:"coverage,omitempty"`
	Verification string `json:"verification,omitempty"`
}

type AccessGraphEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
	Line   int    `json:"line,omitempty"`
}

// BuildAccessGraph creates the observed graph without promoting comments to
// identities. A comment becomes an explicitly unverified identity_hint node;
// only future claim/verification workflows may upgrade that state.
func BuildAccessGraph(snapshot *Snapshot) (*AccessGraph, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is nil")
	}
	graph := &AccessGraph{
		SchemaVersion: GraphSchemaVersion,
		ScanID:        snapshot.ScanID,
		Summary: AccessGraphStats{
			HostsFull: snapshot.Summary.HostsFull, HostsPartial: snapshot.Summary.HostsPartial,
			HostsFailed: snapshot.Summary.HostsFailed,
		},
	}
	nodes := map[string]AccessGraphNode{}
	edges := make([]AccessGraphEdge, 0)
	uniqueEdges := map[string]bool{}
	for _, host := range snapshot.Hosts {
		hostID := graphNodeID(GraphNodeHost, host.Alias)
		nodes[hostID] = AccessGraphNode{ID: hostID, Kind: GraphNodeHost, Label: host.Alias, Host: host.Alias, Coverage: host.Coverage}
		for _, account := range host.Accounts {
			accountValue := host.Alias + "\x00" + account.Username
			accountID := graphNodeID(GraphNodeAccount, accountValue)
			nodes[accountID] = AccessGraphNode{
				ID: accountID, Kind: GraphNodeAccount, Label: account.Username + "@" + host.Alias,
				Host: host.Alias, Account: account.Username,
			}
			appendUniqueGraphEdge(&edges, uniqueEdges, AccessGraphEdge{From: accountID, To: hostID, Kind: GraphEdgeOnHost})
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					fingerprint := normalizeFingerprint(entry.Fingerprint)
					if fingerprint == "" {
						continue
					}
					keyID := graphNodeID(GraphNodeKey, fingerprint)
					keyNode, ok := nodes[keyID]
					if !ok {
						keyNode = AccessGraphNode{ID: keyID, Kind: GraphNodeKey, Label: fingerprint, Fingerprint: fingerprint}
					}
					if entry.Algorithm != "" && (keyNode.Algorithm == "" || entry.Algorithm < keyNode.Algorithm) {
						keyNode.Algorithm = entry.Algorithm
					}
					if entry.Bits > keyNode.Bits {
						keyNode.Bits = entry.Bits
					}
					nodes[keyID] = keyNode
					edges = append(edges, AccessGraphEdge{
						From: keyID, To: accountID, Kind: GraphEdgeAuthorizes,
						Source: source.Path, Line: entry.Line,
					})
					hint := strings.TrimSpace(entry.Comment)
					if hint == "" {
						continue
					}
					hintID := graphNodeID(GraphNodeIdentityHint, hint)
					nodes[hintID] = AccessGraphNode{
						ID: hintID, Kind: GraphNodeIdentityHint, Label: hint,
						Verification: "unverified_comment",
					}
					appendUniqueGraphEdge(&edges, uniqueEdges, AccessGraphEdge{From: hintID, To: keyID, Kind: GraphEdgeClaims})
				}
			}
		}
	}
	for _, node := range nodes {
		graph.Nodes = append(graph.Nodes, node)
		switch node.Kind {
		case GraphNodeHost:
			graph.Summary.Hosts++
		case GraphNodeAccount:
			graph.Summary.Accounts++
		case GraphNodeKey:
			graph.Summary.Keys++
		case GraphNodeIdentityHint:
			graph.Summary.IdentityHints++
		}
	}
	for _, edge := range edges {
		switch edge.Kind {
		case GraphEdgeAuthorizes:
			graph.Summary.AccessEdges++
		case GraphEdgeClaims:
			graph.Summary.ClaimEdges++
		}
	}
	graph.Edges = edges
	sortAccessGraph(graph)
	if err := ValidateAccessGraph(graph); err != nil {
		return nil, err
	}
	return graph, nil
}

func appendUniqueGraphEdge(edges *[]AccessGraphEdge, seen map[string]bool, edge AccessGraphEdge) {
	key := edge.Kind + "\x00" + edge.From + "\x00" + edge.To + "\x00" + edge.Source + "\x00" + fmt.Sprint(edge.Line)
	if seen[key] {
		return
	}
	seen[key] = true
	*edges = append(*edges, edge)
}

func graphNodeID(kind, value string) string {
	hash := sha256.Sum256([]byte(kind + "\x00" + value))
	return kind + ":" + hex.EncodeToString(hash[:])
}

func sortAccessGraph(graph *AccessGraph) {
	kindOrder := map[string]int{
		GraphNodeIdentityHint: 0,
		GraphNodeKey:          1,
		GraphNodeAccount:      2,
		GraphNodeHost:         3,
	}
	sort.Slice(graph.Nodes, func(i, j int) bool {
		left, right := graph.Nodes[i], graph.Nodes[j]
		if kindOrder[left.Kind] != kindOrder[right.Kind] {
			return kindOrder[left.Kind] < kindOrder[right.Kind]
		}
		if left.Label != right.Label {
			return left.Label < right.Label
		}
		return left.ID < right.ID
	})
	sort.Slice(graph.Edges, func(i, j int) bool {
		left, right := graph.Edges[i], graph.Edges[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.From != right.From {
			return left.From < right.From
		}
		if left.To != right.To {
			return left.To < right.To
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		return left.Line < right.Line
	})
}

func RenderAccessGraphText(graph *AccessGraph) string {
	if graph == nil {
		return ""
	}
	nodes := make(map[string]AccessGraphNode, len(graph.Nodes))
	var keys []AccessGraphNode
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
		if node.Kind == GraphNodeKey {
			keys = append(keys, node)
		}
	}
	claims := map[string][]string{}
	access := map[string][]AccessGraphEdge{}
	for _, edge := range graph.Edges {
		switch edge.Kind {
		case GraphEdgeClaims:
			claims[edge.To] = append(claims[edge.To], nodes[edge.From].Label)
		case GraphEdgeAuthorizes:
			access[edge.From] = append(access[edge.From], edge)
		}
	}
	var output strings.Builder
	fmt.Fprintf(&output, "SSH Access Graph  %s\n\n", graph.ScanID)
	fmt.Fprintf(&output, "Hosts: %d (%d partial, %d failed)\n", graph.Summary.Hosts, graph.Summary.HostsPartial, graph.Summary.HostsFailed)
	fmt.Fprintf(&output, "Identity hints: %d (all unverified comments)\n", graph.Summary.IdentityHints)
	fmt.Fprintf(&output, "Keys: %d\n", graph.Summary.Keys)
	fmt.Fprintf(&output, "Observed access edges: %d\n", graph.Summary.AccessEdges)
	fmt.Fprintln(&output, "\nCaveat: authorized_keys comments are identity hints, not ownership proof.")
	for _, key := range keys {
		fmt.Fprintf(&output, "\n%s", key.Fingerprint)
		if key.Algorithm != "" {
			fmt.Fprintf(&output, "  %s", key.Algorithm)
			if key.Bits > 0 {
				fmt.Fprintf(&output, "/%d", key.Bits)
			}
		}
		fmt.Fprintln(&output)
		hints := append([]string(nil), claims[key.ID]...)
		sort.Strings(hints)
		if len(hints) == 0 {
			fmt.Fprintln(&output, "  identity hint: (unclaimed)")
		} else {
			for _, hint := range hints {
				fmt.Fprintf(&output, "  identity hint: %q [unverified_comment]\n", hint)
			}
		}
		keyAccess := append([]AccessGraphEdge(nil), access[key.ID]...)
		sort.Slice(keyAccess, func(i, j int) bool {
			left, right := keyAccess[i], keyAccess[j]
			if nodes[left.To].Label != nodes[right.To].Label {
				return nodes[left.To].Label < nodes[right.To].Label
			}
			if left.Source != right.Source {
				return left.Source < right.Source
			}
			return left.Line < right.Line
		})
		for _, edge := range keyAccess {
			account := nodes[edge.To]
			fmt.Fprintf(&output, "  -> %s  %s:%d\n", account.Label, edge.Source, edge.Line)
		}
	}
	return output.String()
}

func RenderAccessGraphJSON(graph *AccessGraph) ([]byte, error) {
	if err := ValidateAccessGraph(graph); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal access graph: %w", err)
	}
	return append(data, '\n'), nil
}

func WriteAccessGraphJSON(path string, graph *AccessGraph) error {
	data, err := RenderAccessGraphJSON(graph)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

// ReadAccessGraph reads and validates a normalized graph v1 artifact while
// tolerating additive unknown JSON fields for forward compatibility.
func ReadAccessGraph(path string) (*AccessGraph, error) {
	var graph AccessGraph
	if err := readBoundedJSON(path, "access graph", &graph); err != nil {
		return nil, err
	}
	if err := ValidateAccessGraph(&graph); err != nil {
		return nil, err
	}
	return &graph, nil
}
