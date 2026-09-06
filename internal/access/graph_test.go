package access

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAccessGraphKeepsIdentityHintsUnverified(t *testing.T) {
	snapshot := fixtureSnapshot()
	second := snapshot.Hosts[0]
	second.Alias = "db-01"
	second.Accounts = []AccountSnapshot{{
		Username: "root",
		Sources: []KeySource{{
			Type: "authorized_keys_file", Path: "/root/.ssh/authorized_keys", Exists: true, ContentInspected: true,
			Entries: []KeyObservation{{
				Line: 3, Fingerprint: "SHA256:fixture", Algorithm: sshAlgorithmFixture, Bits: 256,
				Comment: "contractor@old-device", PublicKey: "must-not-enter-graph",
			}},
		}},
	}}
	snapshot.Hosts = append(snapshot.Hosts, second)
	snapshot.Summary.HostsPartial = 2
	snapshot.Summary.HostsRequested = 2

	graph, err := BuildAccessGraph(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Summary.Hosts != 2 || graph.Summary.Accounts != 2 || graph.Summary.Keys != 1 || graph.Summary.IdentityHints != 2 || graph.Summary.AccessEdges != 2 || graph.Summary.ClaimEdges != 2 {
		t.Fatalf("graph summary mismatch: %+v", graph.Summary)
	}
	for _, node := range graph.Nodes {
		if node.Kind == GraphNodeIdentityHint && node.Verification != "unverified_comment" {
			t.Fatalf("identity hint was promoted: %+v", node)
		}
	}
	text := RenderAccessGraphText(graph)
	for _, wanted := range []string{
		"authorized_keys comments are identity hints, not ownership proof",
		"contractor@old-device",
		"root@db-01",
		"deploy@web-01",
	} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("graph text missing %q:\n%s", wanted, text)
		}
	}
	jsonData, err := RenderAccessGraphJSON(graph)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(jsonData, []byte("must-not-enter-graph")) || bytes.Contains(jsonData, []byte("public_key")) {
		t.Fatalf("raw public key leaked into graph: %s", jsonData)
	}

	reversed := *snapshot
	reversed.Hosts = []HostSnapshot{snapshot.Hosts[1], snapshot.Hosts[0]}
	reversedGraph, err := BuildAccessGraph(&reversed)
	if err != nil {
		t.Fatal(err)
	}
	reversedJSON, err := RenderAccessGraphJSON(reversedGraph)
	if err != nil || !bytes.Equal(jsonData, reversedJSON) {
		t.Fatalf("graph JSON is not deterministic: err=%v", err)
	}
}

func TestAccessGraphIncludesFailedHostsWithoutInventingEdges(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts = append(snapshot.Hosts, HostSnapshot{Alias: "failed", Coverage: CoverageFailed})
	snapshot.Summary.HostsRequested = 2
	snapshot.Summary.HostsFailed = 1
	graph, err := BuildAccessGraph(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Summary.Hosts != 2 || graph.Summary.HostsFailed != 1 || graph.Summary.AccessEdges != 1 {
		t.Fatalf("failed host graph mismatch: %+v", graph.Summary)
	}
}

func TestWriteAccessGraphJSONUsesPrivateMode(t *testing.T) {
	graph, err := BuildAccessGraph(fixtureSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "graphs", "access.json")
	if err := WriteAccessGraphJSON(path, graph); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("graph mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestAccessGraphV1GoldenFixture(t *testing.T) {
	snapshot, err := ReadSnapshot(filepath.Join("testdata", "snapshot-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildAccessGraph(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RenderAccessGraphJSON(graph)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "access-graph-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("graph v1 golden contract changed\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	read, err := ReadAccessGraph(filepath.Join("testdata", "access-graph-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if read.SchemaVersion != GraphSchemaVersion || read.ScanID != snapshot.ScanID || read.Summary != graph.Summary {
		t.Fatalf("graph golden round trip mismatch: %+v", read)
	}
}

func TestReadAccessGraphToleratesUnknownFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "access-graph-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"scan_id": "scan_golden_v1",`), []byte(`"scan_id": "scan_golden_v1", "future_field": true,`), 1)
	path := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAccessGraph(path); err != nil {
		t.Fatalf("forward-compatible graph field rejected: %v", err)
	}
}

func TestValidateAccessGraphRejectsInconsistentV1Artifacts(t *testing.T) {
	tests := map[string]func(*AccessGraph){
		"summary": func(graph *AccessGraph) { graph.Summary.Keys++ },
		"verified comment": func(graph *AccessGraph) {
			for index := range graph.Nodes {
				if graph.Nodes[index].Kind == GraphNodeIdentityHint {
					graph.Nodes[index].Verification = "verified"
				}
			}
		},
		"unstable node id": func(graph *AccessGraph) { graph.Nodes[0].ID = "identity_hint:not-stable" },
		"bad edge direction": func(graph *AccessGraph) {
			graph.Edges[0].From, graph.Edges[0].To = graph.Edges[0].To, graph.Edges[0].From
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			graph, err := BuildAccessGraph(fixtureSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			mutate(graph)
			if err := ValidateAccessGraph(graph); err == nil {
				t.Fatal("inconsistent graph accepted")
			}
		})
	}
}
