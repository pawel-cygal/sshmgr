package access

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderAccessCSVIsDeterministicCompleteAndSpreadsheetSafe(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Groups = []string{"zeta", "alpha"}
	snapshot.Hosts[0].Tags = []string{"prod", "linux"}
	entry := &snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	entry.Comment = `=HYPERLINK("https://invalid.example")`
	entry.Options = []string{"no-port-forwarding", `from="10.0.0.0/8"`}
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries = append(
		snapshot.Hosts[0].Accounts[0].Sources[0].Entries,
		KeyObservation{Line: 2, ParseError: "malformed fixture"},
	)

	data, err := RenderAccessCSV(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || len(records[0]) != len(accessCSVHeader) {
		t.Fatalf("CSV shape mismatch: rows=%d columns=%d", len(records), len(records[0]))
	}
	columns := map[string]int{}
	for index, name := range records[0] {
		columns[name] = index
	}
	valid := records[1]
	if valid[columns["groups"]] != "alpha;zeta" || valid[columns["tags"]] != "linux;prod" {
		t.Fatalf("set columns are not deterministic: %q %q", valid[columns["groups"]], valid[columns["tags"]])
	}
	if !strings.HasPrefix(valid[columns["comment"]], "'=") {
		t.Fatalf("formula-like comment is not spreadsheet-safe: %q", valid[columns["comment"]])
	}
	if valid[columns["identity_status"]] != "comment_hint_unverified" {
		t.Fatalf("identity status = %q", valid[columns["identity_status"]])
	}
	if records[2][columns["parse_error"]] != "malformed fixture" || records[2][columns["identity_status"]] != "unclaimed" {
		t.Fatalf("malformed observation was hidden: %q", records[2])
	}

	deterministic := *snapshot
	deterministic.Hosts = append([]HostSnapshot(nil), snapshot.Hosts...)
	secondHost := snapshot.Hosts[0]
	secondHost.Alias = "api-00"
	deterministic.Hosts = append(deterministic.Hosts, secondHost)
	orderedData, err := RenderAccessCSV(&deterministic)
	if err != nil {
		t.Fatal(err)
	}
	reversed := deterministic
	reversed.Hosts = append([]HostSnapshot(nil), deterministic.Hosts...)
	for left, right := 0, len(reversed.Hosts)-1; left < right; left, right = left+1, right-1 {
		reversed.Hosts[left], reversed.Hosts[right] = reversed.Hosts[right], reversed.Hosts[left]
	}
	second, err := RenderAccessCSV(&reversed)
	if err != nil || !bytes.Equal(orderedData, second) {
		t.Fatalf("CSV output is not deterministic: err=%v", err)
	}
}

func TestWriteAccessCSVUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "access.csv")
	if err := WriteAccessCSV(path, fixtureSnapshot()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CSV mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSpreadsheetSafeCSVCell(t *testing.T) {
	for input, want := range map[string]string{
		"normal": "normal",
		"=1+1":   "'=1+1",
		"  @cmd": "'  @cmd",
		"\tcmd":  "'\tcmd",
		"\n+cmd": "'\n+cmd",
	} {
		if got := spreadsheetSafeCSVCell(input); got != want {
			t.Errorf("spreadsheetSafeCSVCell(%q) = %q, want %q", input, got, want)
		}
	}
}
