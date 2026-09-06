package access

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

func fixtureSnapshot() *Snapshot {
	snapshot := NewSnapshot("test", Scope{Mode: "current", Selector: "group:test"}, testTime)
	snapshot.ScanID = "scan_fixture"
	snapshot.Hosts = []HostSnapshot{{
		Alias:    "web-01",
		Coverage: CoveragePartial,
		Accounts: []AccountSnapshot{{Username: "deploy", Sources: []KeySource{{
			Type: "authorized_keys_file", Path: ".ssh/authorized_keys", Exists: true, ContentInspected: true,
			Entries: []KeyObservation{{Line: 1, Fingerprint: "SHA256:fixture", Algorithm: sshAlgorithmFixture, Comment: `<admin&ops>`}},
		}}}},
	}}
	snapshot.Finalize(testTime.Add(time.Second))
	return snapshot
}

const sshAlgorithmFixture = "ssh-ed25519"

func TestSnapshotRoundTripUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "scan.json")
	want := fixtureSnapshot()
	if err := WriteSnapshot(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", info.Mode().Perm())
	}
	got, err := ReadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ScanID != want.ScanID || got.Summary != want.Summary || got.Hosts[0].Accounts[0].Username != "deploy" {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestReadSnapshotToleratesUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.json")
	data, err := os.ReadFile(filepath.Join("testdata", "snapshot-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"scanner_version": "test",`), []byte(`"scanner_version": "test", "future_field": {"enabled": true},`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSnapshot(path); err != nil {
		t.Fatalf("forward-compatible field rejected: %v", err)
	}
}

func TestValidateSnapshotRejectsInconsistentV1Artifacts(t *testing.T) {
	tests := map[string]func(*Snapshot){
		"summary":  func(snapshot *Snapshot) { snapshot.Summary.AuthorizedKeyEntries++ },
		"coverage": func(snapshot *Snapshot) { snapshot.Hosts[0].Coverage = "unknown" },
		"raw key without opt-in": func(snapshot *Snapshot) {
			snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].PublicKey = "ssh-ed25519 forbidden"
		},
		"malformed parsed key": func(snapshot *Snapshot) {
			entry := &snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
			entry.ParseError = "bad"
		},
		"time order":       func(snapshot *Snapshot) { snapshot.CompletedAt = testTime.Add(-time.Second).Format(time.RFC3339Nano) },
		"finding severity": func(snapshot *Snapshot) { snapshot.Findings[0].Severity = "urgent" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			snapshot := fixtureSnapshot()
			mutate(snapshot)
			if err := ValidateSnapshot(snapshot); err == nil {
				t.Fatal("inconsistent snapshot accepted")
			}
		})
	}
}

func TestReadSnapshotRejectsUnsupportedSchemaAndTrailingJSON(t *testing.T) {
	for name, data := range map[string]string{
		"schema":   `{"schema_version":"2","scan_id":"scan_bad"}`,
		"trailing": `{"schema_version":"1","scan_id":"scan_bad"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scan.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadSnapshot(path); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("invalid snapshot accepted: %s", data)
			}
		})
	}
}

func TestSchemaV1GoldenFixture(t *testing.T) {
	snapshot, err := ReadSnapshot(filepath.Join("testdata", "snapshot-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != SchemaVersion || snapshot.ScanID != "scan_golden_v1" {
		t.Fatalf("golden envelope mismatch: %+v", snapshot)
	}
	if snapshot.Summary.AuthorizedKeyEntries != 1 || len(snapshot.Findings) != 1 || len(snapshot.Hosts) != 1 {
		t.Fatalf("golden normalized data mismatch: %+v", snapshot)
	}
	entry := snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0]
	if entry.PublicKey != "" || entry.Fingerprint != "SHA256:golden" {
		t.Fatalf("golden redaction contract mismatch: %+v", entry)
	}
	path := filepath.Join(t.TempDir(), "roundtrip.json")
	if err := WriteSnapshot(path, snapshot); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := ReadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if roundtrip.ScanID != snapshot.ScanID || roundtrip.Summary != snapshot.Summary {
		t.Fatalf("golden round trip mismatch: %+v", roundtrip)
	}
}
