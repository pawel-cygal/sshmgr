package access

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalCurrentCollectionScriptContentAndMetadata(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := testPublicKey(t)
	content := []byte(authorizedLine(key, "", "external@test") + "\n")
	keyPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(keyPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	contentOutput := runExternalCurrentScript(t, home, false)
	sources, err := parseExternalCurrentCollection(contentOutput, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || !sources[0].Exists || !sources[0].ContentInspected || sources[0].Mode != "0600" || sources[0].Size != int64(len(content)) {
		t.Fatalf("content source mismatch: %+v", sources)
	}
	if len(sources[0].Entries) != 1 || sources[0].Entries[0].Fingerprint == "" || sources[0].Entries[0].PublicKey != "" {
		t.Fatalf("content entries mismatch: %+v", sources[0].Entries)
	}
	if sources[1].Exists || sources[1].ContentInspected || sources[1].Error != "" {
		t.Fatalf("missing legacy source mismatch: %+v", sources[1])
	}

	metadataOutput := runExternalCurrentScript(t, home, true)
	metadata, err := parseExternalCurrentCollection(metadataOutput, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata[0].Exists || metadata[0].ContentInspected || len(metadata[0].Entries) != 0 || metadata[0].Size != int64(len(content)) {
		t.Fatalf("metadata source mismatch: %+v", metadata[0])
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("external current collector changed authorized_keys")
	}
}

func runExternalCurrentScript(t *testing.T, home string, preflight bool) []byte {
	t.Helper()
	mode := "content"
	if preflight {
		mode = "metadata"
	}
	command := exec.Command("sh", "-s", "--", "current", mode, fmt.Sprint(maxAuthorizedKeysFileBytes))
	command.Dir = home
	command.Stdin = strings.NewReader(externalCurrentCollectionScript)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("external current script: %v", err)
	}
	return output
}

func TestExternalCurrentRemoteCommandContainsNoPaths(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		command := externalCurrentRemoteCommand(preflight)
		if strings.Contains(command, "authorized_keys") || strings.Contains(command, ".ssh") {
			t.Fatalf("fixed key path leaked into command: %q", command)
		}
		if !strings.HasPrefix(command, "sh -s -- current ") {
			t.Fatalf("unexpected external current command: %q", command)
		}
	}
}

func TestParseExternalCurrentCollectionRejectsMalformedProtocol(t *testing.T) {
	validMissing := "SOURCE\t2\tmissing\t-\t-\n"
	for name, protocol := range map[string]string{
		"bad header":        "wrong\nEND\n",
		"missing source":    externalCurrentCollectionMagic + "\nSOURCE\t1\tmissing\t-\t-\nEND\n",
		"duplicate source":  externalCurrentCollectionMagic + "\nSOURCE\t1\tmissing\t-\t-\nSOURCE\t1\tmissing\t-\t-\n" + validMissing + "END\n",
		"bad status":        externalCurrentCollectionMagic + "\nSOURCE\t1\tunknown\t-\t-\n" + validMissing + "END\n",
		"content preflight": externalCurrentCollectionMagic + "\nSOURCE\t1\tfile\t600\t0\nCONTENT\t1\t\n" + validMissing + "END\n",
		"missing content":   externalCurrentCollectionMagic + "\nSOURCE\t1\tfile\t600\t0\n" + validMissing + "END\n",
		"not terminated":    externalCurrentCollectionMagic + "\nSOURCE\t1\tmissing\t-\t-\n" + validMissing,
	} {
		t.Run(name, func(t *testing.T) {
			preflight := name == "content preflight"
			if _, err := parseExternalCurrentCollection([]byte(protocol), false, preflight); err == nil {
				t.Fatalf("malformed external protocol accepted: %q", protocol)
			}
		})
	}
}

func FuzzParseExternalCurrentCollection(f *testing.F) {
	f.Add([]byte(externalCurrentCollectionMagic + "\nSOURCE\t1\tmissing\t-\t-\nSOURCE\t2\tmissing\t-\t-\nEND\n"))
	f.Add([]byte("not-a-protocol\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2<<20 {
			t.Skip()
		}
		_, _ = parseExternalCurrentCollection(input, false, false)
	})
}
