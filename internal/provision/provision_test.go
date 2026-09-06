package provision

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/access"
)

func TestWriteAndRestoreScriptsPreserveExactBytes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), ".ssh")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "authorized_keys")
	before := []byte("# unmanaged\ninvalid-but-preserved\n")
	after := append(append([]byte(nil), before...), []byte("ssh-ed25519 AAAA managed\n")...)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	beforeDigest, afterDigest := access.ContentDigest(before), access.ContentDigest(after)
	input := encodeLines(path, beforeDigest, afterDigest, "0600", uid, gid, "accessplan_test", string(after))
	output := runScriptForTest(t, writeScript, input)
	fields := strings.Split(strings.TrimSpace(output), "\t")
	if len(fields) != 3 || fields[0] != "OK" || fields[2] != afterDigest {
		t.Fatalf("unexpected write receipt: %q", output)
	}
	backup, err := decodeBase64(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil || string(written) != string(after) {
		t.Fatalf("written content = %q, err=%v", written, err)
	}
	runScriptForTest(t, restoreScript, encodeLines(path, backup, afterDigest, "1"))
	restored, err := os.ReadFile(path)
	if err != nil || string(restored) != string(before) {
		t.Fatalf("restored content = %q, err=%v", restored, err)
	}
}

func runScriptForTest(t *testing.T, script, input string) string {
	t.Helper()
	command := exec.Command("sh", "-c", script)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v: %s", err, output)
	}
	return string(output)
}

func decodeBase64(value string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	return string(data), err
}
