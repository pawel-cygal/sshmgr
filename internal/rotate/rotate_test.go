package rotate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/systeampl/sshmgr/internal/config"

	"golang.org/x/crypto/ssh"
)

func testPrivateKey(t *testing.T, name string) (string, ssh.PublicKey) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return path, sshPub
}

func TestRotationTargetLocksShareOneAccount(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"one":   {Host: "server", User: "root", Port: 22},
		"two":   {Host: "SERVER", User: "root", Port: 22},
		"other": {Host: "server", User: "deploy", Port: 22},
	}}
	locks := rotationTargetLocks(cfg, []string{"one", "two", "other"})
	if locks["one"] != locks["two"] {
		t.Fatal("aliases for the same account must share a rotation lock")
	}
	if locks["one"] == locks["other"] {
		t.Fatal("different remote users should not share a rotation lock")
	}
}

func TestPublicKeyLineAndKeyEditing(t *testing.T) {
	path, expected := testPrivateKey(t, "id_ed25519")
	line, parsed, err := PublicKeyLine(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Marshal(), expected.Marshal()) {
		t.Fatal("derived public key differs from private key")
	}
	base := []byte("# retained comment\ninvalid retained line\n")
	withKey := appendLine(base, line)
	if !containsKey(withKey, expected) {
		t.Fatal("appended key was not found")
	}
	withoutKey, removed := removeKey(withKey, expected)
	if !removed {
		t.Fatal("key was not removed")
	}
	if !bytes.Equal(withoutKey, base) {
		t.Fatalf("non-key lines changed:\n%s", withoutKey)
	}
}

func TestAppendLineNormalizesMissingTrailingNewline(t *testing.T) {
	got := appendLine([]byte("first"), "second\n")
	if string(got) != "first\nsecond\n" {
		t.Fatalf("got %q", got)
	}
}

func TestPublicKeyLineSupportsEncryptedKeySidecar(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "test", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_encrypted")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(want), 0o644); err != nil {
		t.Fatal(err)
	}
	_, got, err := PublicKeyLine(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), want.Marshal()) {
		t.Fatal("encrypted key sidecar yielded a different public key")
	}
}
