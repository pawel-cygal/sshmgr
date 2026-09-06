package accessplan

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestReadSigningPrivateKeyAcceptsOpenSSHEd25519(t *testing.T) {
	_, privateKey, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "plan@test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan-signer")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadSigningPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, privateKey) {
		t.Fatal("loaded signing key differs from the OpenSSH private key")
	}
}
