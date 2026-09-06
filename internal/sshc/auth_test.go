package sshc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func encryptedTestKeyMaterial(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func encryptedTestKey(t *testing.T) string {
	path, _ := encryptedTestKeyMaterial(t)
	return path
}

func TestAuthMethodsEncryptedKeyRequiresAgentOrPassword(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := encryptedTestKey(t)

	_, cleanup, err := authMethods(config.HostConfig{Key: path})
	cleanup()
	if err == nil || !strings.Contains(err.Error(), "ssh-add") {
		t.Fatalf("expected actionable encrypted-key error, got %v", err)
	}
}

func TestAuthMethodsEncryptedKeyCanUseAgent(t *testing.T) {
	path := encryptedTestKey(t)
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = agent.ServeAgent(agent.NewKeyring(), conn)
		_ = conn.Close()
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	methods, cleanup, err := authMethods(config.HostConfig{Key: path})
	if err != nil {
		t.Fatalf("encrypted key with agent: %v", err)
	}
	if len(methods) != 2 { // agent public key + keyboard-interactive fallback
		t.Fatalf("got %d methods, want 2", len(methods))
	}
	cleanup()
	<-done
}

func TestAuthMethodsKeyOnlySelectsEncryptedKeyFromAgent(t *testing.T) {
	path, private := encryptedTestKeyMaterial(t)
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = agent.ServeAgent(keyring, conn)
		_ = conn.Close()
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	methods, cleanup, err := authMethods(config.HostConfig{Key: path, KeyOnly: true})
	if err != nil {
		t.Fatalf("encrypted key-only auth: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("key-only auth offered %d methods, want exactly 1", len(methods))
	}
	cleanup()
	<-done
}

func TestAuthMethodsMissingConfiguredKeyIsError(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, cleanup, err := authMethods(config.HostConfig{Key: filepath.Join(t.TempDir(), "missing")})
	cleanup()
	if err == nil || !strings.Contains(err.Error(), "cannot read SSH key") {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestAuthMethodsBatchModeNeverAddsInteractiveFallback(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_batch")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	methods, cleanup, err := authMethods(config.HostConfig{
		Key:            path,
		PasswordPrompt: true,
		AutoDuoPush:    true,
		BatchMode:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(methods) != 1 {
		t.Fatalf("batch auth offered %d methods, want only the configured key", len(methods))
	}
}

func TestAuthMethodsBatchModeRejectsPromptOnlyAuth(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, cleanup, err := authMethods(config.HostConfig{PasswordPrompt: true, BatchMode: true})
	cleanup()
	if err == nil || !strings.Contains(err.Error(), "no non-interactive") {
		t.Fatalf("expected batch-mode non-interactive error, got %v", err)
	}
}

func TestHostKeyCallbackBatchModeNeverTrustsUnknownHost(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHMGR_KNOWN_HOSTS", knownHosts)
	callback, err := hostKeyCallback(true, true)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	err = callback("new.example:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}, key)
	if err == nil || !strings.Contains(err.Error(), "unknown host key") {
		t.Fatalf("batch mode trusted an unknown key: %v", err)
	}
	data, err := os.ReadFile(knownHosts)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("batch mode modified known_hosts: %q", data)
	}
}

func TestHostKeyCallbackBatchModeRequiresExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "known_hosts")
	t.Setenv("SSHMGR_KNOWN_HOSTS", path)
	if _, err := hostKeyCallback(false, true); err == nil || !strings.Contains(err.Error(), "requires an existing") {
		t.Fatalf("missing known_hosts accepted in batch mode: %v", err)
	}
}

func TestNewClientConnTimeoutBoundsSilentHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	started := time.Now()
	_, _, _, err := newClientConnTimeout(client, "silent:22", &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // no key is ever received
	}, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected handshake timeout, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("handshake timeout took %s", elapsed)
	}
}
