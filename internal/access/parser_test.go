package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func authorizedLine(key ssh.PublicKey, prefix, comment string) string {
	return prefix + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + comment
}

func TestParseAuthorizedKeysNormalizesEntries(t *testing.T) {
	key := testPublicKey(t)
	input := "# ignored\r\n\r\n" + authorizedLine(key, `from="10.0.0.0/8",no-port-forwarding `, "pawel@laptop") + "\r\nnot-a-key\n"
	entries, err := ParseAuthorizedKeys([]byte(input), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d observations, want 2", len(entries))
	}
	valid := entries[0]
	if valid.Line != 3 || valid.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("unexpected normalized entry: %+v", valid)
	}
	if valid.Algorithm != ssh.KeyAlgoED25519 || valid.Bits != 256 || valid.Comment != "pawel@laptop" {
		t.Fatalf("unexpected key metadata: %+v", valid)
	}
	if len(valid.Options) != 2 || valid.PublicKey != "" {
		t.Fatalf("options or redaction mismatch: %+v", valid)
	}
	if entries[1].Line != 4 || entries[1].ParseError == "" {
		t.Fatalf("malformed entry was hidden: %+v", entries[1])
	}
}

func TestParseAuthorizedKeysPublicKeyIsOptIn(t *testing.T) {
	key := testPublicKey(t)
	entries, err := ParseAuthorizedKeys([]byte(authorizedLine(key, "", "key comment")), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].PublicKey, ssh.KeyAlgoED25519+" ") {
		t.Fatalf("normalized public key missing: %+v", entries)
	}
	if strings.Contains(entries[0].PublicKey, "key comment") {
		t.Fatal("normalized public key unexpectedly includes the untrusted comment")
	}
}

func TestParseAuthorizedKeysCertificateAuthorityAndSecurityKey(t *testing.T) {
	ca := testPublicKey(t)
	caLine := authorizedLine(ca, "cert-authority ", "team ssh ca")
	skLine := "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIJjzc2a20RjCvN/0ibH6UpGuN9F9hDvD7x182bOesNhHAAAABHNzaDo= hardware-key"
	entries, err := ParseAuthorizedKeys([]byte(caLine+"\n"+skLine+"\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if len(entries[0].Options) != 1 || entries[0].Options[0] != "cert-authority" {
		t.Fatalf("CA option not preserved: %+v", entries[0])
	}
	if entries[1].Algorithm != ssh.KeyAlgoSKED25519 || entries[1].Fingerprint == "" || entries[1].ParseError != "" {
		t.Fatalf("security key not normalized: %+v", entries[1])
	}
}

func TestParseAuthorizedKeysVeryLongLineIsBounded(t *testing.T) {
	_, err := ParseAuthorizedKeys([]byte(strings.Repeat("x", maxAuthorizedKeyLineBytes+1)), false)
	if err == nil || !strings.Contains(err.Error(), "line exceeds") {
		t.Fatalf("expected bounded scanner error, got %v", err)
	}
}

func TestFinalizeDerivesStableSummary(t *testing.T) {
	snapshot := NewSnapshot("test", Scope{Mode: "current"}, testTime)
	snapshot.Hosts = []HostSnapshot{
		{Alias: "z", Coverage: CoverageFailed},
		{Alias: "a", Coverage: CoveragePartial, Accounts: []AccountSnapshot{{Username: "root", Sources: []KeySource{{Exists: true, Entries: []KeyObservation{{Line: 2, Fingerprint: "SHA256:one"}, {Line: 1, Fingerprint: "SHA256:one"}, {Line: 3, ParseError: "bad"}}}}}}},
	}
	snapshot.Finalize(testTime)
	if snapshot.Hosts[0].Alias != "a" {
		t.Fatalf("hosts are not stable: %+v", snapshot.Hosts)
	}
	want := Summary{HostsRequested: 2, HostsPartial: 1, HostsFailed: 1, AccountsObserved: 1, KeySourcesFound: 1, AuthorizedKeyEntries: 2, MalformedEntries: 1, UniqueFingerprints: 1, FindingsTotal: 3, FindingsHigh: 1, FindingsLow: 1, FindingsInfo: 1}
	if snapshot.Summary != want {
		t.Fatalf("summary = %+v, want %+v", snapshot.Summary, want)
	}
}

func FuzzParseAuthorizedKeys(f *testing.F) {
	f.Add([]byte("# comment\n"))
	f.Add([]byte("not a key\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxAuthorizedKeyLineBytes*2 {
			t.Skip()
		}
		_, _ = ParseAuthorizedKeys(data, false)
	})
}
