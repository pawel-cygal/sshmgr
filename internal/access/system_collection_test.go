package access

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeSystemCollectionLimits(t *testing.T) {
	source, total, err := NormalizeSystemCollectionLimits(0, 0)
	if err != nil || source != defaultMaxSourceBytes || total != defaultMaxTotalSourceBytes {
		t.Fatalf("defaults: source=%d total=%d err=%v", source, total, err)
	}
	for name, limits := range map[string][2]int64{
		"negative source":       {-1, 1},
		"source above hard cap": {hardMaxSourceBytes + 1, hardMaxTotalSourceBytes},
		"total above hard cap":  {1, hardMaxTotalSourceBytes + 1},
		"source above total":    {2 << 20, 1 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NormalizeSystemCollectionLimits(limits[0], limits[1]); err == nil {
				t.Fatalf("invalid limits accepted: %v", limits)
			}
		})
	}
}

func TestApplySystemCollectionParsesMetadataAndKeys(t *testing.T) {
	uid, gid := uint64(1000), uint64(1000)
	key := testPublicKey(t)
	content := []byte(authorizedLine(key, "", "owner@laptop") + "\n")
	accounts := []AccountSnapshot{{
		Username: "deploy", UID: &uid, GID: &gid, Home: "/home/deploy",
		Sources: []KeySource{{Type: "authorized_keys_file", Path: "/home/deploy/.ssh/authorized_keys"}},
	}}
	protocol := fmt.Sprintf("%s\nSOURCE\t1\tfile\t600\t1000\t1000\t%d\tdirectory\t700\t1000\t1000\nCONTENT\t1\t%s\nCAP\ttotal_read\t%d\nCAP\tbudget_hit\tfalse\nEND\n",
		systemCollectionMagic, len(content), base64.StdEncoding.EncodeToString(content), len(content))
	stats, err := applySystemCollection([]byte(protocol), accounts, []systemCollectionTarget{{ID: 1}}, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	source := accounts[0].Sources[0]
	if !source.Exists || !source.ContentInspected || source.Mode != "0600" || source.Size != int64(len(content)) {
		t.Fatalf("source metadata mismatch: %+v", source)
	}
	if source.OwnerUID == nil || *source.OwnerUID != 1000 || source.ParentOwnerUID == nil || *source.ParentOwnerUID != 1000 {
		t.Fatalf("ownership metadata mismatch: %+v", source)
	}
	if source.ParentPath != "/home/deploy/.ssh" || source.ParentMode != "0700" {
		t.Fatalf("parent metadata mismatch: %+v", source)
	}
	if len(source.Entries) != 1 || source.Entries[0].Fingerprint == "" || source.Entries[0].PublicKey != "" {
		t.Fatalf("key observation mismatch: %+v", source.Entries)
	}
	if stats.SourcesInspected != 1 || stats.BytesRead != int64(len(content)) || stats.ContentBudgetHit {
		t.Fatalf("collection stats mismatch: %+v", stats)
	}
}

func TestApplySystemCollectionPreservesPerSourceLimitations(t *testing.T) {
	accounts := []AccountSnapshot{{Username: "deploy", Sources: []KeySource{
		{Type: "authorized_keys_file", Path: "/one"},
		{Type: "authorized_keys_file", Path: "/two"},
		{Type: "authorized_keys_file", Path: "/three"},
	}}}
	protocol := strings.Join([]string{
		systemCollectionMagic,
		"SOURCE\t1\tmissing\t-\t-\t-\t-\tdirectory\t755\t0\t0",
		"SOURCE\t2\tsymlink\t-\t-\t-\t-\tdirectory\t755\t0\t0",
		"SOURCE\t3\ttotal-limit\t600\t1000\t1000\t12\tdirectory\t700\t1000\t1000",
		"CAP\ttotal_read\t0",
		"CAP\tbudget_hit\ttrue",
		"END",
		"",
	}, "\n")
	targets := []systemCollectionTarget{{ID: 1, SourceIndex: 0}, {ID: 2, SourceIndex: 1}, {ID: 3, SourceIndex: 2}}
	stats, err := applySystemCollection([]byte(protocol), accounts, targets, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if accounts[0].Sources[0].Exists || accounts[0].Sources[0].Error != "" {
		t.Fatalf("missing source mismatch: %+v", accounts[0].Sources[0])
	}
	if !accounts[0].Sources[1].Symlink || accounts[0].Sources[1].Error == "" {
		t.Fatalf("symlink source mismatch: %+v", accounts[0].Sources[1])
	}
	if !accounts[0].Sources[2].Exists || !strings.Contains(accounts[0].Sources[2].Error, "per-host") || !stats.ContentBudgetHit {
		t.Fatalf("budget source mismatch: source=%+v stats=%+v", accounts[0].Sources[2], stats)
	}
}

func TestSystemCoverageCompleteRequiresExactStaticSources(t *testing.T) {
	complete := func() (*SystemSnapshot, []AccountSnapshot) {
		uid, gid := uint64(1000), uint64(1000)
		return &SystemSnapshot{
				Root: true, AccountDatabase: "getent-keyed", AccountsEnumerated: true,
				SourcesRequested: 1, SourcesInspected: 1,
				SSHD: SSHDConfigSnapshot{Present: true, ConfigValid: true, EffectiveConfig: true,
					AuthorizedKeysCommand: "none", TrustedUserCAKeys: "none",
					AuthorizedPrincipalsFile: "none", AuthorizedPrincipalsCommand: "none"},
			}, []AccountSnapshot{{
				Username: "audit", UID: &uid, GID: &gid, Home: "/home/audit",
				Auth: &AccountAuthSnapshot{EffectiveConfig: true, PubkeyAuthentication: "yes",
					AuthorizedKeysCommand: "none", TrustedUserCAKeys: "none",
					AuthorizedPrincipalsFile: "none", AuthorizedPrincipalsCommand: "none"},
				Sources: []KeySource{{Type: "authorized_keys_file", Path: "/home/audit/.ssh/authorized_keys",
					Exists: true, ContentInspected: true, ContentSHA256: ContentDigest([]byte("key\n"))}},
			}}
	}

	system, accounts := complete()
	if !systemCoverageComplete(system, accounts) {
		t.Fatal("complete static source did not receive full coverage")
	}

	for name, breakCoverage := range map[string]func(*SystemSnapshot, []AccountSnapshot){
		"dynamic key command": func(_ *SystemSnapshot, accounts []AccountSnapshot) {
			accounts[0].Auth.AuthorizedKeysCommand = "/usr/local/bin/keys"
		},
		"trusted CA": func(system *SystemSnapshot, _ []AccountSnapshot) {
			system.SSHD.TrustedUserCAKeys = "/etc/ssh/ca.pub"
		},
		"account missing": func(system *SystemSnapshot, _ []AccountSnapshot) {
			system.MissingAccounts = []string{"audit"}
		},
		"source truncated": func(system *SystemSnapshot, _ []AccountSnapshot) {
			system.SourcesTruncated = true
		},
		"source error": func(_ *SystemSnapshot, accounts []AccountSnapshot) {
			accounts[0].Sources[0].Error = "read failed"
		},
		"source not inspected": func(_ *SystemSnapshot, accounts []AccountSnapshot) {
			accounts[0].Sources[0].ContentInspected = false
		},
		"public key disabled": func(_ *SystemSnapshot, accounts []AccountSnapshot) {
			accounts[0].Auth.PubkeyAuthentication = "no"
		},
	} {
		t.Run(name, func(t *testing.T) {
			system, accounts := complete()
			breakCoverage(system, accounts)
			if systemCoverageComplete(system, accounts) {
				t.Fatal("incomplete coverage was promoted to full")
			}
		})
	}

	system, accounts = complete()
	accounts[0].Sources[0] = KeySource{Type: "authorized_keys_file", Path: "/home/audit/.ssh/authorized_keys"}
	system.SourcesInspected = 0
	if !systemCoverageComplete(system, accounts) {
		t.Fatal("an exactly observed missing static source should retain full coverage")
	}
}

func TestSystemCollectionScriptReadsOnlyRequestedRegularFile(t *testing.T) {
	if _, err := exec.LookPath("base64"); err != nil {
		t.Skip("base64 is unavailable")
	}
	directory := filepath.Join(t.TempDir(), "home with spaces", ".ssh")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	key := testPublicKey(t)
	content := []byte(authorizedLine(key, "", "script@test") + "\n")
	sourcePath := filepath.Join(directory, "authorized_keys")
	if err := os.WriteFile(sourcePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	accounts := []AccountSnapshot{{Username: "test", Sources: []KeySource{{Type: "authorized_keys_file", Path: sourcePath}}}}
	request, targets, requested, truncated := buildSystemCollectionRequest(accounts)
	if requested != 1 || truncated || len(targets) != 1 {
		t.Fatalf("request mismatch: requested=%d truncated=%t targets=%+v", requested, truncated, targets)
	}
	command := exec.Command("sh", "-c", systemCollectionScript, "sshmgr-system-collection", "1048576", "1048576")
	command.Stdin = strings.NewReader(request)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("collector script failed: %v", err)
	}
	stats, err := applySystemCollection(output, accounts, targets, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only system collector changed the source file")
	}
	if stats.SourcesInspected != 1 || len(accounts[0].Sources[0].Entries) != 1 {
		t.Fatalf("script collection mismatch: stats=%+v source=%+v", stats, accounts[0].Sources[0])
	}
}

func TestSystemCollectionScriptRefusesSymlinkedSource(t *testing.T) {
	if _, err := exec.LookPath("base64"); err != nil {
		t.Skip("base64 is unavailable")
	}
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "real-keys")
	if err := os.WriteFile(targetPath, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "authorized_keys")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatal(err)
	}
	accounts := []AccountSnapshot{{Username: "test", Sources: []KeySource{{Type: "authorized_keys_file", Path: linkPath}}}}
	request, targets, _, _ := buildSystemCollectionRequest(accounts)
	command := exec.Command("sh", "-c", systemCollectionScript, "sshmgr-system-collection", "1048576", "1048576")
	command.Stdin = strings.NewReader(request)
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	stats, err := applySystemCollection(output, accounts, targets, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !accounts[0].Sources[0].Symlink || accounts[0].Sources[0].ContentInspected || stats.SourcesInspected != 0 {
		t.Fatalf("symlink was not safely refused: stats=%+v source=%+v", stats, accounts[0].Sources[0])
	}
}

func TestSystemCollectionRemoteCommandContainsNoRequestedPath(t *testing.T) {
	options := ScanOptions{MaxSourceBytes: 4 << 20, MaxTotalBytes: 16 << 20}
	command := systemCollectionRemoteCommand(options, true)
	if !strings.HasPrefix(command, "sudo -n sh -c ") || !strings.HasSuffix(command, " sshmgr-system-collection 4194304 16777216") {
		t.Fatalf("unexpected remote command framing: %q", command)
	}
	if strings.Contains(command, "/home/deploy/.ssh/authorized_keys") {
		t.Fatal("a requested path leaked into the remote command")
	}
}

func TestApplySystemCollectionRejectsMalformedProtocol(t *testing.T) {
	accounts := []AccountSnapshot{{Username: "root", Sources: []KeySource{{Path: "/root/.ssh/authorized_keys"}}}}
	targets := []systemCollectionTarget{{ID: 1}}
	for name, protocol := range map[string]string{
		"bad header":       "wrong\nEND\n",
		"missing source":   systemCollectionMagic + "\nCAP\ttotal_read\t0\nEND\n",
		"duplicate source": systemCollectionMagic + "\nSOURCE\t1\tmissing\t-\t-\t-\t-\tmissing\t-\t-\t-\nSOURCE\t1\tmissing\t-\t-\t-\t-\tmissing\t-\t-\t-\nEND\n",
		"bad base64":       systemCollectionMagic + "\nSOURCE\t1\tfile\t600\t0\t0\t1\tdirectory\t700\t0\t0\nCONTENT\t1\t%%%\nEND\n",
	} {
		t.Run(name, func(t *testing.T) {
			copyAccounts := append([]AccountSnapshot(nil), accounts...)
			if _, err := applySystemCollection([]byte(protocol), copyAccounts, targets, false, 1<<20); err == nil {
				t.Fatalf("malformed protocol accepted: %q", protocol)
			}
		})
	}
}

func FuzzApplySystemCollection(f *testing.F) {
	f.Add([]byte(systemCollectionMagic + "\nSOURCE\t1\tmissing\t-\t-\t-\t-\tmissing\t-\t-\t-\nCAP\ttotal_read\t0\nEND\n"))
	f.Add([]byte("not-a-protocol\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2<<20 {
			t.Skip()
		}
		accounts := []AccountSnapshot{{Username: "root", Sources: []KeySource{{Path: "/root/.ssh/authorized_keys"}}}}
		_, _ = applySystemCollection(input, accounts, []systemCollectionTarget{{ID: 1}}, false, 1<<20)
	})
}
