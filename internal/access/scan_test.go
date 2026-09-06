package access

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
)

func TestScanCurrentWorkerPoolAndOrdering(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"a": {}, "b": {}, "c": {}}}
	var active atomic.Int32
	var maximum atomic.Int32
	collector := func(_ context.Context, _ *config.Config, alias string, _ ScanOptions) HostSnapshot {
		now := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if now <= old || maximum.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		return HostSnapshot{Alias: alias, Coverage: CoveragePartial}
	}
	snapshot := scanCurrentWith(context.Background(), cfg, []string{"c", "a", "b"}, ScanOptions{Parallel: 2}, collector)
	if maximum.Load() > 2 {
		t.Fatalf("parallelism exceeded: %d", maximum.Load())
	}
	if snapshot.Hosts[0].Alias != "a" || snapshot.Hosts[2].Alias != "c" {
		t.Fatalf("snapshot order is not deterministic: %+v", snapshot.Hosts)
	}
	if snapshot.Summary.HostsPartial != 3 {
		t.Fatalf("unexpected summary: %+v", snapshot.Summary)
	}
}

func TestBatchConfigDisablesInteractiveAuthAndBoundsTimeout(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"slow": {ConnectTimeout: 100, PasswordPrompt: true},
		"fast": {ConnectTimeout: 2},
	}}
	clone := batchConfig(cfg, 3500*time.Millisecond)
	if !clone.Hosts["slow"].BatchMode || clone.Hosts["slow"].ConnectTimeout != 4 {
		t.Fatalf("slow host was not bounded: %+v", clone.Hosts["slow"])
	}
	if clone.Hosts["fast"].ConnectTimeout != 2 {
		t.Fatalf("shorter configured timeout changed: %+v", clone.Hosts["fast"])
	}
	if cfg.Hosts["slow"].BatchMode {
		t.Fatal("source config was mutated")
	}
}

func TestParseFallbackSource(t *testing.T) {
	key := testPublicKey(t)
	content := []byte(authorizedLine(key, "", "fallback@test") + "\n")
	header := []byte("F\t600\t" + fmt.Sprint(len(content)) + "\n")
	source := parseFallbackSource(".ssh/authorized_keys", append(header, content...), false, false)
	if source.Error != "" || !source.Exists || !source.ContentInspected || source.Mode != "0600" || len(source.Entries) != 1 {
		t.Fatalf("fallback source mismatch: %+v", source)
	}
	preflight := parseFallbackSource(".ssh/authorized_keys", []byte("F\t644\t123\n"), false, true)
	if preflight.Error != "" || preflight.ContentInspected || preflight.Size != 123 || preflight.Mode != "0644" {
		t.Fatalf("preflight fallback mismatch: %+v", preflight)
	}
	missing := parseFallbackSource(".ssh/authorized_keys", []byte("M\n"), false, false)
	if missing.Exists || missing.Error != "" {
		t.Fatalf("missing source mismatch: %+v", missing)
	}
}

func TestFallbackProtocolRejectsTruncationAndArbitraryPaths(t *testing.T) {
	source := parseFallbackSource(".ssh/authorized_keys", []byte("F\t600\t10\nshort"), false, false)
	if source.Error == "" || !strings.Contains(source.Error, "expected 10") {
		t.Fatalf("truncated content accepted: %+v", source)
	}
	if command, ok := fixedReadOnlySourceCommand("../../etc/shadow", false); ok || command != "" {
		t.Fatal("fallback accepted an arbitrary path")
	}
	for _, path := range defaultCurrentAccountSources {
		command, ok := fixedReadOnlySourceCommand(path, false)
		if !ok || !strings.Contains(command, "cat \"$p\"") {
			t.Fatalf("fixed command missing for %s", path)
		}
	}
}

func TestProxyCommandInChainRejectsInteractiveExternalTransport(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"target": {ProxyJump: "jump"},
		"jump":   {ProxyCommand: "ssh bastion -W %h:%p"},
		"direct": {},
	}}
	if got := proxyCommandInChain(cfg, "target", map[string]bool{}); got != "jump" {
		t.Fatalf("unsafe proxy command resolved to %q", got)
	}
	if got := proxyCommandInChain(cfg, "direct", map[string]bool{}); got != "" {
		t.Fatalf("direct host marked unsafe at %q", got)
	}
}

func TestClassifyExternalSSHFailure(t *testing.T) {
	for name, test := range map[string]struct {
		stderr string
		want   string
	}{
		"host key":    {"Host key verification failed.\n", "host-key verification failed"},
		"changed key": {"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", "host-key verification failed"},
		"auth":        {"user@host: Permission denied (publickey).", "authentication failed"},
		"refused":     {"connect to host x port 22: Connection refused", "connection refused"},
		"timeout":     {"ssh: connect to host x port 22: Connection timed out", "connection timed out"},
		"dns":         {"ssh: Could not resolve hostname x: Name or service not known", "hostname resolution failed"},
		"reset":       {"kex_exchange_identification: Connection closed by remote host", "connection reset during SSH handshake"},
		"config":      {"command-line: line 0: Bad configuration option: nope", "invalid OpenSSH configuration"},
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyExternalSSHFailure(255, test.stderr)
			if !strings.Contains(got, test.want) || !strings.Contains(got, "status 255") {
				t.Fatalf("classification = %q, want category %q", got, test.want)
			}
			if strings.Contains(got, "user@host") || strings.Contains(got, "command-line") {
				t.Fatalf("raw OpenSSH stderr leaked into classification: %q", got)
			}
		})
	}
	if got := classifyExternalSSHFailure(23, "secret remote stderr"); got != "external OpenSSH collector exited with status 23" {
		t.Fatalf("fallback classification = %q", got)
	}
}
