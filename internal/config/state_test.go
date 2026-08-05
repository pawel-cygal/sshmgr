package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func isolatedConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	t.Setenv("SSHMGR_CONFIG", path)
	t.Setenv("SSHMGR_STATE", filepath.Join(dir, "state.yaml"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRejectsUnknownConfigFields(t *testing.T) {
	isolatedConfig(t, "hosts:\n  a:\n    host: example\n    conenct_timeout: 5\n")
	if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), "conenct_timeout") {
		t.Fatalf("unknown field should fail with its name, got %v", err)
	}
}

func TestRuntimeHistoryMigratesAndNeverReturnsToConfig(t *testing.T) {
	path := isolatedConfig(t, "hosts:\n  a:\n    host: example\nlogin_history:\n  - alias: a\n    action: connect\n    when: 2026-01-01T00:00:00Z\n")
	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LoginHistory) != 1 {
		t.Fatalf("legacy history not loaded: %+v", cfg.LoginHistory)
	}
	if err := Save(cfg, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "login_history") {
		t.Fatalf("runtime history remained in config:\n%s", data)
	}
	if err := RecordLogin(path, "a", "sftp", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	reloaded, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.LoginHistory) != 2 || reloaded.LoginHistory[0].Action != "sftp" {
		t.Fatalf("state history not overlaid: %+v", reloaded.LoginHistory)
	}
}

func TestSaveRejectsStaleConfigSnapshot(t *testing.T) {
	path := isolatedConfig(t, "hosts:\n  a:\n    host: one\n")
	first, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	stale, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	h := first.Hosts["a"]
	h.Host = "new"
	first.Hosts["a"] = h
	if err := Save(first, path); err != nil {
		t.Fatal(err)
	}
	h = stale.Hosts["a"]
	h.Host = "stale"
	stale.Hosts["a"] = h
	if err := Save(stale, path); err == nil || !strings.Contains(err.Error(), "changed on disk") {
		t.Fatalf("stale save should be rejected, got %v", err)
	}
}

func TestConcurrentRuntimeWritersDoNotLoseEntries(t *testing.T) {
	path := isolatedConfig(t, "hosts: {}\n")
	const writers = 40
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- RecordLogin(path, fmt.Sprintf("h-%d", i), "connect", time.Unix(int64(i), 0))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LoginHistory) != writers {
		t.Fatalf("lost concurrent history entries: got %d want %d", len(cfg.LoginHistory), writers)
	}
}
