package fwdregistry

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withTempState points XDG_RUNTIME_DIR at a temp dir so registry entries
// don't pollute the user's real state. Returns the dir for assertions and
// creates it eagerly so tests that bypass Register (writing entry files
// directly) don't need to redo the MkdirAll dance.
func withTempState(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := StateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRegisterWritesFileAndListReadsIt(t *testing.T) {
	dir := withTempState(t)
	e, cleanup, err := Register("bastion", "L", "3000:internal:3000", "native", "direct")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if e.ID == "" || e.PID != os.Getpid() {
		t.Fatalf("registered entry looks off: %+v", e)
	}
	if _, err := os.Stat(filepath.Join(dir, e.ID+".json")); err != nil {
		t.Fatalf("entry file missing: %v", err)
	}
	got, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != e.ID || got[0].Alias != "bastion" {
		t.Errorf("List should round-trip the entry: got %+v", got)
	}
}

func TestCleanupRemovesFile(t *testing.T) {
	dir := withTempState(t)
	e, cleanup, err := Register("h", "D", "1080", "native", "direct")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Join(dir, e.ID+".json")); err == nil {
		t.Errorf("cleanup must remove the entry file")
	}
	got, _ := List()
	if len(got) != 0 {
		t.Errorf("List after cleanup must be empty, got %+v", got)
	}
}

func TestListPrunesDeadPID(t *testing.T) {
	dir := withTempState(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// PID 999999 is well above the typical pid_max — almost certainly dead.
	// Write a manual entry so we don't have to spawn-and-kill a real process.
	stalePath := filepath.Join(dir, "stale.json")
	stale := `{"id":"stale","alias":"h","type":"L","spec":"1:h:1","pid":999999,"started_at":"2026-01-01T00:00:00Z","backend":"native","source":"direct"}`
	if err := os.WriteFile(stalePath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("dead-PID entry must be pruned: %+v", got)
	}
	if _, err := os.Stat(stalePath); err == nil {
		t.Errorf("stale entry file should be removed on List")
	}
}

func TestIsAlive(t *testing.T) {
	if !IsAlive(os.Getpid()) {
		t.Error("our own PID should be alive")
	}
	if IsAlive(0) || IsAlive(-1) {
		t.Error("non-positive PIDs are never alive")
	}
}

func TestFindByIDAndPrefix(t *testing.T) {
	withTempState(t)
	e, cleanup, err := Register("h", "L", "1:h:1", "native", "direct")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// Full ID
	if got, err := Find(e.ID); err != nil || got.ID != e.ID {
		t.Errorf("Find by full ID: got %+v, err %v", got, err)
	}
	// Short prefix
	if got, err := Find(e.ID[:6]); err != nil || got.ID != e.ID {
		t.Errorf("Find by prefix: got %+v, err %v", got, err)
	}
	// No match
	if _, err := Find("deadbeef"); err == nil {
		t.Error("Find with no match must error")
	}
}

func TestFindAmbiguousPrefix(t *testing.T) {
	withTempState(t)
	// Two entries are very unlikely to share a 16-hex prefix by chance, so
	// craft files with deliberately colliding short IDs to exercise the
	// ambiguous-prefix branch.
	for _, id := range []string{"abc11111", "abc22222"} {
		body := `{"id":"` + id + `","alias":"h","type":"L","spec":"1:h:1","pid":` + fmt.Sprint(os.Getpid()) + `,"started_at":"2026-01-01T00:00:00Z","backend":"native","source":"direct"}`
		if err := os.WriteFile(filepath.Join(StateDir(), id+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Find("abc")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("expected an ambiguous-prefix error, got %v", err)
	}
}

func TestKillTerminatesProcessAndRemovesEntry(t *testing.T) {
	dir := withTempState(t)
	// Spawn a short-lived child we can ask the registry to kill.
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not spawn sleep child: %v", err)
	}
	// Reap the child eagerly so IsAlive (kill -0) doesn't see a zombie
	// when Kill's deadline checks it. In production the detached child is
	// reparented to init, so this is only a test-harness concern.
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	defer func() {
		_ = cmd.Process.Kill()
		<-done
	}()
	// Manually write an entry pointing at the child's PID.
	e := Entry{
		ID: "killtest1234", Alias: "h", Type: "L", Spec: "1:h:1",
		PID: cmd.Process.Pid, StartedAt: time.Now().UTC(),
		Backend: "native", Source: "direct",
	}
	data, _ := json.Marshal(e)
	if err := os.WriteFile(filepath.Join(dir, e.ID+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Kill(e, 2*time.Second); err != nil {
		t.Fatalf("Kill returned %v", err)
	}
	if IsAlive(e.PID) {
		t.Error("Kill must terminate the process")
	}
	if _, err := os.Stat(filepath.Join(dir, e.ID+".json")); err == nil {
		t.Error("Kill must remove the registry file")
	}
}
