// Package fwdregistry tracks the port-forwards live in this user's sshmgr
// processes. One JSON file per active forward in StateDir() — Register
// writes the file, the returned cleanup func removes it on graceful exit,
// and List filters out entries whose owning PID has died (best-effort:
// sshmgr crashed with kill -9 leaves a stale file the next List sweeps).
package fwdregistry

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Entry describes one live forward. The fields are stable JSON so a future
// version of sshmgr can read entries left by an older one.
type Entry struct {
	ID        string    `json:"id"`
	Alias     string    `json:"alias"`
	Type      string    `json:"type"` // "L" | "R" | "D"
	Spec      string    `json:"spec"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Backend   string    `json:"backend"` // "native" | "external"
	Source    string    `json:"source"`  // "direct" | "saved:<name>" | "tui"
}

// StateDir returns the directory holding registry entries. Uses
// $XDG_RUNTIME_DIR when set (per-user, cleaned on logout on most systems)
// and falls back to a per-UID directory under the OS temp dir.
func StateDir() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "sshmgr", "forwards")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("sshmgr-%d-forwards", os.Getuid()))
}

// Register writes a new entry to StateDir() and returns it along with a
// cleanup func the caller MUST defer — Cleanup removes the entry file
// (or no-ops if it's already gone). On error the file is not written and
// the returned cleanup is a no-op.
func Register(alias, typ, spec, backend, source string) (Entry, func(), error) {
	dir := StateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Entry{}, func() {}, err
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return Entry{}, func() {}, err
	}
	id := hex.EncodeToString(buf[:])
	e := Entry{
		ID: id, Alias: alias, Type: typ, Spec: spec,
		PID: os.Getpid(), StartedAt: time.Now().UTC(),
		Backend: backend, Source: source,
	}
	data, err := json.Marshal(e)
	if err != nil {
		return Entry{}, func() {}, err
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return Entry{}, func() {}, err
	}
	cleanup := func() { _ = os.Remove(path) }
	return e, cleanup, nil
}

// List returns every live forward, sorted by start time. Stale entries
// (owning PID gone) are silently pruned so a kill -9 doesn't leave the
// registry permanently dirty.
func List() ([]Entry, error) {
	dir := StateDir()
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, en := range dirEntries {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, en.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			continue
		}
		if !IsAlive(e.PID) {
			_ = os.Remove(path)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

// IsAlive reports whether pid still names a live process owned (or visible
// to) the current user. signal 0 is a probe — success means the process
// exists; ESRCH means it's gone; EPERM means it exists but isn't ours
// (which on Linux happens after PID reuse — treat as alive).
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Find returns the live entry matching id exactly or by ID prefix (the
// short 8-char form `fwd active` prints). The error distinguishes "no
// match" from "ambiguous prefix" so callers can give a useful hint.
func Find(idOrPrefix string) (Entry, error) {
	entries, err := List()
	if err != nil {
		return Entry{}, err
	}
	var matches []Entry
	for _, e := range entries {
		if e.ID == idOrPrefix || (idOrPrefix != "" && strings.HasPrefix(e.ID, idOrPrefix)) {
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 0:
		return Entry{}, fmt.Errorf("no active forward matching %q (try `sshmgr fwd active`)", idOrPrefix)
	case 1:
		return matches[0], nil
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.ID[:8])
		}
		return Entry{}, fmt.Errorf("%q is an ambiguous prefix (%d matches: %s) — use a longer ID", idOrPrefix, len(matches), strings.Join(ids, ", "))
	}
}

// Kill sends SIGTERM to the entry's PID, waits up to timeout for graceful
// exit, then escalates to SIGKILL if the process is still alive. The
// registry file is removed regardless of how the process died — the
// returned error reports problems sending the signal or a process that
// survived both signals.
func Kill(e Entry, timeout time.Duration) error {
	proc, err := os.FindProcess(e.PID)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			_ = os.Remove(filepath.Join(StateDir(), e.ID+".json"))
			return nil // already dead — treat as success
		}
		return fmt.Errorf("send SIGTERM to pid %d: %w", e.PID, err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsAlive(e.PID) {
			_ = os.Remove(filepath.Join(StateDir(), e.ID+".json"))
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	// SIGTERM didn't take in time — escalate. Best-effort: the registry
	// file goes regardless so a stuck process doesn't keep the entry alive.
	_ = proc.Signal(syscall.SIGKILL)
	time.Sleep(100 * time.Millisecond)
	_ = os.Remove(filepath.Join(StateDir(), e.ID+".json"))
	if IsAlive(e.PID) {
		return fmt.Errorf("pid %d did not exit after SIGTERM+SIGKILL", e.PID)
	}
	return nil
}
