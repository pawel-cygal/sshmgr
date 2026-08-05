package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// runtimeState is intentionally separate from the declarative inventory.
// Operational events may be written by many short- and long-lived sshmgr
// processes; they must never serialize a stale Config over user edits.
type runtimeState struct {
	ForwardHistory  []ForwardEntry  `yaml:"forward_history,omitempty"`
	TransferHistory []TransferEntry `yaml:"transfer_history,omitempty"`
	LoginHistory    []LoginEntry    `yaml:"login_history,omitempty"`
}

func runtimeStatePath(configPath string) string {
	if p := os.Getenv("SSHMGR_STATE"); p != "" {
		return ExpandPath(p)
	}
	if os.Getenv("SSHMGR_CONFIG") != "" {
		return configPath + ".state.yaml"
	}
	if base := os.Getenv("XDG_STATE_HOME"); base != "" {
		return filepath.Join(base, "sshmgr", "state.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "sshmgr", "state.yaml")
	}
	return configPath + ".state.yaml"
}

func runtimeStateFromConfig(cfg *Config) runtimeState {
	return runtimeState{
		ForwardHistory:  append([]ForwardEntry(nil), cfg.ForwardHistory...),
		TransferHistory: append([]TransferEntry(nil), cfg.TransferHistory...),
		LoginHistory:    append([]LoginEntry(nil), cfg.LoginHistory...),
	}
}

func hasRuntimeState(cfg *Config) bool {
	return len(cfg.ForwardHistory) > 0 || len(cfg.TransferHistory) > 0 || len(cfg.LoginHistory) > 0
}

func applyRuntimeState(cfg *Config, state runtimeState) {
	cfg.ForwardHistory = state.ForwardHistory
	cfg.TransferHistory = state.TransferHistory
	cfg.LoginHistory = state.LoginHistory
}

func loadRuntimeState(configPath string) (runtimeState, bool, error) {
	path := runtimeStatePath(configPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return runtimeState{}, false, nil
		}
		return runtimeState{}, false, fmt.Errorf("cannot read runtime state %s: %w", path, err)
	}
	var state runtimeState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return runtimeState{}, false, fmt.Errorf("cannot parse runtime state %s: %w", path, err)
	}
	return state, true, nil
}

func replaceRuntimeState(configPath string, state runtimeState) error {
	path := runtimeStatePath(configPath)
	return withFileLock(path, func() error { return saveRuntimeState(path, state) })
}

func updateRuntimeState(configPath string, update func(*runtimeState)) error {
	path := runtimeStatePath(configPath)
	return withFileLock(path, func() error {
		state, ok, err := loadRuntimeState(configPath)
		if err != nil {
			return err
		}
		if !ok {
			state = runtimeState{}
		}
		update(&state)
		return saveRuntimeState(path, state)
	})
}

func saveRuntimeState(path string, state runtimeState) error {
	data, err := yaml.Marshal(&state)
	if err != nil {
		return fmt.Errorf("marshal runtime state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create runtime state dir: %w", err)
	}
	return atomicWrite(path, data, 0o600)
}

// RecordLogin records one successful user-visible action without touching the
// declarative config file.
func RecordLogin(configPath, alias, action string, when time.Time) error {
	return updateRuntimeState(configPath, func(state *runtimeState) {
		entry := LoginEntry{Alias: alias, Action: action, When: when.UTC().Format(time.RFC3339)}
		state.LoginHistory = append([]LoginEntry{entry}, state.LoginHistory...)
		if len(state.LoginHistory) > 500 {
			state.LoginHistory = state.LoginHistory[:500]
		}
	})
}

// RecordTransfer records a completed transfer without rewriting inventory.
func RecordTransfer(configPath string, entry TransferEntry) error {
	return updateRuntimeState(configPath, func(state *runtimeState) {
		state.TransferHistory = append([]TransferEntry{entry}, state.TransferHistory...)
		if len(state.TransferHistory) > 200 {
			state.TransferHistory = state.TransferHistory[:200]
		}
	})
}

// RecordForward updates the MRU forward list without rewriting inventory.
func RecordForward(configPath string, entry ForwardEntry) error {
	return updateRuntimeState(configPath, func(state *runtimeState) {
		out := []ForwardEntry{entry}
		for _, old := range state.ForwardHistory {
			if old.Alias == entry.Alias && old.Type == entry.Type && old.Spec == entry.Spec {
				continue
			}
			out = append(out, old)
			if len(out) >= 20 {
				break
			}
		}
		state.ForwardHistory = out
	})
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sshmgr-write-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return nil
}

// withFileLock serializes sshmgr writers across processes. The kernel releases
// the advisory lock when a process exits, so a crash cannot leave a stale lock
// behind and no writer ever has to race another writer while deleting one.
func withFileLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock %s: %w", lockPath, err)
	}
	defer f.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
			return fn()
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for lock %s", lockPath)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
