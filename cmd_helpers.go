package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sshmgr/internal/config"
	exec_ "sshmgr/internal/exec"
	"sshmgr/internal/external"

)

func selectAliases(cfg *config.Config, group, tag, hosts string, all bool) []string {
	sel := exec_.Selector{Group: group, Tag: tag, All: all}
	if hosts != "" {
		for _, h := range strings.Split(hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				sel.Hosts = append(sel.Hosts, h)
			}
		}
	}
	aliases := exec_.Select(cfg, sel)
	if len(aliases) == 0 {
		fatal("no hosts matched the selector (try --group, --tag, --host, or --all)")
	}
	return aliases
}

// cmdExport dispatches `sshmgr export <target>`. The only target today is
// `ansible` — an Ansible inventory generated from the fleet.
func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// splitPlaybookArgs separates the playbook argument from the flag tokens, so
// `playbook <file> --group g` works despite Go's flag parser stopping at the
// first non-flag token. The first bare token is the playbook.
func recordLogin(alias, action string) {
	cfg, path, err := config.Load()
	if err != nil {
		return
	}
	cfg.LoginHistory = append([]config.LoginEntry{{
		Alias:  alias,
		Action: action,
		When:   time.Now().UTC().Format(time.RFC3339),
	}}, cfg.LoginHistory...)
	if len(cfg.LoginHistory) > 500 {
		cfg.LoginHistory = cfg.LoginHistory[:500]
	}
	_ = config.Save(cfg, path)
}

// persistTransferLog appends a TransferEntry to the config file, capped at 200.
// Best-effort: silently swallows save errors so a flaky write doesn't break
// the user's transfer.
func persistTransferLog(direction, alias, local, remote string, n int64, when time.Time) {
	cfg, path, err := config.Load()
	if err != nil {
		return
	}
	e := config.TransferEntry{
		Alias:     alias,
		Direction: direction,
		Local:     local,
		Remote:    remote,
		Bytes:     n,
		When:      when.UTC().Format(time.RFC3339),
	}
	out := append([]config.TransferEntry{e}, cfg.TransferHistory...)
	if len(out) > 200 {
		out = out[:200]
	}
	cfg.TransferHistory = out
	_ = config.Save(cfg, path)
}

func upsertForward(hist []config.ForwardEntry, e config.ForwardEntry, cap int) []config.ForwardEntry {
	out := make([]config.ForwardEntry, 0, len(hist)+1)
	out = append(out, e)
	for _, h := range hist {
		if h.Alias == e.Alias && h.Type == e.Type && h.Spec == e.Spec {
			continue
		}
		out = append(out, h)
		if len(out) >= cap {
			break
		}
	}
	return out
}

func sessionLogPath(alias string) string {
	dir := os.Getenv("SSHMGR_SESSION_DIR")
	if dir == "" {
		if base := os.Getenv("XDG_DATA_HOME"); base != "" {
			dir = filepath.Join(base, "sshmgr", "sessions")
		} else {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, ".local", "share", "sshmgr", "sessions")
		}
	}
	// Include PID so two operators on the same host within the same second
	// don't share a log file (would interleave their sessions).
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dir, fmt.Sprintf("%s-%s-%d.log", alias, stamp, os.Getpid()))
}

// maybeReturnToUI re-execs `sshmgr ui` when SSHMGR_FROM_UI=1 is set in the
// environment, so a TUI-launched connection drops the user back into the host
// list after the remote shell exits.
func maybeReturnToUI() {
	if os.Getenv("SSHMGR_FROM_UI") != "1" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	env := os.Environ()
	// Keep SSHMGR_FROM_UI=1 so subsequent connect-from-TUI loops work.
	_ = syscall.Exec(exe, []string{"sshmgr", "ui"}, env)
}

func lookPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		p := dir + "/" + name
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found in PATH: %s", name)
}

// parseCompleteArgs interprets the tokens after "__complete". Shells pass the
// partial word followed by already-typed tokens; fish prefixes a literal
// "--" separator, which is dropped.
func parseCompleteArgs(args []string) (passed []string, word string) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return nil, ""
	}
	if len(args) > 1 {
		passed = args[1:]
	}
	return passed, args[0]
}

// rejectExternal aborts when any selected alias is an external host. Used by
// rotate-key, whose native-backend key manipulation has no safe system-ssh
// equivalent — failing fast beats a confusing partial run.
func rejectExternal(cfg *config.Config, aliases []string, cmdName string) {
	if ext := external.Aliases(cfg, aliases); len(ext) > 0 {
		fatal(cmdName + " is not supported for external hosts: " + strings.Join(ext, ", ") +
			" — external hosts use the system ssh client")
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func prompt(reader *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

