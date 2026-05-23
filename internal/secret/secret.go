// Package secret resolves a login step's response from one of several backends:
// literal, env var, OS keyring, command output, or interactive prompt.
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"sshmgr/internal/config"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// KeyringService is the namespace used for sshmgr entries in the OS keyring.
const KeyringService = "sshmgr"

// Spec describes where to fetch a password from. Backends are tried in field
// order; the first non-empty wins.
type Spec struct {
	Literal string // plaintext (NOT recommended)
	Env     string // env var name
	Keyring string // OS keyring key under service "sshmgr"
	Cmd     string // shell command, stdout's first line is the password
	Prompt  bool   // interactive prompt fallback
	Label   string // shown in prompts / error messages
	// Vars supplies {{name}} placeholder values expanded into Keyring and
	// Cmd before use — so one group-level password_cmd / password_keyring
	// can serve a fleet of per-host vault entries.
	Vars map[string]string
}

// expand substitutes {{name}} placeholders in s with values from vars.
// Unknown placeholders are left untouched.
func expand(s string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// ResolveSpec runs the resolution chain for a Spec. Returns ("", error) when
// the configured backend can't satisfy the request, ("", nil) when no backend
// is configured at all (caller decides if that's fatal).
func ResolveSpec(s Spec) (string, error) {
	if s.Literal != "" {
		return s.Literal, nil
	}
	if s.Env != "" {
		v := os.Getenv(s.Env)
		if v == "" {
			return "", fmt.Errorf("env var %s is empty", s.Env)
		}
		return v, nil
	}
	if s.Keyring != "" {
		key := expand(s.Keyring, s.Vars)
		v, err := keyring.Get(KeyringService, key)
		if err != nil {
			return "", fmt.Errorf("keyring get %q: %w (try `sshmgr keyring set %s`)", key, err, key)
		}
		return v, nil
	}
	if s.Cmd != "" {
		cmdline := expand(s.Cmd, s.Vars)
		out, err := runPasswordCmd(cmdline)
		if err != nil {
			return "", fmt.Errorf("password_cmd %q: %w", cmdline, err)
		}
		return out, nil
	}
	if s.Prompt {
		label := s.Label
		if label == "" {
			label = "password"
		}
		return promptPassword(fmt.Sprintf("[sshmgr] %s: ", label))
	}
	return "", nil
}

// hostVars builds the {{alias}}/{{host}}/{{user}}/{{port}} placeholder set
// used by both the host-auth and login-step resolvers.
func hostVars(h config.HostConfig) map[string]string {
	return map[string]string{
		"alias": h.Alias,
		"host":  h.Host,
		"user":  h.User,
		"port":  strconv.Itoa(h.Port),
	}
}

// Resolve resolves the password for a LoginStep run against host h. The host
// context lets the step's password_cmd / password_keyring expand the same
// placeholders as the host-auth path and share the process-wide cache.
func Resolve(step config.LoginStep, h config.HostConfig) (string, error) {
	v, err := ResolveSpec(Spec{
		Literal: step.Response,
		Env:     step.PasswordEnv,
		Keyring: step.PasswordKeyring,
		Cmd:     step.PasswordCmd,
		Prompt:  step.PasswordPrompt,
		Label:   "password for " + step.Command,
		Vars:    hostVars(h),
	})
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("no password backend configured for step")
	}
	return v, nil
}

// ResolveHostPassword resolves the SSH-auth password for a host, or returns
// ("", nil) when no backend is configured (caller may then fall back to other
// SSH auth methods).
func ResolveHostPassword(h config.HostConfig) (string, error) {
	return ResolveSpec(Spec{
		Literal: h.Password,
		Env:     h.PasswordEnv,
		Keyring: h.PasswordKeyring,
		Cmd:     h.PasswordCmd,
		Prompt:  h.PasswordPrompt,
		Label:   fmt.Sprintf("password for %s@%s", h.User, h.Host),
		Vars:    hostVars(h),
	})
}

// pwCall is one in-flight password_cmd execution that concurrent callers
// with the same command line wait on, so the underlying secret CLI runs once.
type pwCall struct {
	wg  sync.WaitGroup
	val string
	err error
}

// password_cmd results are memoised for the process lifetime: a fleet-wide
// command (or a TUI session running many actions) then invokes the secret
// CLI — and any biometric prompt — only once per distinct command line.
// pwInflight gives singleflight semantics; pwDone caches successes only, so a
// transient failure is retried rather than poisoning the cache.
var (
	pwMu       sync.Mutex
	pwDone     = map[string]string{}
	pwInflight = map[string]*pwCall{}
)

func runPasswordCmd(cmdline string) (string, error) {
	pwMu.Lock()
	if v, ok := pwDone[cmdline]; ok {
		pwMu.Unlock()
		return v, nil
	}
	if c, ok := pwInflight[cmdline]; ok {
		pwMu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &pwCall{}
	c.wg.Add(1)
	pwInflight[cmdline] = c
	pwMu.Unlock()

	c.val, c.err = execPasswordCmd(cmdline)
	c.wg.Done()

	pwMu.Lock()
	delete(pwInflight, cmdline)
	if c.err == nil {
		pwDone[cmdline] = c.val
	}
	pwMu.Unlock()
	return c.val, c.err
}

// execPasswordCmd runs cmdline via `sh -c` and returns the first line of
// stdout — lots of secret CLIs add a trailing newline or print extra
// metadata after the password which we want to ignore.
func execPasswordCmd(cmdline string) (string, error) {
	cmd := exec.Command("sh", "-c", cmdline)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: stderr=%q", err, stderr.String())
	}
	out := stdout.String()
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	out = strings.TrimRight(out, "\r")
	if out == "" {
		return "", errors.New("command produced empty output")
	}
	return out, nil
}

func promptPassword(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("cannot prompt: stdin is not a terminal")
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// KeyringSet stores a password in the OS keyring under sshmgr's service namespace.
func KeyringSet(key, password string) error {
	return keyring.Set(KeyringService, key, password)
}

// KeyringGet retrieves a password from the OS keyring.
func KeyringGet(key string) (string, error) {
	return keyring.Get(KeyringService, key)
}

// KeyringDelete removes an entry from the OS keyring.
func KeyringDelete(key string) error {
	return keyring.Delete(KeyringService, key)
}
