package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Theme picks a UI color palette: "default" (aqua), "hacker" (matrix green),
	// or "cyberpunk" (neon magenta/cyan). Overridden by $SSHMGR_THEME if set.
	Theme string `yaml:"theme,omitempty"`
	// PlaybooksDir is where `sshmgr playbook` (and the TUI) look up a
	// playbook given by bare name. Empty → ResolvePlaybooksDir's default.
	PlaybooksDir string `yaml:"playbooks_dir,omitempty"`
	// SnippetsDir holds reusable snippet-library files; SnippetGlob limits
	// which files in it are loaded. Empty → the Resolve* defaults.
	SnippetsDir string `yaml:"snippets_dir,omitempty"`
	SnippetGlob string `yaml:"snippet_glob,omitempty"`
	// Forwards holds named, reusable port-forward profiles — the manager
	// counterpart to ForwardHistory's transient most-recently-used list.
	Forwards map[string]ForwardProfile `yaml:"forwards,omitempty"`
	// ForwardsDir holds file-based forward libraries; ForwardGlob filters
	// which files in it load. Empty → the Resolve* defaults.
	ForwardsDir     string                   `yaml:"forwards_dir,omitempty"`
	ForwardGlob     string                   `yaml:"forward_glob,omitempty"`
	ForwardHistory  []ForwardEntry           `yaml:"forward_history,omitempty"`
	TransferHistory []TransferEntry          `yaml:"transfer_history,omitempty"`
	LoginHistory    []LoginEntry             `yaml:"login_history,omitempty"`
	Groups          map[string]GroupDefaults `yaml:"groups,omitempty"`
	Hosts           map[string]HostConfig    `yaml:"hosts"`
}

// ForwardEntry remembers a recent port-forward invocation so the TUI can
// suggest replays. Spec format matches the CLI: e.g. "8080:localhost:3306".
type ForwardEntry struct {
	Alias    string `yaml:"alias"`
	Type     string `yaml:"type"` // "L" | "R" | "D"
	Spec     string `yaml:"spec"`
	LastUsed string `yaml:"last_used,omitempty"` // ISO-8601 date
}

// ForwardProfile is a named, reusable port-forward configuration. Profiles
// can live inline in Config.Forwards or under forwards_dir as file libraries
// (one file may define many profiles via `forwards: { name: {...} }`).
type ForwardProfile struct {
	Alias       string `yaml:"alias" json:"alias"`
	Type        string `yaml:"type" json:"type"` // "L" | "R" | "D"
	Spec        string `yaml:"spec" json:"spec"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// TransferEntry is one logged file transfer (upload or download) so the user
// can see what's been copied, when, and how big.
type TransferEntry struct {
	Alias     string `yaml:"alias"`
	Direction string `yaml:"direction"` // "up" or "down"
	Local     string `yaml:"local"`
	Remote    string `yaml:"remote"`
	Bytes     int64  `yaml:"bytes"`
	When      string `yaml:"when"` // RFC-3339 timestamp
}

// LoginEntry records a successful action on a host (connect/sftp/files/fwd).
// Sorted by When, newest first, in cfg.LoginHistory.
type LoginEntry struct {
	Alias  string `yaml:"alias"`
	Action string `yaml:"action"`
	When   string `yaml:"when"`
}

// GroupDefaults are inherited by hosts that list the group in their `groups:` field.
// Host-level fields override group fields. Tags are merged (union, deduplicated).
type GroupDefaults struct {
	User              string       `yaml:"user,omitempty"`
	Port              int          `yaml:"port,omitempty"`
	Key               string       `yaml:"key,omitempty"`
	Password          string       `yaml:"password,omitempty"`
	PasswordEnv       string       `yaml:"password_env,omitempty"`
	PasswordKeyring   string       `yaml:"password_keyring,omitempty"`
	PasswordCmd       string       `yaml:"password_cmd,omitempty"`
	PasswordPrompt    *bool        `yaml:"password_prompt,omitempty"`
	AutoDuoPush       *bool        `yaml:"auto_duo_push,omitempty"`
	AutoAcceptHostKey *bool        `yaml:"auto_accept_host_key,omitempty"`
	ProxyJump         string       `yaml:"proxy_jump,omitempty"`
	ProxyCommand      string       `yaml:"proxy_command,omitempty"`
	Become            BecomeConfig `yaml:"become,omitempty"`
	// LoginSteps is inherited by every host in the group that does not define
	// its own login_steps (and has not set login_steps_none). Lets a whole
	// fleet share one su/sudo escalation chain.
	LoginSteps []LoginStep `yaml:"login_steps,omitempty"`
	// LoginStepsAuto controls whether login_steps run automatically at connect.
	// nil → default true (auto). false → chain runs only via the in-session
	// escalation hotkey, never at connect (use on MFA-gated hosts where
	// auto-firing would race the MFA prompt).
	LoginStepsAuto *bool `yaml:"login_steps_auto,omitempty"`
	// EscalateKey overrides the in-session escalation escape character (default
	// "~", OpenSSH-style, recognised only at line start).
	EscalateKey string `yaml:"escalate_key,omitempty"`
	// KVM is the out-of-band controller, inherited by hosts without their own.
	KVM                 *KVMConfig `yaml:"kvm,omitempty"`
	Tags                []string   `yaml:"tags,omitempty"`
	ForwardAgent        *bool      `yaml:"forward_agent,omitempty"`
	ConnectTimeout      int        `yaml:"connect_timeout,omitempty"`
	ServerAliveInterval int        `yaml:"server_alive_interval,omitempty"`
	ServerAliveCountMax int        `yaml:"server_alive_count_max,omitempty"`
	SSHOptions          []string   `yaml:"ssh_options,omitempty"`
	Snippets            []Snippet  `yaml:"snippets,omitempty"`
	SessionLog          *bool      `yaml:"session_log,omitempty"`
	Persistent          string     `yaml:"persistent,omitempty"`
}

type HostConfig struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port,omitempty" json:"port,omitempty"`
	User string `yaml:"user,omitempty" json:"user,omitempty"`
	Key  string `yaml:"key,omitempty" json:"key,omitempty"`
	// SSH-auth password (used when the server requests password or
	// keyboard-interactive without a Duo-style prompt). Resolution order
	// matches LoginStep: Password > PasswordEnv > PasswordKeyring > PasswordCmd
	// > PasswordPrompt. PasswordKeyring and PasswordCmd expand the placeholders
	// {{alias}} / {{host}} / {{user}} / {{port}} — so one group-level value
	// can serve a whole fleet of per-host vault entries.
	Password          string `yaml:"password,omitempty" json:"password,omitempty"`
	PasswordEnv       string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordKeyring   string `yaml:"password_keyring,omitempty" json:"password_keyring,omitempty"`
	PasswordCmd       string `yaml:"password_cmd,omitempty" json:"password_cmd,omitempty"`
	PasswordPrompt    bool   `yaml:"password_prompt,omitempty" json:"password_prompt,omitempty"`
	AutoDuoPush       bool   `yaml:"auto_duo_push,omitempty" json:"auto_duo_push,omitempty"`
	AutoAcceptHostKey bool   `yaml:"auto_accept_host_key,omitempty" json:"auto_accept_host_key,omitempty"`
	// External=true means "just exec `ssh <Host>` and let OpenSSH handle
	// everything (knock, auth, Duo)". Use for hosts that need ssh-config
	// features sshmgr's Go SSH library can't do (ProxyCommand, Match blocks, etc.).
	External bool `yaml:"external,omitempty" json:"external,omitempty"`
	// KeyOnly is a runtime-only flag (never serialized): when set, auth uses
	// EXACTLY the configured Key and nothing else — no password, no
	// keyboard-interactive fallback. Used by key-rotation verification so a
	// new key is proven to work on its own merits.
	KeyOnly bool `yaml:"-" json:"-"`
	// Alias is the host's config key. Runtime-only (never serialized);
	// ResolveHost fills it so downstream code — e.g. password_cmd
	// placeholder expansion — can reference the host by its sshmgr name.
	Alias        string   `yaml:"-" json:"-"`
	ProxyJump    string   `yaml:"proxy_jump,omitempty" json:"proxy_jump,omitempty"`
	ProxyCommand string   `yaml:"proxy_command,omitempty" json:"proxy_command,omitempty"`
	Groups       []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Tags         []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Pinned floats the host to the top of the TUI host list.
	Pinned bool         `yaml:"pinned,omitempty" json:"pinned,omitempty"`
	Become BecomeConfig `yaml:"become,omitempty" json:"become,omitempty,omitzero"`
	// LoginSteps runs a sequence of expect/response commands after the shell
	// opens, before handing control to the user. Use for chains like
	// `su - deployer` then `sudo su -`, each with its own password prompt.
	LoginSteps []LoginStep `yaml:"login_steps,omitempty" json:"login_steps,omitempty"`
	// LoginStepsNone, when true, suppresses any group-inherited login_steps so
	// this host opens a plain shell. Survives config round-trips (unlike an
	// empty login_steps:, which omitempty would drop on save). Use to exclude
	// individual hosts from a group's escalation chain.
	LoginStepsNone bool `yaml:"login_steps_none,omitempty" json:"login_steps_none,omitempty"`
	// LoginStepsAuto: nil → default true (login_steps run at connect). false →
	// they run only via the in-session escalation hotkey. Inherited from group.
	LoginStepsAuto *bool `yaml:"login_steps_auto,omitempty" json:"login_steps_auto,omitempty"`
	// EscalateKey overrides the escalation escape character (default "~").
	EscalateKey string `yaml:"escalate_key,omitempty" json:"escalate_key,omitempty"`
	// KVM is this host's out-of-band controller (inherited from group if unset).
	KVM      *KVMConfig `yaml:"kvm,omitempty" json:"kvm,omitempty"`
	Commands []string   `yaml:"commands,omitempty" json:"commands,omitempty"`
	// Snippets are saved one-liners attached to a host. The TUI exposes them
	// under 'c' (pick from menu); inherited from a host's groups too.
	Snippets []Snippet `yaml:"snippets,omitempty" json:"snippets,omitempty"`
	// X11Forward asks the server for X11 forwarding when opening the interactive
	// shell so remote GUI apps render on the local X server.
	X11Forward bool `yaml:"x11_forward,omitempty" json:"x11_forward,omitempty"`
	// ForwardAgent forwards the local ssh-agent into the session (handy for
	// chained logins / `git clone` from the remote without copying keys).
	ForwardAgent bool `yaml:"forward_agent,omitempty" json:"forward_agent,omitempty"`
	// ConnectTimeout is the TCP-dial timeout in seconds (default 30).
	ConnectTimeout int `yaml:"connect_timeout,omitempty" json:"connect_timeout,omitempty"`
	// ServerAliveInterval (seconds) — when >0, sshmgr sends a keepalive every N
	// seconds. After ServerAliveCountMax (default 3) consecutive failures the
	// session is torn down. Mirrors OpenSSH's option names.
	ServerAliveInterval int `yaml:"server_alive_interval,omitempty" json:"server_alive_interval,omitempty"`
	ServerAliveCountMax int `yaml:"server_alive_count_max,omitempty" json:"server_alive_count_max,omitempty"`
	// SSHOptions is a free-form list of `-o KEY=VAL` pairs (or `KEY=VAL`).
	// Currently honored only by `external: true` hosts — sshmgr passes each as
	// an extra `-o` arg to the system ssh client. For native (Go SSH) hosts
	// the typed fields above are the canonical knobs.
	SSHOptions []string `yaml:"ssh_options,omitempty" json:"ssh_options,omitempty"`
	// SessionLog enables auditing of interactive shells. When true sshmgr
	// tees the remote shell's output to a file under
	// $XDG_DATA_HOME/sshmgr/sessions/<alias>-<timestamp>.log (override the
	// directory with $SSHMGR_SESSION_DIR).
	SessionLog bool `yaml:"session_log,omitempty" json:"session_log,omitempty"`
	// Persistent wraps the shell in tmux (default) or screen so the session
	// survives network drops / laptop sleep — sshmgr reattaches on the next
	// connect. Set "tmux" or "screen" to pick a multiplexer; "true" / "yes"
	// pick tmux. Empty disables.
	Persistent string `yaml:"persistent,omitempty" json:"persistent,omitempty"`
}

type BecomeConfig struct {
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	User   string `yaml:"user,omitempty" json:"user,omitempty"`
}

// Snippet is a named one-liner runnable via `sshmgr <alias> :<name>` or
// picked from the TUI 'c' menu. Description shows in the picker.
type Snippet struct {
	Name        string   `yaml:"name" json:"name"`
	Command     string   `yaml:"command" json:"command"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// LoginStep represents one command + expect/response in a post-login chain.
// Example:
//
//	command="su - deployer", expect="Password:", password_keyring="deployer-secret"
//
// Password resolution order (first non-empty wins):
//  1. Response   — literal plaintext (NOT recommended outside ad-hoc tests)
//  2. PasswordEnv  — environment variable name
//  3. PasswordKeyring — OS keyring entry under service "sshmgr"
//  4. PasswordCmd  — shell command, stdout (first line) is the password
//  5. PasswordPrompt — prompt user once at connect time
type LoginStep struct {
	Command         string `yaml:"command" json:"command"`
	Expect          string `yaml:"expect,omitempty" json:"expect,omitempty"`
	Response        string `yaml:"response,omitempty" json:"response,omitempty"`
	PasswordEnv     string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordKeyring string `yaml:"password_keyring,omitempty" json:"password_keyring,omitempty"`
	PasswordCmd     string `yaml:"password_cmd,omitempty" json:"password_cmd,omitempty"`
	PasswordPrompt  bool   `yaml:"password_prompt,omitempty" json:"password_prompt,omitempty"`
	TimeoutMS       int    `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
}

// KVMConfig describes a host's out-of-band KVM controller (e.g. a Sipeed
// NanoKVM reachable over Tailscale as {alias}-kvm). Its credentials are
// independent of the host's SSH auth. Inherited from a group when the host
// defines none. Host is placeholder-expanded ({{alias}}/{{host}}/{{user}}/{{port}})
// via ResolvedHost, so a group can carry one templated address for the fleet.
type KVMConfig struct {
	Type            string `yaml:"type,omitempty" json:"type,omitempty"` // driver; default "nanokvm"
	Host            string `yaml:"host,omitempty" json:"host,omitempty"`
	Scheme          string `yaml:"scheme,omitempty" json:"scheme,omitempty"` // default "https"
	Port            int    `yaml:"port,omitempty" json:"port,omitempty"`
	User            string `yaml:"user,omitempty" json:"user,omitempty"`
	Password        string `yaml:"password,omitempty" json:"password,omitempty"`
	PasswordEnv     string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordKeyring string `yaml:"password_keyring,omitempty" json:"password_keyring,omitempty"`
	PasswordCmd     string `yaml:"password_cmd,omitempty" json:"password_cmd,omitempty"`
	PasswordPrompt  bool   `yaml:"password_prompt,omitempty" json:"password_prompt,omitempty"`
	// Insecure skips TLS verification for the KVM HTTP client only (NanoKVM ships
	// a self-signed cert). nil → default true; set false to require a valid cert.
	Insecure *bool `yaml:"insecure,omitempty" json:"insecure,omitempty"`
}

// ResolvedHost expands {{alias}}/{{host}}/... placeholders in Host without
// mutating the receiver (group-shared KVMConfigs must stay templated).
func (k KVMConfig) ResolvedHost(vars map[string]string) string {
	h := k.Host
	for key, val := range vars {
		h = strings.ReplaceAll(h, "{{"+key+"}}", val)
	}
	return h
}

// ResolveHost returns the host with group defaults merged in.
// Host-level non-zero fields take precedence; tags are union-merged.
// A proxy_command / proxy_jump that would route the host through itself is
// dropped (see below). Returns (HostConfig{}, false) if alias is not configured.
func (c *Config) ResolveHost(alias string) (HostConfig, bool) {
	h, ok := c.Hosts[alias]
	if !ok {
		return HostConfig{}, false
	}

	tagSet := map[string]struct{}{}
	for _, t := range h.Tags {
		tagSet[t] = struct{}{}
	}

	for _, gname := range h.Groups {
		g, exists := c.Groups[gname]
		if !exists {
			continue
		}
		if h.User == "" {
			h.User = g.User
		}
		if h.Port == 0 {
			h.Port = g.Port
		}
		if h.Key == "" {
			h.Key = g.Key
		}
		if g.AutoDuoPush != nil && !h.AutoDuoPush {
			h.AutoDuoPush = *g.AutoDuoPush
		}
		if g.AutoAcceptHostKey != nil && !h.AutoAcceptHostKey {
			h.AutoAcceptHostKey = *g.AutoAcceptHostKey
		}
		if h.Password == "" {
			h.Password = g.Password
		}
		if h.PasswordEnv == "" {
			h.PasswordEnv = g.PasswordEnv
		}
		if h.PasswordKeyring == "" {
			h.PasswordKeyring = g.PasswordKeyring
		}
		if h.PasswordCmd == "" {
			h.PasswordCmd = g.PasswordCmd
		}
		if g.PasswordPrompt != nil && !h.PasswordPrompt {
			h.PasswordPrompt = *g.PasswordPrompt
		}
		if g.ForwardAgent != nil && !h.ForwardAgent {
			h.ForwardAgent = *g.ForwardAgent
		}
		if h.ConnectTimeout == 0 {
			h.ConnectTimeout = g.ConnectTimeout
		}
		if h.ServerAliveInterval == 0 {
			h.ServerAliveInterval = g.ServerAliveInterval
		}
		if h.ServerAliveCountMax == 0 {
			h.ServerAliveCountMax = g.ServerAliveCountMax
		}
		if len(g.SSHOptions) > 0 {
			merged := append([]string{}, g.SSHOptions...)
			merged = append(merged, h.SSHOptions...)
			h.SSHOptions = merged
		}
		if g.SessionLog != nil && !h.SessionLog {
			h.SessionLog = *g.SessionLog
		}
		if h.Persistent == "" {
			h.Persistent = g.Persistent
		}
		// Snippets union — host-level wins on duplicate Name.
		if len(g.Snippets) > 0 {
			seen := map[string]bool{}
			for _, s := range h.Snippets {
				seen[s.Name] = true
			}
			for _, s := range g.Snippets {
				if !seen[s.Name] {
					h.Snippets = append(h.Snippets, s)
				}
			}
		}
		if h.ProxyJump == "" {
			h.ProxyJump = g.ProxyJump
		}
		if h.ProxyCommand == "" {
			h.ProxyCommand = g.ProxyCommand
		}
		if h.Become.User == "" {
			h.Become = g.Become
		}
		if len(h.LoginSteps) == 0 && !h.LoginStepsNone {
			h.LoginSteps = g.LoginSteps
		}
		if h.LoginStepsAuto == nil {
			h.LoginStepsAuto = g.LoginStepsAuto
		}
		if h.EscalateKey == "" {
			h.EscalateKey = g.EscalateKey
		}
		if g.KVM != nil {
			if h.KVM == nil {
				h.KVM = g.KVM
			} else {
				// Field-merge: host fields win, group fills the rest — so a group
				// can hold shared creds while each host supplies only its address.
				m := *h.KVM
				gk := g.KVM
				if m.Type == "" {
					m.Type = gk.Type
				}
				if m.Host == "" {
					m.Host = gk.Host
				}
				if m.Scheme == "" {
					m.Scheme = gk.Scheme
				}
				if m.Port == 0 {
					m.Port = gk.Port
				}
				if m.User == "" {
					m.User = gk.User
				}
				if m.Password == "" {
					m.Password = gk.Password
				}
				if m.PasswordEnv == "" {
					m.PasswordEnv = gk.PasswordEnv
				}
				if m.PasswordKeyring == "" {
					m.PasswordKeyring = gk.PasswordKeyring
				}
				if m.PasswordCmd == "" {
					m.PasswordCmd = gk.PasswordCmd
				}
				if !m.PasswordPrompt {
					m.PasswordPrompt = gk.PasswordPrompt
				}
				if m.Insecure == nil {
					m.Insecure = gk.Insecure
				}
				h.KVM = &m
			}
		}
		// Implicit tag: group name itself becomes a tag.
		tagSet[gname] = struct{}{}
		for _, t := range g.Tags {
			tagSet[t] = struct{}{}
		}
	}

	if len(tagSet) > 0 {
		h.Tags = h.Tags[:0]
		for t := range tagSet {
			h.Tags = append(h.Tags, t)
		}
		sortStrings(h.Tags)
	}

	// Drop a proxy directive that would route the host through itself — a
	// loop that can never connect, typically a jump host inheriting its
	// group's "go through me" proxy. For external hosts this hands routing
	// back to the host's own ~/.ssh/config entry.
	self := func(name string) bool {
		if i := strings.LastIndexByte(name, '@'); i >= 0 {
			name = name[i+1:]
		}
		return name != "" && (name == alias || name == h.Host)
	}
	if self(ExtractSSHJumpAlias(h.ProxyCommand)) {
		h.ProxyCommand = ""
	}
	for _, hop := range strings.Split(h.ProxyJump, ",") {
		if i := strings.IndexByte(hop, ':'); i >= 0 {
			hop = hop[:i]
		}
		if self(strings.TrimSpace(hop)) {
			h.ProxyJump = ""
			break
		}
	}

	if h.Port == 0 {
		h.Port = 22
	}
	h.Alias = alias
	return h, true
}

// ResolvedField is one resolved host field with its value and origin —
// "host", "group:<name>", or "" when nothing provides it.
type ResolvedField struct {
	Name   string
	Value  string
	Source string
}

// ResolveTrace returns the string-valued inheritable fields of host alias,
// each tagged with where its resolved value came from (the host itself, or
// the first group that provides it). Fields that neither the host nor any
// of its groups set are omitted. ok is false if alias is not configured.
func (c *Config) ResolveTrace(alias string) (fields []ResolvedField, ok bool) {
	raw, ok := c.Hosts[alias]
	if !ok {
		return nil, false
	}
	resolved, _ := c.ResolveHost(alias)
	// groupWith returns "group:<name>" for the first of the host's groups
	// whose pick() is non-empty — the same first-wins order as ResolveHost.
	groupWith := func(pick func(GroupDefaults) string) string {
		for _, g := range raw.Groups {
			if gd, defined := c.Groups[g]; defined && pick(gd) != "" {
				return "group:" + g
			}
		}
		return ""
	}
	trace := func(name, resolvedVal, rawVal string, pick func(GroupDefaults) string) {
		if resolvedVal == "" {
			return
		}
		src := "host"
		if rawVal == "" {
			src = groupWith(pick)
		}
		fields = append(fields, ResolvedField{Name: name, Value: resolvedVal, Source: src})
	}
	trace("user", resolved.User, raw.User, func(g GroupDefaults) string { return g.User })
	trace("key", resolved.Key, raw.Key, func(g GroupDefaults) string { return g.Key })
	trace("proxy_jump", resolved.ProxyJump, raw.ProxyJump, func(g GroupDefaults) string { return g.ProxyJump })
	trace("proxy_command", resolved.ProxyCommand, raw.ProxyCommand, func(g GroupDefaults) string { return g.ProxyCommand })
	trace("persistent", resolved.Persistent, raw.Persistent, func(g GroupDefaults) string { return g.Persistent })
	return fields, true
}

// flagsTakingValue lists OpenSSH-client flags whose argument is a separate
// token (not glued like "-oKEY=VAL") — used to find the destination host in
// an `ssh ...` proxy command.
var flagsTakingValue = map[string]bool{
	"-b": true, "-c": true, "-D": true, "-E": true, "-e": true,
	"-F": true, "-I": true, "-i": true, "-J": true, "-L": true,
	"-l": true, "-m": true, "-O": true, "-o": true, "-p": true,
	"-Q": true, "-R": true, "-S": true, "-W": true, "-w": true,
}

// ExtractSSHJumpAlias parses `ssh [flags] <dest> ...` and returns <dest>, or
// "" if cmd isn't an `ssh` invocation. Skips both `-fVAL` glued flags and
// `-f VAL` separate-value flags.
func ExtractSSHJumpAlias(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) < 2 || fields[0] != "ssh" {
		return ""
	}
	i := 1
	for i < len(fields) {
		tok := fields[i]
		if !strings.HasPrefix(tok, "-") {
			return tok
		}
		if flagsTakingValue[tok] && i+1 < len(fields) {
			i += 2
			continue
		}
		i++
	}
	return ""
}

func sortStrings(s []string) {
	// Avoid importing sort here just for this; small enough for insertion sort.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Path returns the resolved config path, honoring $SSHMGR_CONFIG, then
// $XDG_CONFIG_HOME/sshmgr/config.yaml, falling back to ~/.config/sshmgr/config.yaml.
func Path() (string, error) {
	if p := os.Getenv("SSHMGR_CONFIG"); p != "" {
		return ExpandPath(p), nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sshmgr", "config.yaml"), nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home dir: %w", err)
	}
	return filepath.Join(usr.HomeDir, ".config", "sshmgr", "config.yaml"), nil
}

// ResolvePlaybooksDir returns the directory scanned for playbooks: the
// configured playbooks_dir if set, else $XDG_CONFIG_HOME/sshmgr/playbooks,
// else ~/.config/sshmgr/playbooks.
func (c *Config) ResolvePlaybooksDir() string {
	if c.PlaybooksDir != "" {
		return ExpandPath(c.PlaybooksDir)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sshmgr", "playbooks")
	}
	if usr, err := user.Current(); err == nil {
		return filepath.Join(usr.HomeDir, ".config", "sshmgr", "playbooks")
	}
	return "playbooks"
}

// ResolveSnippetsDir returns the directory scanned for snippet libraries:
// the configured snippets_dir if set, else $XDG_CONFIG_HOME/sshmgr/snippets,
// else ~/.config/sshmgr/snippets.
func (c *Config) ResolveSnippetsDir() string {
	if c.SnippetsDir != "" {
		return ExpandPath(c.SnippetsDir)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sshmgr", "snippets")
	}
	if usr, err := user.Current(); err == nil {
		return filepath.Join(usr.HomeDir, ".config", "sshmgr", "snippets")
	}
	return "snippets"
}

// ResolveSnippetGlob returns the filename glob for snippet libraries
// (default "*.yaml").
func (c *Config) ResolveSnippetGlob() string {
	if c.SnippetGlob != "" {
		return c.SnippetGlob
	}
	return "*.yaml"
}

// ResolveForwardsDir returns the directory scanned for forward libraries:
// the configured forwards_dir if set, else $XDG_CONFIG_HOME/sshmgr/forwards,
// else ~/.config/sshmgr/forwards.
func (c *Config) ResolveForwardsDir() string {
	if c.ForwardsDir != "" {
		return ExpandPath(c.ForwardsDir)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sshmgr", "forwards")
	}
	if usr, err := user.Current(); err == nil {
		return filepath.Join(usr.HomeDir, ".config", "sshmgr", "forwards")
	}
	return "forwards"
}

// ResolveForwardGlob returns the filename glob for forward libraries
// (default "*.yaml").
func (c *Config) ResolveForwardGlob() string {
	if c.ForwardGlob != "" {
		return c.ForwardGlob
	}
	return "*.yaml"
}

func Load() (*Config, string, error) {
	path, err := Path()
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Hosts: map[string]HostConfig{}}, path, nil
		}
		return nil, path, fmt.Errorf("cannot read config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, path, fmt.Errorf("cannot parse config %s: %w", path, err)
	}
	if cfg.Hosts == nil {
		cfg.Hosts = map[string]HostConfig{}
	}
	return &cfg, path, nil
}

// Save writes the config atomically (tmp + rename). Creates parent dirs if
// missing. Before overwriting an existing config, snapshots it into
// <dir>/backups/config.yaml.YYYYMMDD-HHMMSS and keeps the 10 most recent.
func Save(cfg *Config, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot create config dir: %w", err)
	}
	_ = backupExisting(path)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("cannot marshal config: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sshmgr-config-*.yaml")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("cannot write config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot rename to %s: %w", path, err)
	}
	return nil
}

// backupExisting copies the current config (if any) into
// <dir>/backups/config.yaml.YYYYMMDD-HHMMSS and keeps only the 10 newest
// backups. Best-effort — errors are swallowed so a flaky backup never
// blocks the actual save.
func backupExisting(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err // missing file is normal on first run
	}
	dir := filepath.Join(filepath.Dir(path), "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	dst := filepath.Join(dir, filepath.Base(path)+"."+stamp)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return err
	}
	pruneBackups(dir, filepath.Base(path), 10)
	return nil
}

type backupCandidate struct {
	name string
	mod  time.Time
}

func pruneBackups(dir, prefix string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var cs []backupCandidate
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix+".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cs = append(cs, backupCandidate{e.Name(), info.ModTime()})
	}
	if len(cs) <= keep {
		return
	}
	// Newest first (insertion sort — N is small).
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j-1].mod.Before(cs[j].mod); j-- {
			cs[j-1], cs[j] = cs[j], cs[j-1]
		}
	}
	for _, c := range cs[keep:] {
		_ = os.Remove(filepath.Join(dir, c.name))
	}
}

func ExpandPath(path string) string {
	if !strings.HasPrefix(path, "~/") && path != "~" {
		return path
	}
	usr, err := user.Current()
	if err != nil {
		return path
	}
	if path == "~" {
		return usr.HomeDir
	}
	return filepath.Join(usr.HomeDir, strings.TrimPrefix(path, "~/"))
}
