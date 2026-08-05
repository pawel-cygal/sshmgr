// Package lint validates a config and reports issues — unused groups,
// broken proxy_jump references, missing key files, duplicate aliases. Read-only;
// run via `sshmgr lint`.
package lint

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/forwards"
	"github.com/systeampl/sshmgr/internal/kvm"
	"github.com/systeampl/sshmgr/internal/snippets"
)

// Severity grades each finding so the user can filter at a glance.
type Severity string

const (
	SevError Severity = "error" // configuration is broken — connect will fail
	SevWarn  Severity = "warn"  // probably wrong but won't crash
	SevInfo  Severity = "info"  // cleanup suggestion
)

type Finding struct {
	Severity Severity `json:"severity"`
	Scope    string   `json:"scope"` // alias, group name, or "config"
	Message  string   `json:"message"`
}

// Report is the machine-readable form of a lint run (`lint --json`).
type Report struct {
	Findings []Finding `json:"findings"`
	Errors   int       `json:"errors"`
	Warnings int       `json:"warnings"`
	Infos    int       `json:"infos"`
}

// Summarize wraps findings with per-severity counts for JSON output.
func Summarize(findings []Finding) Report {
	if findings == nil {
		findings = []Finding{} // stable schema: emit [] not null
	}
	r := Report{Findings: findings}
	for _, f := range findings {
		switch f.Severity {
		case SevError:
			r.Errors++
		case SevWarn:
			r.Warnings++
		case SevInfo:
			r.Infos++
		}
	}
	return r
}

// Run produces a list of findings for cfg, sorted by severity then scope.
func Run(cfg *config.Config) []Finding {
	var out []Finding

	// 1. Broken proxy_jump references and multi-host cycles. Use resolved hosts
	// so group-inherited jumps receive the same validation as host-local ones.
	jumpGraph := map[string]string{}
	for alias := range cfg.Hosts {
		h, _ := cfg.ResolveHost(alias)
		if h.ProxyJump == "" {
			continue
		}
		if _, ok := cfg.Hosts[h.ProxyJump]; !ok {
			out = append(out, Finding{
				Severity: SevError,
				Scope:    alias,
				Message:  fmt.Sprintf("proxy_jump references unknown alias %q", h.ProxyJump),
			})
			continue
		}
		jumpGraph[alias] = h.ProxyJump
	}
	state := map[string]uint8{}
	var stack []string
	var visit func(string)
	visit = func(alias string) {
		state[alias] = 1
		stack = append(stack, alias)
		if next := jumpGraph[alias]; next != "" {
			switch state[next] {
			case 0:
				visit(next)
			case 1:
				start := 0
				for i := range stack {
					if stack[i] == next {
						start = i
						break
					}
				}
				cycle := append(append([]string{}, stack[start:]...), next)
				out = append(out, Finding{
					Severity: SevError,
					Scope:    next,
					Message:  "proxy_jump cycle: " + strings.Join(cycle, " -> "),
				})
			}
		}
		stack = stack[:len(stack)-1]
		state[alias] = 2
	}
	aliases := make([]string, 0, len(cfg.Hosts))
	for alias := range cfg.Hosts {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		if state[alias] == 0 {
			visit(alias)
		}
	}

	// 2. Groups referenced by hosts but not defined in cfg.Groups.
	usedGroups := map[string]bool{}
	for alias, h := range cfg.Hosts {
		for _, g := range h.Groups {
			usedGroups[g] = true
			if _, ok := cfg.Groups[g]; !ok {
				out = append(out, Finding{
					Severity: SevWarn,
					Scope:    alias,
					Message:  fmt.Sprintf("group %q is not defined under top-level `groups:`", g),
				})
			}
		}
	}

	// 3. Defined groups with no member hosts.
	for g := range cfg.Groups {
		if !usedGroups[g] {
			out = append(out, Finding{
				Severity: SevInfo,
				Scope:    "group " + g,
				Message:  "defined but no hosts list it",
			})
		}
	}

	// 4. Missing key files (best-effort — only if the host configures one).
	for alias, h := range cfg.Hosts {
		resolved, _ := cfg.ResolveHost(alias)
		if resolved.Key == "" {
			continue
		}
		p := config.ExpandPath(resolved.Key)
		if _, err := os.Stat(p); err != nil {
			sev := SevWarn
			// If the host has no password backend either, the key is the only
			// way in — bump to error.
			if resolved.Password == "" && resolved.PasswordEnv == "" && resolved.PasswordKeyring == "" && resolved.PasswordCmd == "" && !resolved.PasswordPrompt {
				sev = SevError
			}
			out = append(out, Finding{
				Severity: sev,
				Scope:    alias,
				Message:  fmt.Sprintf("key file %s not found (%v)", p, err),
			})
		}
		_ = h // resolved already used
	}

	// 5. Hosts with auto_duo_push but no keyboard-interactive method.
	// (We always add keyboard-interactive when AutoDuoPush is set, so this
	// is only a sanity check for misconfigured external hosts.)
	for alias, h := range cfg.Hosts {
		if h.External && h.AutoDuoPush {
			out = append(out, Finding{
				Severity: SevInfo,
				Scope:    alias,
				Message:  "auto_duo_push has no effect on external hosts (OpenSSH handles auth)",
			})
		}
	}

	// 5b. KVM blocks: a configured controller needs a valid endpoint and a way
	// to authenticate, or every kvm action will fail at runtime.
	for alias := range cfg.Hosts {
		resolved, _ := cfg.ResolveHost(alias)
		k := resolved.KVM
		if k == nil {
			continue
		}
		host := k.ResolvedHost(map[string]string{
			"alias": alias, "host": resolved.Host, "user": resolved.User,
			"port": fmt.Sprintf("%d", resolved.Port),
		})
		// An empty host means the block is just group-inherited credentials with
		// no device for this host — not configured here, so nothing to validate.
		if strings.TrimSpace(host) == "" {
			continue
		}
		if !kvm.KnownType(k.Type) {
			out = append(out, Finding{
				Severity: SevError,
				Scope:    alias,
				Message:  fmt.Sprintf("unknown kvm type %q", k.Type),
			})
		} else if err := kvm.ValidateConfig(*k, host); err != nil {
			out = append(out, Finding{Severity: SevError, Scope: alias, Message: err.Error()})
		}
		if strings.Contains(host, "{{") {
			out = append(out, Finding{
				Severity: SevError,
				Scope:    alias,
				Message:  fmt.Sprintf("kvm host contains an unresolved placeholder: %q", host),
			})
		}
		if k.Password == "" && k.PasswordEnv == "" && k.PasswordKeyring == "" && k.PasswordCmd == "" && !k.PasswordPrompt {
			out = append(out, Finding{
				Severity: SevWarn,
				Scope:    alias,
				Message:  "kvm has no password backend (set kvm.password_keyring or similar)",
			})
		}
	}

	// 5c. Network ranges, plaintext credentials, and native/external option
	// mismatches. These are valid YAML but either fail later or weaken the
	// secret-management model, so surface them in the normal lint pass.
	for _, alias := range aliases {
		r, _ := cfg.ResolveHost(alias)
		if strings.TrimSpace(r.Host) == "" {
			out = append(out, Finding{Severity: SevError, Scope: alias, Message: "host is empty"})
		}
		if r.Port < 1 || r.Port > 65535 {
			out = append(out, Finding{Severity: SevError, Scope: alias, Message: fmt.Sprintf("invalid SSH port %d (want 1..65535)", r.Port)})
		}
		if r.ConnectTimeout < 0 || r.ServerAliveInterval < 0 || r.ServerAliveCountMax < 0 {
			out = append(out, Finding{Severity: SevError, Scope: alias, Message: "SSH timeout/keepalive values cannot be negative"})
		}
		h := cfg.Hosts[alias]
		if h.Password != "" {
			out = append(out, Finding{Severity: SevWarn, Scope: alias, Message: "plaintext SSH password in config; prefer password_keyring, password_env, or password_cmd"})
		}
		for i, step := range h.LoginSteps {
			if step.Response != "" {
				out = append(out, Finding{Severity: SevWarn, Scope: alias, Message: fmt.Sprintf("login_steps[%d] contains a plaintext response", i)})
			}
		}
		if h.KVM != nil && h.KVM.Password != "" {
			out = append(out, Finding{Severity: SevWarn, Scope: alias, Message: "plaintext KVM password in config; prefer password_keyring, password_env, or password_cmd"})
		}
		if h.External && (h.X11Forward || h.ForwardAgent || len(h.LoginSteps) > 0 || h.Persistent != "") {
			out = append(out, Finding{Severity: SevInfo, Scope: alias, Message: "native session options (x11/agent/login_steps/persistent) are ignored for external hosts"})
		}
	}
	for name, g := range cfg.Groups {
		scope := "group " + name
		if g.Port < 0 || g.Port > 65535 {
			out = append(out, Finding{Severity: SevError, Scope: scope, Message: fmt.Sprintf("invalid SSH port %d", g.Port)})
		}
		if g.Password != "" {
			out = append(out, Finding{Severity: SevWarn, Scope: scope, Message: "plaintext SSH password in config"})
		}
		for i, step := range g.LoginSteps {
			if step.Response != "" {
				out = append(out, Finding{Severity: SevWarn, Scope: scope, Message: fmt.Sprintf("login_steps[%d] contains a plaintext response", i)})
			}
		}
		if g.KVM != nil && g.KVM.Password != "" {
			out = append(out, Finding{Severity: SevWarn, Scope: scope, Message: "plaintext KVM password in config"})
		}
	}

	// 6. Snippet name collisions per resolved host.
	for alias := range cfg.Hosts {
		resolved, _ := cfg.ResolveHost(alias)
		seen := map[string]int{}
		for _, sn := range resolved.Snippets {
			seen[sn.Name]++
		}
		for name, n := range seen {
			if n > 1 {
				out = append(out, Finding{
					Severity: SevWarn,
					Scope:    alias,
					Message:  fmt.Sprintf("snippet %q defined %d times (host + groups) — only one is reachable", name, n),
				})
			}
		}
	}

	// 7. Hosts whose proxy_command references an ssh alias that isn't a
	// configured host (lint can only catch the simple `ssh X -W` form).
	for alias, h := range cfg.Hosts {
		if h.ProxyCommand == "" {
			continue
		}
		jump := config.ExtractSSHJumpAlias(h.ProxyCommand)
		if jump != "" {
			if _, ok := cfg.Hosts[jump]; !ok {
				out = append(out, Finding{
					Severity: SevInfo,
					Scope:    alias,
					Message:  fmt.Sprintf("proxy_command's ssh target %q isn't a configured sshmgr host (probably fine if it's in ~/.ssh/config)", jump),
				})
			}
		}
	}

	// 8. File-based snippet libraries: parse errors and duplicate names.
	fileSnips, fileErrs := snippets.FileSnippets(cfg)
	for _, e := range fileErrs {
		out = append(out, Finding{
			Severity: SevError,
			Scope:    "snippets",
			Message:  e.Error(),
		})
	}
	fileCounts := map[string]int{}
	for _, s := range fileSnips {
		fileCounts[s.Name]++
	}
	for name, n := range fileCounts {
		if n > 1 {
			out = append(out, Finding{
				Severity: SevWarn,
				Scope:    "snippets",
				Message:  fmt.Sprintf("snippet %q is defined %d times across file libraries", name, n),
			})
		}
	}
	// An explicitly configured snippets_dir that doesn't exist is probably a
	// mistake — a missing default dir is fine (file libraries are optional).
	if cfg.SnippetsDir != "" {
		if _, err := os.Stat(config.ExpandPath(cfg.SnippetsDir)); err != nil {
			out = append(out, Finding{
				Severity: SevWarn,
				Scope:    "config",
				Message:  fmt.Sprintf("snippets_dir %q does not exist", cfg.SnippetsDir),
			})
		}
	}

	// 9. A proxy directive (set on the host or inherited from a group) that
	// routes the host through itself — sshmgr drops it at resolve time, but
	// the config is a footgun, usually a jump host sharing a group with the
	// hosts behind it.
	for alias, h := range cfg.Hosts {
		pc, pcSrc := h.ProxyCommand, "set on the host"
		pj, pjSrc := h.ProxyJump, "set on the host"
		for _, gn := range h.Groups {
			g, ok := cfg.Groups[gn]
			if !ok {
				continue
			}
			if pc == "" && g.ProxyCommand != "" {
				pc, pcSrc = g.ProxyCommand, "inherited from group "+gn
			}
			if pj == "" && g.ProxyJump != "" {
				pj, pjSrc = g.ProxyJump, "inherited from group "+gn
			}
		}
		if t := config.ExtractSSHJumpAlias(pc); t != "" && (t == alias || t == h.Host) {
			out = append(out, Finding{
				Severity: SevWarn,
				Scope:    alias,
				Message:  fmt.Sprintf("proxy_command (%s) routes the host through itself — sshmgr ignores it and connects directly", pcSrc),
			})
		}
		if pj != "" && (pj == alias || pj == h.Host) {
			out = append(out, Finding{
				Severity: SevWarn,
				Scope:    alias,
				Message:  fmt.Sprintf("proxy_jump (%s) points the host at itself — sshmgr ignores it and connects directly", pjSrc),
			})
		}
	}

	// 10. Saved forward profiles: invalid type/spec, unknown alias, file
	// parse errors and name collisions across the file libraries.
	for name, p := range cfg.Forwards {
		scope := "forward " + name
		if name == "" {
			out = append(out, Finding{Severity: SevWarn, Scope: "forwards", Message: "an inline forward has an empty name"})
			continue
		}
		if err := forwards.ValidateProfile(p); err != nil {
			out = append(out, Finding{Severity: SevError, Scope: scope, Message: err.Error()})
			continue
		}
		if _, ok := cfg.Hosts[p.Alias]; !ok {
			out = append(out, Finding{Severity: SevError, Scope: scope, Message: fmt.Sprintf("references unknown alias %q", p.Alias)})
		}
	}
	fileFwds, fileFwdErrs := forwards.FileForwards(cfg)
	for _, e := range fileFwdErrs {
		out = append(out, Finding{Severity: SevError, Scope: "forwards", Message: e.Error()})
	}
	fileFwdCounts := map[string]int{}
	for _, r := range fileFwds {
		fileFwdCounts[r.Name]++
		scope := "forward " + r.Name + " (" + r.Source + ")"
		if err := forwards.ValidateProfile(r.ForwardProfile); err != nil {
			out = append(out, Finding{Severity: SevError, Scope: scope, Message: err.Error()})
			continue
		}
		if _, ok := cfg.Hosts[r.Alias]; !ok {
			out = append(out, Finding{Severity: SevError, Scope: scope, Message: fmt.Sprintf("references unknown alias %q", r.Alias)})
		}
	}
	for name, n := range fileFwdCounts {
		if n > 1 {
			out = append(out, Finding{Severity: SevWarn, Scope: "forwards", Message: fmt.Sprintf("forward %q is defined %d times across file libraries", name, n)})
		}
	}
	if cfg.ForwardsDir != "" {
		if _, err := os.Stat(config.ExpandPath(cfg.ForwardsDir)); err != nil {
			out = append(out, Finding{Severity: SevWarn, Scope: "config", Message: fmt.Sprintf("forwards_dir %q does not exist", cfg.ForwardsDir)})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return sevRank(out[i].Severity) < sevRank(out[j].Severity)
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

func sevRank(s Severity) int {
	switch s {
	case SevError:
		return 0
	case SevWarn:
		return 1
	default:
		return 2
	}
}

// Print writes findings to w as a coloured report. Returns the number of
// errors (callers can use this for the exit code).
func Print(findings []Finding) (errs int) {
	for _, f := range findings {
		mark := "•"
		switch f.Severity {
		case SevError:
			mark = "✗"
			errs++
		case SevWarn:
			mark = "!"
		case SevInfo:
			mark = "i"
		}
		fmt.Fprintf(os.Stderr, "%s  %-7s  %-25s  %s\n", mark, f.Severity, f.Scope, f.Message)
	}
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "✓ no issues found")
	}
	return errs
}
