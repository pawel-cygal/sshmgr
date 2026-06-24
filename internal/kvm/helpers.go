package kvm

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"

	"sshmgr/internal/config"
	"sshmgr/internal/secret"
)

// ForHost builds the Provider for a resolved host's kvm block and returns the
// resolved KVM address alongside it. The password is resolved lazily from the
// kvm block's own secret backends (independent of SSH auth). Shared by the CLI
// and the TUI so both build providers identically.
func ForHost(h config.HostConfig, alias string) (Provider, string, error) {
	if h.KVM == nil {
		return nil, "", fmt.Errorf("no kvm configured for %s", alias)
	}
	k := *h.KVM
	vars := map[string]string{
		"alias": alias,
		"host":  h.Host,
		"user":  h.User,
		"port":  strconv.Itoa(h.Port),
	}
	host := k.ResolvedHost(vars)
	if host == "" {
		return nil, "", fmt.Errorf("kvm host is empty for %s", alias)
	}
	pass := func() (string, error) {
		return secret.ResolveSpec(secret.Spec{
			Literal: k.Password,
			Env:     k.PasswordEnv,
			Keyring: k.PasswordKeyring,
			Cmd:     k.PasswordCmd,
			Prompt:  k.PasswordPrompt,
			Label:   "kvm password for " + alias,
			Vars:    vars,
		})
	}
	p, err := New(k, host, pass)
	return p, host, err
}

// OpenURL opens url in the platform's default browser.
func OpenURL(url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		name, args = "xdg-open", []string{url}
	}
	return exec.Command(name, args...).Start()
}
