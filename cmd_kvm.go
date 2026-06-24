package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/kvm"
	"sshmgr/internal/secret"
)

// cmdKVM implements `sshmgr kvm <alias> <action> [--yes]`, controlling a host's
// out-of-band KVM. reset/power/off act on the target machine and require
// confirmation; web opens the device UI; status reports reachability/state.
func cmdKVM(args []string) {
	yes := false
	var rest []string
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			yes = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) < 2 {
		fatal("usage: sshmgr kvm <alias> <reset|power|off|web|status> [--yes]")
	}
	alias, action := rest[0], rest[1]

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	if h.KVM == nil {
		fatal("no kvm configured for " + alias)
	}

	k := *h.KVM
	vars := map[string]string{
		"alias": alias,
		"host":  h.Host,
		"user":  h.User,
		"port":  strconv.Itoa(h.Port),
	}
	kvmHost := k.ResolvedHost(vars)
	if kvmHost == "" {
		fatal("kvm host is empty for " + alias)
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

	prov, err := kvm.New(k, kvmHost, pass)
	if err != nil {
		fatal(err.Error())
	}
	ctx := context.Background()

	switch action {
	case "web":
		url := prov.WebURL()
		if err := openBrowser(url); err != nil {
			fatal("open browser: " + err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] opening %s\n", url)
	case "status":
		s, err := prov.Status(ctx)
		if err != nil {
			fatal(err.Error())
		}
		fmt.Println(s)
	case "reset", "power", "off":
		if !yes && !confirmKVM(action, alias, kvmHost) {
			fmt.Fprintln(os.Stderr, "aborted")
			return
		}
		var aerr error
		switch action {
		case "reset":
			aerr = prov.Reset(ctx)
		case "power":
			aerr = prov.Power(ctx)
		case "off":
			aerr = prov.Off(ctx)
		}
		if aerr != nil {
			fatal(aerr.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] kvm %s sent to %s (%s)\n", action, alias, kvmHost)
	default:
		fatal("unknown action " + action + " (reset|power|off|web|status)")
	}
}

func confirmKVM(action, alias, kvmHost string) bool {
	reader := bufio.NewReader(os.Stdin)
	ans := prompt(reader, fmt.Sprintf("%s %s via KVM (%s)?", action, alias, kvmHost), "n")
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

// openBrowser launches the platform's default browser for url.
func openBrowser(url string) error {
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
