package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/kvm"
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
	prov, kvmHost, err := kvm.ForHost(h, alias)
	if err != nil {
		fatal(err.Error())
	}
	ctx := context.Background()

	switch action {
	case "web":
		url := prov.WebURL()
		if err := kvm.OpenURL(url); err != nil {
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
