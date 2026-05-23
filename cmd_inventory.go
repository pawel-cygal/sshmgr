package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"sshmgr/internal/config"

)

func cmdHistory(args []string) {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	what := "transfers"
	if len(args) >= 1 {
		what = args[0]
	}
	switch what {
	case "transfers", "xfer":
		if len(cfg.TransferHistory) == 0 {
			fmt.Fprintln(os.Stderr, "no transfers logged yet")
			return
		}
		for _, e := range cfg.TransferHistory {
			arrow := "->"
			a, b := e.Local, e.Remote
			if e.Direction == "down" {
				arrow = "<-"
				a, b = e.Remote, e.Local
			}
			fmt.Printf("%s  %s  %-22s %s %s %s  (%s)\n",
				e.When, e.Direction, e.Alias, a, arrow, b, humanBytes(e.Bytes))
		}
	case "forwards", "fwd":
		if len(cfg.ForwardHistory) == 0 {
			fmt.Fprintln(os.Stderr, "no forwards logged yet")
			return
		}
		for _, e := range cfg.ForwardHistory {
			fmt.Printf("%s  %-22s -%s %s\n", e.LastUsed, e.Alias, e.Type, e.Spec)
		}
	case "logins", "login":
		if len(cfg.LoginHistory) == 0 {
			fmt.Fprintln(os.Stderr, "no logins logged yet")
			return
		}
		for _, e := range cfg.LoginHistory {
			fmt.Printf("%s  %-7s %s\n", e.When, e.Action, e.Alias)
		}
	default:
		fatal("usage: sshmgr history [transfers|forwards|logins]")
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	groupFilter := fs.String("group", "", "show only hosts in this group")
	tagFilter := fs.String("tag", "", "show only hosts with this tag")
	_ = fs.Parse(args)

	cfg, path, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	if len(cfg.Hosts) == 0 {
		fmt.Fprintf(os.Stderr, "no hosts configured in %s\n", path)
		return
	}
	aliases := make([]string, 0, len(cfg.Hosts))
	for a := range cfg.Hosts {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	matched := 0
	for _, a := range aliases {
		h, _ := cfg.ResolveHost(a)
		if *groupFilter != "" && !containsString(h.Groups, *groupFilter) {
			continue
		}
		if *tagFilter != "" && !containsString(h.Tags, *tagFilter) {
			continue
		}
		tags := ""
		if len(h.Tags) > 0 {
			tags = "  [" + strings.Join(h.Tags, " ") + "]"
		}
		fmt.Printf("%-25s %s@%s:%d%s\n", a, h.User, h.Host, h.Port, tags)
		matched++
	}
	if matched == 0 {
		fmt.Fprintf(os.Stderr, "no hosts match the given filters\n")
	}
}

func cmdGroups() {
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	counts := map[string]int{}
	for _, h := range cfg.Hosts {
		for _, g := range h.Groups {
			counts[g]++
		}
	}
	names := make([]string, 0, len(cfg.Groups))
	for g := range cfg.Groups {
		names = append(names, g)
	}
	for g := range counts {
		if _, ok := cfg.Groups[g]; !ok {
			names = append(names, g) // host references a non-defined group; still report it
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "no groups defined")
		return
	}
	for _, g := range names {
		marker := ""
		if _, defined := cfg.Groups[g]; !defined {
			marker = "  (used but not defined)"
		}
		fmt.Printf("%-20s %d host(s)%s\n", g, counts[g], marker)
	}
}

func cmdInfo(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr info <alias>")
	}
	alias := args[0]
	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	h, ok := cfg.ResolveHost(alias)
	if !ok {
		fatal("alias not found: " + alias)
	}
	out := struct {
		Alias string             `json:"alias"`
		Host  config.HostConfig `json:"host"`
	}{Alias: alias, Host: h}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal(err.Error())
	}
}

