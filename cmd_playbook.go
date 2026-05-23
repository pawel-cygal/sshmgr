package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"sshmgr/internal/ansible"
	"sshmgr/internal/config"

)

func cmdExport(args []string) {
	if len(args) < 1 {
		fatal("usage: sshmgr export ansible [--format yaml|ini] [--group G|--tag T|--host a,b|--all] [--out path]")
	}
	switch args[0] {
	case "ansible":
		cmdExportAnsible(args[1:])
	default:
		fatal("unknown export target %q — use: ansible")
	}
}

func cmdExportAnsible(args []string) {
	fs := flag.NewFlagSet("export ansible", flag.ExitOnError)
	format := fs.String("format", "yaml", "inventory format: yaml | ini")
	group := fs.String("group", "", "select hosts in this group")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias")
	out := fs.String("out", "", "write to this file instead of stdout")
	_ = fs.Parse(args)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("export ansible takes no positional arguments; unexpected: " + strings.Join(extra, " "))
	}

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	aliases := selectAliases(cfg, *group, *tag, *hosts, *all)
	inv, err := ansible.Inventory(cfg, aliases, *format)
	if err != nil {
		fatal(err.Error())
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(inv), 0o644); err != nil {
			fatal(err.Error())
		}
		fmt.Fprintf(os.Stderr, "[sshmgr] wrote inventory for %d host(s) to %s\n", len(aliases), *out)
		return
	}
	fmt.Print(inv)
}

// multiFlag collects a repeatable string flag (e.g. --extra-vars).
type multiFlag []string

func splitPlaybookArgs(args []string) (playbook string, flagArgs []string) {
	valueFlags := map[string]bool{
		"-group": true, "--group": true, "-tag": true, "--tag": true,
		"-host": true, "--host": true, "-limit": true, "--limit": true,
		"-extra-vars": true, "--extra-vars": true,
	}
	var extras []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if valueFlags[a] && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		if playbook == "" {
			playbook = a
		} else {
			extras = append(extras, a)
		}
	}
	return playbook, append(flagArgs, extras...)
}

// cmdPlaybook runs an Ansible playbook against selected hosts: it generates a
// temporary inventory from the fleet and shells out to `ansible-playbook`.
func cmdPlaybook(args []string) {
	playbookArg, flagArgs := splitPlaybookArgs(args)
	if playbookArg == "" {
		fatal("usage: sshmgr playbook <playbook.yml> [--group G|--tag T|--host a,b|--all] [--check] [--diff] [--limit E] [--extra-vars V] [--inventory-debug]")
	}
	fs := flag.NewFlagSet("playbook", flag.ExitOnError)
	group := fs.String("group", "", "select hosts in this group")
	tag := fs.String("tag", "", "select hosts with this tag")
	hosts := fs.String("host", "", "comma-separated alias list")
	all := fs.Bool("all", false, "select every alias")
	check := fs.Bool("check", false, "run ansible-playbook in --check (dry-run) mode")
	diff := fs.Bool("diff", false, "pass --diff to ansible-playbook")
	limit := fs.String("limit", "", "ansible --limit pattern (further restricts the run)")
	invDebug := fs.Bool("inventory-debug", false, "print the generated inventory and exit")
	var extraVars multiFlag
	fs.Var(&extraVars, "extra-vars", "extra vars for ansible-playbook (repeatable)")
	_ = fs.Parse(flagArgs)
	if extra := fs.Args(); len(extra) > 0 {
		fatal("unexpected argument(s) after the playbook: " + strings.Join(extra, " ") +
			" (one playbook per invocation; scope hosts with --group/--tag/--host)")
	}

	cfg, _, err := config.Load()
	if err != nil {
		fatal(err.Error())
	}
	aliases := selectAliases(cfg, *group, *tag, *hosts, *all)

	inv, err := ansible.Inventory(cfg, aliases, "yaml")
	if err != nil {
		fatal(err.Error())
	}
	if *invDebug {
		fmt.Print(inv)
		return
	}

	pbPath, err := ansible.ResolvePlaybook(playbookArg, cfg.ResolvePlaybooksDir())
	if err != nil {
		fatal(err.Error())
	}
	pbBin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		fatal("ansible-playbook not found in PATH — install Ansible to run playbooks")
	}

	tmp, err := os.CreateTemp("", "sshmgr-inventory-*.yaml")
	if err != nil {
		fatal(err.Error())
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(inv); err != nil {
		tmp.Close()
		fatal(err.Error())
	}
	if err := tmp.Close(); err != nil {
		fatal(err.Error())
	}

	argv := ansible.PlaybookArgv(pbPath, tmpName, ansible.PlaybookOptions{
		Check:     *check,
		Diff:      *diff,
		Limit:     *limit,
		ExtraVars: extraVars,
	})
	fmt.Fprintf(os.Stderr, "[sshmgr] ansible-playbook on %d host(s): %s\n", len(aliases), pbPath)
	cmd := exec.Command(pbBin, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fatal(err.Error())
	}
}

// cmdRotateKey rolls a new SSH key onto a fleet, safely: append the new key,
// verify it works with a key-only connection, and only then (with
// --remove-old) drop the old key. Never removes the old key unless the new
// one is proven to work.
