package tui

import (
	"fmt"
	"sort"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/snippets"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func (s *uiState) scopeSelector() (label string, args []string, ok bool) {
	if len(s.multiSelected) > 0 {
		aliases := make([]string, 0, len(s.multiSelected))
		for a := range s.multiSelected {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
		return fmt.Sprintf("%d selected host(s)", len(aliases)),
			[]string{"--host", strings.Join(aliases, ",")}, true
	}
	// On a tree group node currentAlias is "" — scope to the whole group.
	alias := s.currentAlias()
	if alias == "" {
		if g := s.currentGroup(); g != "" {
			return "group " + g, []string{"--group", g}, true
		}
		return "", nil, false
	}
	return alias, []string{"--host", alias}, true
}

// execExtraArgs assembles the ActionExec extraArgs: an optional --diff, the
// {--host|--group} selector, then "--" and the command. The "--" terminator
// keeps a command that starts with a dash (e.g. "--version") from being
// parsed as an sshmgr exec flag.
func execExtraArgs(diff bool, selectorArgs []string, command string) []string {
	var args []string
	if diff {
		args = append(args, "--diff")
	}
	args = append(args, selectorArgs...)
	return append(args, "--", command)
}

func (s *uiState) openExecPrompt() {
	selectorLabel, selectorArgs, ok := s.scopeSelector()
	if !ok {
		s.modal("nothing selected — move the cursor to a host (or a group node) first, or Space to multi-select", nil)
		return
	}

	// Build the snippet list shared by every host in scope. For ActionExec
	// only snippets that ALL targets have make sense (else some hosts will
	// fail). For single-host scope it's just that host's snippets.
	targetAliases := s.execScopeAliases(selectorArgs)
	shared := s.sharedSnippets(targetAliases)

	var commands string
	form := tview.NewForm()

	// Add the textarea FIRST so the dropdown callback below can find it via
	// GetFormItemByLabel — if we added the dropdown first the lookup would
	// return nil (it walks the items added so far) and snippet picks would
	// silently fail to update the visible text.
	form.AddTextArea("commands (one per line)", "", 60, 6, 0, func(v string) { commands = v })

	driftMode := false
	form.AddCheckbox("group identical output (drift detection)", false, func(v bool) { driftMode = v })

	if len(shared) > 0 {
		opts := []string{"(none)"}
		for _, sn := range shared {
			label := sn.Name
			if sn.Description != "" {
				label += "  — " + sn.Description
			}
			opts = append(opts, label)
		}
		form.AddDropDown("snippet (optional)", opts, 0, func(_ string, i int) {
			if i <= 0 {
				return
			}
			sn := shared[i-1]
			if commands == "" {
				commands = sn.Command
			} else {
				commands = commands + "\n" + sn.Command
			}
			if ta, ok := form.GetFormItemByLabel("commands (one per line)").(*tview.TextArea); ok {
				ta.SetText(commands, true)
			}
		})
		if dd, ok := form.GetFormItemByLabel("snippet (optional)").(*tview.DropDown); ok {
			dd.SetListStyles(
				tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(theme.Current.Text),
				tcell.StyleDefault.Background(theme.Current.Selection).Foreground(theme.Current.Inverse).Bold(true),
			)
		}
	}

	form.AddButton("Run", func() {
		var clean []string
		for _, l := range strings.Split(commands, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				clean = append(clean, l)
			}
		}
		if len(clean) == 0 {
			s.modal("no commands entered", func() { s.app.SetFocus(form) })
			return
		}
		// Multiple lines run as a single shell command joined with '; '. SSH
		// already wraps in `sh -c` on the remote so this is the natural way
		// to chain steps.
		s.action = ActionExec
		s.extraArgs = execExtraArgs(driftMode, selectorArgs, strings.Join(clean, "; "))
		s.pages.RemovePage("execform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("execform")
		s.focusList()
	})
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" run command on %s ", selectorLabel)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	s.pages.AddPage("execform", centered(form, 80, 16), true, true)
	s.app.SetFocus(form)
}

// execScopeAliases returns the alias list described by selectorArgs (--host
// a,b,c or --group g). Used to gather shared snippets for the exec prompt.
func (s *uiState) execScopeAliases(selectorArgs []string) []string {
	if len(selectorArgs) < 2 {
		return nil
	}
	switch selectorArgs[0] {
	case "--host":
		return strings.Split(selectorArgs[1], ",")
	case "--group":
		out := []string{}
		group := selectorArgs[1]
		for alias, h := range s.cfg.Hosts {
			for _, g := range h.Groups {
				if g == group {
					out = append(out, alias)
					break
				}
			}
		}
		return out
	}
	return nil
}

// sharedSnippets returns snippets whose Name is visible (across the file /
// group / host layers) on every alias in scope.
func (s *uiState) sharedSnippets(aliases []string) []config.Snippet {
	if len(aliases) == 0 {
		return nil
	}
	type agg struct {
		count    int
		snippet  config.Snippet
		conflict bool // same name, different command across hosts
	}
	counts := map[string]*agg{}
	for _, a := range aliases {
		for _, sn := range snippets.For(s.cfg, a) {
			if c, ok := counts[sn.Name]; ok {
				c.count++
				if c.snippet.Command != sn.Command {
					c.conflict = true
				}
			} else {
				counts[sn.Name] = &agg{count: 1, snippet: sn.Snippet}
			}
		}
	}
	// A snippet is "shared" only when every selected host has the name AND
	// the command is identical everywhere — a host- or file-level override
	// to a different command would otherwise be run fleet-wide unnoticed.
	out := []config.Snippet{}
	for _, c := range counts {
		if c.count == len(aliases) && !c.conflict {
			out = append(out, c.snippet)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sourceLabel shortens a snippet's Source for the picker. The picker is
// already scoped to one host, so "host:" collapses to "host"; group and
// file keep their name so the user knows where to edit it.
// filterStrings keeps strings that contain q (case-insensitive). Empty q
// passes everything through — used by the playbook picker's filter input.
func (s *uiState) openWatchPrompt(alias string) {
	var command string
	interval := "2"
	form := tview.NewForm()
	form.AddInputField("command", "", 60, nil, func(v string) { command = v })
	form.AddInputField("interval (seconds)", "2", 6, tview.InputFieldInteger, func(v string) { interval = v })
	form.AddButton("Watch", func() {
		command = strings.TrimSpace(command)
		if command == "" {
			s.modal("command is empty", func() { s.app.SetFocus(form) })
			return
		}
		if interval == "" {
			interval = "2"
		}
		s.selected = alias
		s.action = ActionWatch
		// extraArgs = {interval, command}; main assembles the flag order.
		s.extraArgs = []string{interval, command}
		s.pages.RemovePage("watchform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("watchform")
		s.focusList()
	})
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" watch · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	s.pages.AddPage("watchform", centered(form, 74, 10), true, true)
	s.app.SetFocus(form)
}

// snippetScope picks the hosts the snippet menu runs against: any non-empty
// multi-selection wins (matching the `x` exec flow), otherwise the single
// highlighted alias. Returns the aliases (for sharedSnippets), the exec
// --host selector, and whether multi-select is active.
