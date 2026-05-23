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

func filterResolved(items []snippets.Resolved, q string) []snippets.Resolved {
	if q == "" {
		return items
	}
	needle := strings.ToLower(q)
	out := make([]snippets.Resolved, 0, len(items))
	for _, sn := range items {
		if strings.Contains(strings.ToLower(sn.Name), needle) ||
			strings.Contains(strings.ToLower(sn.Description), needle) ||
			strings.Contains(strings.ToLower(sn.Command), needle) ||
			strings.Contains(strings.ToLower(sn.Source), needle) {
			out = append(out, sn)
		}
	}
	return out
}

func sourceLabel(src string) string {
	if strings.HasPrefix(src, "host:") {
		return "host"
	}
	return src // "group:<name>" or "file:<filename>"
}

// openWatchPrompt asks for a command to watch on the host, then exits the
// TUI so main re-execs `sshmgr watch <alias> <cmd>`.
func (s *uiState) snippetScope(alias string) (aliases, selector []string, multi bool) {
	if len(s.multiSelected) > 0 {
		aliases = make([]string, 0, len(s.multiSelected))
		for a := range s.multiSelected {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
		return aliases, []string{"--host", strings.Join(aliases, ",")}, true
	}
	return []string{alias}, []string{"--host", alias}, false
}

// openSnippetMenu lists the snippets visible on the host across all three
// layers — file libraries, the host's groups and the host itself — each
// tagged with its source. Enter runs the highlighted snippet via
// `sshmgr exec` so the scrollable result viewer (and its back-to-UI / exit
// choice) applies. With a non-empty multi-selection the picker offers only
// the snippets every selected host shares and runs on all of them. 'a' adds
// a new host-level snippet; 'd' deletes a host-level one (group / file
// snippets show a note pointing at where they're defined) — both require
// a single-host scope. 'Esc' closes.
func (s *uiState) openSnippetMenu(alias string) {
	scopeAliases, selectorArgs, multi := s.snippetScope(alias)

	var all []snippets.Resolved
	if multi {
		for _, sn := range s.sharedSnippets(scopeAliases) {
			all = append(all, snippets.Resolved{Snippet: sn, Source: "shared"})
		}
	} else {
		all = snippets.For(s.cfg, alias)
	}

	titleScope := alias
	titleKeys := "(a=add  d=del  Enter=run  /=filter  Esc)"
	if multi {
		titleScope = fmt.Sprintf("%d selected hosts", len(scopeAliases))
		titleKeys = "(Enter=run on all  /=filter  Esc · deselect to add/del)"
	}

	list := tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" snippets · %s   %s ", titleScope, titleKeys)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	// `visible` parallels list items, indexed by row, so Enter from the
	// filter input can trigger the highlighted row's run action.
	var visible []snippets.Resolved
	rebuild := func(filter string) {
		list.Clear()
		visible = filterResolved(all, filter)
		for _, sn := range visible {
			sn := sn
			body := sn.Description
			if body == "" {
				body = sn.Command
			}
			list.AddItem(sn.Name, "["+sourceLabel(sn.Source)+"]  "+body, 0, func() {
				s.action = ActionExec
				s.extraArgs = execExtraArgs(false, selectorArgs, sn.Command)
				s.app.Stop()
			})
		}
		if list.GetItemCount() == 0 {
			msg := "(no snippets yet — press 'a' to add)"
			switch {
			case multi:
				msg = "(no snippets shared across the selection)"
			case filter != "":
				msg = fmt.Sprintf("(no match for %q)", filter)
			}
			list.AddItem(msg, "", 0, nil)
		}
	}
	rebuild("")

	filterInput := tview.NewInputField().
		SetLabel("/ ").
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.FieldText).
		SetLabelColor(theme.Current.Dim)
	filterInput.SetChangedFunc(func(text string) { rebuild(text) })

	close := func() {
		s.pages.RemovePage("snippets")
		s.focusList()
	}

	runSelected := func() {
		idx := list.GetCurrentItem()
		if idx < 0 || idx >= len(visible) {
			return
		}
		sn := visible[idx]
		s.action = ActionExec
		s.extraArgs = execExtraArgs(false, selectorArgs, sn.Command)
		s.app.Stop()
	}

	deleteSelected := func() {
		idx := list.GetCurrentItem()
		if idx < 0 || idx >= len(visible) {
			return
		}
		r := visible[idx]
		close()
		switch {
		case strings.HasPrefix(r.Source, "host:"):
			s.deleteSnippet(alias, r.Name)
		case strings.HasPrefix(r.Source, "group:"):
			s.modal(fmt.Sprintf("snippet %q is inherited from %s — edit that group's snippets list to remove it", r.Name, r.Source), nil)
		default:
			s.modal(fmt.Sprintf("snippet %q comes from a file library (%s) — edit that file to remove it", r.Name, r.Source), nil)
		}
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		switch event.Rune() {
		case '/':
			s.app.SetFocus(filterInput)
			return nil
		case 'a':
			if multi {
				s.modal("multi-select is active — Space to deselect, then 'a' to add a snippet", nil)
				return nil
			}
			close()
			s.addSnippetPrompt(alias)
			return nil
		case 'd':
			if multi {
				s.modal("multi-select is active — Space to deselect, then 'd' to delete a snippet", nil)
				return nil
			}
			deleteSelected()
			return nil
		}
		return event
	})

	// While the filter input has focus the user types into the filter;
	// Up/Down still drive the list and Enter runs the highlighted entry,
	// so the snippet picker stays usable without leaving the input field.
	filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			filterInput.SetText("")
			rebuild("")
			s.app.SetFocus(list)
			return nil
		case tcell.KeyEnter:
			runSelected()
			return nil
		case tcell.KeyUp:
			i := list.GetCurrentItem() - 1
			if i < 0 {
				i = 0
			}
			list.SetCurrentItem(i)
			return nil
		case tcell.KeyDown:
			i := list.GetCurrentItem() + 1
			if i >= list.GetItemCount() {
				i = list.GetItemCount() - 1
			}
			list.SetCurrentItem(i)
			return nil
		}
		return event
	})

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(list, 0, 1, true).
		AddItem(filterInput, 1, 0, false)
	s.pages.AddPage("snippets", centered(layout, 80, 18), true, true)
	s.app.SetFocus(list)
}

// addSnippetPrompt shows a small form to attach a new snippet to the host.
func (s *uiState) addSnippetPrompt(alias string) {
	var (
		name, cmd, desc string
	)
	form := tview.NewForm().
		AddInputField("name", "", 30, nil, func(v string) { name = strings.TrimSpace(v) }).
		AddInputField("command", "", 60, nil, func(v string) { cmd = v }).
		AddInputField("description", "", 60, nil, func(v string) { desc = v })
	form.AddButton("Save", func() {
		if name == "" || cmd == "" {
			s.modal("name and command are required", func() { s.app.SetFocus(form) })
			return
		}
		h := s.cfg.Hosts[alias]
		h.Snippets = append(h.Snippets, config.Snippet{Name: name, Command: cmd, Description: desc})
		s.cfg.Hosts[alias] = h
		if err := config.Save(s.cfg, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.pages.RemovePage("snippet-add")
		s.focusList()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("snippet-add")
		s.focusList()
	})
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" new snippet · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	s.pages.AddPage("snippet-add", centered(form, 72, 12), true, true)
	s.app.SetFocus(form)
}

func (s *uiState) deleteSnippet(alias, name string) {
	h := s.cfg.Hosts[alias]
	out := make([]config.Snippet, 0, len(h.Snippets))
	for _, sn := range h.Snippets {
		if sn.Name != name {
			out = append(out, sn)
		}
	}
	if len(out) == len(h.Snippets) {
		s.modal(fmt.Sprintf("snippet %q is inherited from a group — edit the group's snippets list to remove it", name), nil)
		return
	}
	h.Snippets = out
	s.cfg.Hosts[alias] = h
	if err := config.Save(s.cfg, s.configPath); err != nil {
		s.modal("save failed: "+err.Error(), nil)
	}
}

// openPlaybookForm starts the two-step Ansible-playbook launcher: a
// filterable picker for the playbook (step 1), then a small form for
// check / diff / extra-vars (step 2). The target follows the same rule as
// exec — multi-select, else the group node, else the host under the
// cursor. On Run the TUI exits and main re-execs `sshmgr playbook …`.
