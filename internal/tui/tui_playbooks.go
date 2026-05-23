package tui

import (
	"fmt"
	"strings"

	"sshmgr/internal/ansible"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func filterStrings(items []string, q string) []string {
	if q == "" {
		return items
	}
	needle := strings.ToLower(q)
	out := make([]string, 0, len(items))
	for _, s := range items {
		if strings.Contains(strings.ToLower(s), needle) {
			out = append(out, s)
		}
	}
	return out
}

// filterResolved keeps snippets whose name, description, command or source
// label contains q (case-insensitive). An empty q passes everything
// through — used by the snippet picker's `/`-filter mode.
func (s *uiState) openPlaybookForm() {
	label, selectorArgs, ok := s.scopeSelector()
	if !ok {
		s.modal("nothing selected — move the cursor to a host (or a group node) first, or Space to multi-select", nil)
		return
	}
	dir := s.cfg.ResolvePlaybooksDir()
	books, err := ansible.DiscoverPlaybooks(dir)
	if err != nil {
		s.modal("cannot read playbooks dir: "+err.Error(), nil)
		return
	}
	if len(books) == 0 {
		s.modal(fmt.Sprintf("no playbooks (*.yml / *.yaml) in %s\nset playbooks_dir in the config or add files there", dir), nil)
		return
	}
	s.openPlaybookPicker(label, selectorArgs, books)
}

// openPlaybookPicker shows the filterable playbook list. Mirrors the
// snippet picker: `/` focuses the filter, Up/Down still drive the list and
// Enter from the filter runs the highlighted entry, Esc clears the filter
// (or closes the picker when focus is on the list).
func (s *uiState) openPlaybookPicker(label string, selectorArgs, books []string) {
	list := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" pick a playbook · %s   (Enter=continue  /=filter  Esc=close) ", label)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	var visible []string
	rebuild := func(filter string) {
		list.Clear()
		visible = filterStrings(books, filter)
		for _, b := range visible {
			b := b
			list.AddItem(b, "", 0, func() {
				s.pages.RemovePage("playbookpicker")
				s.openPlaybookOptions(label, selectorArgs, books, b)
			})
		}
		if list.GetItemCount() == 0 {
			list.AddItem(fmt.Sprintf("(no playbook matching %q)", filter), "", 0, nil)
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
		s.pages.RemovePage("playbookpicker")
		s.focusList()
	}
	runSelected := func() {
		idx := list.GetCurrentItem()
		if idx < 0 || idx >= len(visible) {
			return
		}
		picked := visible[idx]
		s.pages.RemovePage("playbookpicker")
		s.openPlaybookOptions(label, selectorArgs, books, picked)
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		if event.Rune() == '/' {
			s.app.SetFocus(filterInput)
			return nil
		}
		return event
	})
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
	s.pages.AddPage("playbookpicker", centered(layout, 80, 18), true, true)
	s.app.SetFocus(list)
}

// openPlaybookOptions is step 2 of the playbook launcher: a small form
// for check / diff / extra-vars + Run / Cancel. Esc returns to the picker
// so the user can change their mind without leaving the manager flow.
func (s *uiState) openPlaybookOptions(label string, selectorArgs, books []string, playbook string) {
	var (
		check     bool
		diff      bool
		extraVars string
	)
	form := tview.NewForm()
	form.AddCheckbox("check mode (--check)", false, func(v bool) { check = v })
	form.AddCheckbox("show diffs (--diff)", false, func(v bool) { diff = v })
	form.AddInputField("extra-vars", "", 50, nil, func(v string) { extraVars = v })

	form.AddButton("Run", func() {
		s.action = ActionPlaybook
		s.extraArgs = playbookExtraArgs(playbook, selectorArgs, check, diff, extraVars)
		s.pages.RemovePage("playbookform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("playbookform")
		s.focusList()
	})
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" ansible-playbook · %s · %s ", playbook, label)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			s.pages.RemovePage("playbookform")
			s.openPlaybookPicker(label, selectorArgs, books)
			return nil
		}
		return event
	})

	s.pages.AddPage("playbookform", centered(form, 76, 12), true, true)
	s.app.SetFocus(form)
}

// playbookExtraArgs assembles the ActionPlaybook extraArgs: the playbook
// name, the {--host|--group} selector, then the optional flags.
func playbookExtraArgs(playbook string, selectorArgs []string, check, diff bool, extraVars string) []string {
	args := append([]string{playbook}, selectorArgs...)
	if check {
		args = append(args, "--check")
	}
	if diff {
		args = append(args, "--diff")
	}
	if ev := strings.TrimSpace(extraVars); ev != "" {
		args = append(args, "--extra-vars", ev)
	}
	return args
}

// openForwardMenu shows a forward-manager menu for the host: a "new
// forward" entry that opens the existing setup form, plus inline rows for
// every saved profile matching this alias, every recent run from history,
// and every currently-active tunnel (informational — selecting an active
// row is a no-op). Selecting a saved or recent entry runs it via the same
// re-exec path as the form.
