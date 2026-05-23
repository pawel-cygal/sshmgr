package tui

import (
	"fmt"
	"strings"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/forwards"
	"sshmgr/internal/fwdregistry"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func (s *uiState) openForwardMenu(alias string) {
	list := tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" forwards · %s   (Enter=run  Esc=close) ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	close := func() {
		s.pages.RemovePage("forwardmenu")
		s.focusList()
	}

	runProfile := func(typ, spec, targetAlias string) {
		s.action = ActionForward
		s.extraArgs = []string{"-" + typ, spec}
		s.selected = targetAlias
		close()
		s.app.Stop()
	}

	list.AddItem("new forward", "open the setup form for a fresh forward", 0, func() {
		close()
		s.openForwardForm(alias)
	})

	for _, p := range forwards.ForAlias(s.cfg, alias) {
		p := p
		desc := p.Description
		sourceTag := p.Source
		if desc == "" {
			desc = sourceTag
		} else {
			desc = desc + "  ·  " + sourceTag
		}
		list.AddItem(
			fmt.Sprintf("[saved]   %s   -%s %s", p.Name, p.Type, p.Spec),
			desc, 0,
			func() { runProfile(p.Type, p.Spec, p.Alias) },
		)
	}

	for _, e := range s.cfg.ForwardHistory {
		if e.Alias != alias {
			continue
		}
		e := e
		sec := "last used " + e.LastUsed
		list.AddItem(
			fmt.Sprintf("[recent]  -%s %s", e.Type, e.Spec),
			sec, 0,
			func() { runProfile(e.Type, e.Spec, alias) },
		)
	}

	active, _ := fwdregistry.List()
	for _, e := range active {
		if e.Alias != alias {
			continue
		}
		e := e
		age := time.Since(e.StartedAt).Round(time.Second)
		list.AddItem(
			fmt.Sprintf("[active]  -%s %s   pid %d   age %s", e.Type, e.Spec, e.PID, age),
			e.Source+"  ·  "+e.Backend,
			0,
			// Enter on an active row asks to stop it rather than relaunching
			// it (which would race the live tunnel and double-bind). After
			// the confirm flow we reopen the forward menu so the user keeps
			// the manager context.
			func() {
				close()
				s.confirmKillForward(alias, e, func() { s.openForwardMenu(alias) })
			},
		)
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		return event
	})

	s.pages.AddPage("forwardmenu", centered(list, 80, 16), true, true)
	s.app.SetFocus(list)
}

// openForwardForm shows a port-forward setup dialog: type dropdown,
// spec field (with format hint), and a recent-history dropdown filtered to
// the current alias. On Save, sets state.action=ActionForward + extraArgs and
// stops the app so main can re-exec `sshmgr fwd <alias> -L/-R/-D <spec>`.
func (s *uiState) openForwardForm(alias string) {
	fwdTypes := []string{"L (local listen, dial remote)", "R (remote listen, dial local)", "D (SOCKS5 proxy)"}
	flags := []string{"-L", "-R", "-D"}
	typeIdx := 0
	spec := ""

	// Build the history dropdown options, most recent first, for this alias.
	histOpts := []string{"(new entry)"}
	histRefs := []config.ForwardEntry{{}}
	for _, h := range s.cfg.ForwardHistory {
		if h.Alias != alias {
			continue
		}
		histOpts = append(histOpts, fmt.Sprintf("-%s %s", h.Type, h.Spec))
		histRefs = append(histRefs, h)
	}

	form := tview.NewForm()
	specField := tview.NewInputField().SetLabel("spec ").SetFieldWidth(40)
	specField.SetChangedFunc(func(t string) { spec = strings.TrimSpace(t) })

	// Style for the expanded options list inside DropDown — without this the
	// popup uses tview's defaults and ignores our theme.
	listUnsel := tcell.StyleDefault.
		Background(tcell.ColorDefault).
		Foreground(theme.Current.Text)
	listSel := tcell.StyleDefault.
		Background(theme.Current.Selection).
		Foreground(theme.Current.Inverse).
		Bold(true)

	form.AddDropDown("type", fwdTypes, 0, func(_ string, i int) { typeIdx = i; updateSpecPlaceholder(specField, flags[i]) })
	form.AddDropDown("from history", histOpts, 0, func(_ string, i int) {
		if i == 0 {
			return
		}
		h := histRefs[i]
		for j, f := range flags {
			if strings.TrimPrefix(f, "-") == h.Type {
				typeIdx = j
				break
			}
		}
		// Reflect into the type dropdown widget.
		if dd, ok := form.GetFormItemByLabel("type").(*tview.DropDown); ok {
			dd.SetCurrentOption(typeIdx)
		}
		specField.SetText(h.Spec)
		spec = h.Spec
	})
	form.AddFormItem(specField)
	updateSpecPlaceholder(specField, "-L")

	if dd, ok := form.GetFormItemByLabel("type").(*tview.DropDown); ok {
		dd.SetListStyles(listUnsel, listSel)
	}
	if dd, ok := form.GetFormItemByLabel("from history").(*tview.DropDown); ok {
		dd.SetListStyles(listUnsel, listSel)
	}

	form.AddButton("Run", func() {
		if spec == "" {
			s.modal("spec is empty", func() { s.app.SetFocus(form) })
			return
		}
		s.selected = alias
		s.action = ActionForward
		s.extraArgs = []string{flags[typeIdx], spec}
		s.pages.RemovePage("fwdform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("fwdform")
		if s.mode == modeTree {
			s.app.SetFocus(s.tree)
		} else {
			s.app.SetFocus(s.list)
		}
	})
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" port forward · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	s.pages.AddPage("fwdform", centered(form, 72, 14), true, true)
	s.app.SetFocus(form)
}

func updateSpecPlaceholder(f *tview.InputField, flag string) {
	switch flag {
	case "-L":
		f.SetPlaceholder("port:host:port  or  bind:port:host:port")
	case "-R":
		f.SetPlaceholder("remotePort:localHost:localPort")
	case "-D":
		f.SetPlaceholder("port  (SOCKS5 bind)")
	}
}

// inputPrompt shows a simple "label + InputField + OK/Cancel" modal that
// invokes onSubmit with the entered text on OK.
func (s *uiState) killActiveForHost(alias string) {
	all, _ := fwdregistry.List()
	var live []fwdregistry.Entry
	for _, e := range all {
		if e.Alias == alias {
			live = append(live, e)
		}
	}
	switch len(live) {
	case 0:
		s.modal(fmt.Sprintf("no active forwards on %s", alias), nil)
	case 1:
		// K is launched from the host list — nil onClose so the user lands
		// back on the host list instead of being dropped into the p-menu
		// they didn't open.
		s.confirmKillForward(alias, live[0], nil)
	default:
		s.modal(fmt.Sprintf("%s has %d active forwards — open the menu with `p` and Enter on the one to stop", alias, len(live)), nil)
	}
}

// confirmKillForward asks the user to confirm stopping a live tunnel. On
// Stop it sends SIGTERM (escalating to SIGKILL after a brief grace).
// onClose runs after every exit path (Cancel, Stop+success, Stop+error)
// so callers control where the user lands — the p-menu flow reopens the
// menu, the host-list `K` flow returns straight to the host list.
func (s *uiState) confirmKillForward(alias string, e fwdregistry.Entry, onClose func()) {
	afterClose := func() {
		if onClose != nil {
			onClose()
		} else {
			s.focusList()
		}
	}
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Stop forward -%s %s on %s (pid %d)?", e.Type, e.Spec, e.Alias, e.PID)).
		AddButtons([]string{"Stop", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			s.pages.RemovePage("killconfirm")
			if label != "Stop" {
				afterClose()
				return
			}
			if err := fwdregistry.Kill(e, 2*time.Second); err != nil {
				s.modal("kill failed: "+err.Error(), afterClose)
				return
			}
			s.modal(fmt.Sprintf("stopped -%s %s (pid %d)", e.Type, e.Spec, e.PID), afterClose)
		})
	s.pages.AddPage("killconfirm", modal, true, true)
}

