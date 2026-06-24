package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"sshmgr/internal/kvm"
	"sshmgr/internal/theme"
)

// openKVMMenu shows the out-of-band power actions for a host's KVM. web opens
// the browser in-process; status/reset/power/off run their network calls in a
// goroutine (so the UI stays live) and report the outcome in a modal.
// reset/power/off confirm first, naming the host AND the KVM address.
func (s *uiState) openKVMMenu(alias string) {
	h, ok := s.cfg.ResolveHost(alias)
	if !ok || h.KVM == nil {
		s.modal("no kvm configured for "+alias, nil)
		return
	}
	prov, kvmHost, err := kvm.ForHost(h, alias)
	if err != nil {
		s.modal("kvm: "+err.Error(), nil)
		return
	}

	list := tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" kvm · %s (%s)   (Enter=run  Esc) ", alias, kvmHost)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	closeMenu := func() {
		s.pages.RemovePage("kvm")
		s.focusList()
	}

	// runAction runs a network call off the UI thread and reports the outcome.
	runAction := func(verb string, fn func(context.Context) error) {
		go func() {
			err := fn(context.Background())
			s.app.QueueUpdateDraw(func() {
				if err != nil {
					s.modal(fmt.Sprintf("kvm %s failed:\n\n%v", verb, err), nil)
				} else {
					s.modal(fmt.Sprintf("kvm %s sent to %s (%s)", verb, alias, kvmHost), nil)
				}
			})
		}()
	}

	confirmThenRun := func(verb string, fn func(context.Context) error) {
		closeMenu()
		btn := strings.ToUpper(verb[:1]) + verb[1:]
		modal := tview.NewModal().
			SetText(fmt.Sprintf("%s %s via KVM (%s)?", btn, alias, kvmHost)).
			AddButtons([]string{btn, "Cancel"}).
			SetDoneFunc(func(_ int, label string) {
				s.pages.RemovePage("kvmconfirm")
				if label == "Cancel" {
					s.focusList()
					return
				}
				runAction(verb, fn)
			})
		s.pages.AddPage("kvmconfirm", modal, true, true)
	}

	list.AddItem("Reset", "press reset (confirms)", 0, func() { confirmThenRun("reset", prov.Reset) })
	list.AddItem("Power", "short power press (confirms)", 0, func() { confirmThenRun("power", prov.Power) })
	list.AddItem("Off", "long press / force off (confirms)", 0, func() { confirmThenRun("off", prov.Off) })
	list.AddItem("Open web UI", prov.WebURL(), 0, func() {
		url := prov.WebURL()
		closeMenu()
		if err := kvm.OpenURL(url); err != nil {
			s.modal("open browser: "+err.Error(), nil)
		}
	})
	list.AddItem("Status", "query reachability / power state", 0, func() {
		closeMenu()
		go func() {
			st, err := prov.Status(context.Background())
			s.app.QueueUpdateDraw(func() {
				if err != nil {
					s.modal("kvm status failed:\n\n"+err.Error(), nil)
				} else {
					s.modal("kvm status ("+kvmHost+"):\n\n"+st, nil)
				}
			})
		}()
	})

	list.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEsc {
			closeMenu()
			return nil
		}
		return e
	})

	s.pages.AddPage("kvm", centered(list, 64, 13), true, true)
	s.app.SetFocus(list)
}
