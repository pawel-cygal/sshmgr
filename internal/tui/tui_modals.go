package tui

import (

	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func (s *uiState) inputPrompt(label, def string, onSubmit func(string)) {
	input := tview.NewInputField().
		SetLabel(label + " ").
		SetText(def).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetLabelColor(theme.Current.Primary)
	form := tview.NewForm().
		AddFormItem(input).
		AddButton("OK", func() {
			s.pages.RemovePage("input")
			if s.mode == modeTree {
				s.app.SetFocus(s.tree)
			} else {
				s.app.SetFocus(s.list)
			}
			onSubmit(input.GetText())
		}).
		AddButton("Cancel", func() {
			s.pages.RemovePage("input")
			if s.mode == modeTree {
				s.app.SetFocus(s.tree)
			} else {
				s.app.SetFocus(s.list)
			}
		}).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).SetBorderColor(theme.Current.Primary).SetTitle(" " + label + " ").SetTitleColor(theme.Current.Primary)
	s.pages.AddPage("input", centered(form, 60, 7), true, true)
	s.app.SetFocus(input)
}

// showHelpOverlay pops a scrollable modal with the full keymap (`?` key).
func (s *uiState) showHelpOverlay() {
	tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	tv.SetText(fullHelpText())
	tv.SetBorder(true).
		SetTitle(" keys — Esc to close ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)
	closeOverlay := func() {
		s.pages.RemovePage("help-overlay")
		s.focusList()
	}
	tv.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEsc || e.Rune() == 'q' || e.Rune() == '?' {
			closeOverlay()
			return nil
		}
		switch e.Rune() {
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		}
		return e
	})
	s.pages.AddPage("help-overlay", centered(tv, 62, 30), true, true)
	s.app.SetFocus(tv)
}

// showResolvedConfig pops a modal tracing where each inherited field of the
// host comes from — the host itself or a specific group (`i` key).
func (s *uiState) modal(text string, onClose func()) {
	m := tview.NewModal().
		SetText(text).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			s.pages.RemovePage("info")
			if onClose != nil {
				onClose()
			} else {
				s.focusList()
			}
		})
	s.pages.AddPage("info", m, true, true)
}

