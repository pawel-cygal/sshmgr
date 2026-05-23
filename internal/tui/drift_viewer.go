// Two-level drift viewer for `exec --diff`. Level 1 is a list of output
// groups (the largest is the baseline by default, marked [baseline]; 'b'
// on a row sets a new baseline). Level 2 opens a colored unified diff
// between the selected group and the current baseline.

package tui

import (
	"fmt"
	"os"
	"strings"

	"sshmgr/internal/exec"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ShowDriftReport opens the two-level drift viewer.
//
// Overview keys: Enter open diff · b set baseline · j/k move · q back to UI
// · x exit to shell.
// Detail keys: j/k scroll · g/G top/bottom · n/p next/prev group · w save
// the current diff to a timestamped file · q/Esc back to overview · x exit.
func ShowDriftReport(title, cmd string, groups []exec.OutputGroup) ExecChoice {
	applyTheme(nil)
	app := tview.NewApplication()
	baseline := defaultBaselineIndex(groups)
	cursor := 0
	choice := ExecBackToUI

	pages := tview.NewPages()

	groupLabel := func(g exec.OutputGroup, i int) string {
		return fmt.Sprintf("group #%d · %d host(s) · %s", i+1, len(g.Aliases), g.Label)
	}

	list := tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(" " + title + " ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

	detail := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false).
		SetScrollable(true)
	detail.SetBorder(true).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

	overviewFooter := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	detailFooter := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	overviewFooter.SetText(driftOverviewFooter(cmd, len(groups)))

	// renderDetail must be addressable before renderList captures it.
	var renderDetail func()
	renderDetail = func() {
		base := groups[baseline]
		sel := groups[cursor]
		if cursor == baseline {
			body := theme.Current.AccentBTag() + "(this is the baseline group)[-]\n\n" +
				theme.Current.DimTag() + groupLabel(base, baseline) + "[-]\n\n" +
				tview.Escape(base.Output)
			detail.SetText(body)
			detail.SetTitle(" " + groupLabel(sel, cursor) + " · [baseline] ")
		} else {
			body := unifiedDiff(
				splitLines(base.Output), splitLines(sel.Output),
				"baseline · "+groupLabel(base, baseline),
				groupLabel(sel, cursor),
				3, true,
			)
			detail.SetText(body)
			detail.SetTitle(" " + groupLabel(sel, cursor) + " vs baseline ")
		}
		detail.ScrollToBeginning()
		detailFooter.SetText(driftDetailFooter())
	}

	renderList := func() {
		list.Clear()
		for i, g := range groups {
			main := driftRowLine(g, i, baseline, groupLabel)
			sec := strings.Join(g.Aliases, ", ")
			if len(sec) > 80 {
				sec = sec[:77] + "..."
			}
			i := i
			list.AddItem(main, sec, 0, func() {
				cursor = i
				renderDetail()
				pages.SwitchToPage("detail")
				app.SetFocus(detail)
			})
		}
		if cursor >= 0 && cursor < len(groups) {
			list.SetCurrentItem(cursor)
		}
	}

	list.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		switch e.Rune() {
		case 'q':
			choice = ExecBackToUI
			app.Stop()
			return nil
		case 'x':
			choice = ExecToShell
			app.Stop()
			return nil
		case 'b':
			i := list.GetCurrentItem()
			if i >= 0 && i < len(groups) {
				baseline = i
				renderList()
			}
			return nil
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		}
		if e.Key() == tcell.KeyEsc {
			choice = ExecBackToUI
			app.Stop()
			return nil
		}
		return e
	})

	backToOverview := func() {
		renderList()
		pages.SwitchToPage("overview")
		app.SetFocus(list)
	}

	detail.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		switch e.Rune() {
		case 'q':
			backToOverview()
			return nil
		case 'x':
			choice = ExecToShell
			app.Stop()
			return nil
		case 'n':
			cursor = (cursor + 1) % len(groups)
			renderDetail()
			return nil
		case 'p':
			cursor = (cursor - 1 + len(groups)) % len(groups)
			renderDetail()
			return nil
		case 'w':
			var plain string
			if cursor == baseline {
				plain = "(this is the baseline group)\n\n" +
					groupLabel(groups[baseline], baseline) + "\n\n" +
					groups[baseline].Output + "\n"
			} else {
				plain = unifiedDiff(
					splitLines(groups[baseline].Output), splitLines(groups[cursor].Output),
					"baseline · "+groupLabel(groups[baseline], baseline),
					groupLabel(groups[cursor], cursor),
					3, false,
				)
			}
			if path, err := saveDiffOutput(plain); err != nil {
				detailFooter.SetText(theme.Current.ErrorTag() + "save failed: " + err.Error() + "[-]")
			} else {
				detailFooter.SetText(theme.Current.AccentBTag() + "saved -> " + path + "[-]")
			}
			return nil
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		case 'g':
			detail.ScrollToBeginning()
			return nil
		case 'G':
			detail.ScrollToEnd()
			return nil
		}
		if e.Key() == tcell.KeyEsc {
			backToOverview()
			return nil
		}
		return e
	})

	overviewLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(list, 0, 1, true).
		AddItem(overviewFooter, 1, 0, false)
	detailLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(detail, 0, 1, true).
		AddItem(detailFooter, 1, 0, false)
	pages.AddPage("overview", overviewLayout, true, true)
	pages.AddPage("detail", detailLayout, true, false)

	renderList()

	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "drift viewer: %v\n", err)
	}
	return choice
}

// driftRowLine renders one overview row: the `[baseline]` prefix on the
// chosen baseline, then the group label, then a trailing ⚠ marker for the
// drift / failed groups (matching the CLI renderDrift output).
func driftRowLine(g exec.OutputGroup, i, baseline int, label func(exec.OutputGroup, int) string) string {
	prefix := ""
	if i == baseline {
		prefix = "[baseline] "
	}
	suffix := ""
	switch {
	case g.Failed:
		suffix = "  ⚠ failed"
	case i != baseline:
		suffix = "  ⚠ drift"
	}
	return prefix + label(g, i) + suffix
}

func driftOverviewFooter(cmd string, n int) string {
	summary := fmt.Sprintf("%d distinct group(s)  ·  cmd: %s", n, cmd)
	return summary + "    " +
		pill("Enter", "open") + " " + pill("b", "baseline") + " " +
		pill("j/k", "move") + " " + pill("q", "back") + " " + pill("x", "shell")
}

func driftDetailFooter() string {
	return pill("n/p", "group") + " " + pill("j/k", "scroll") + " " +
		pill("g/G", "top/bot") + " " + pill("w", "save") + " " +
		pill("q", "back") + " " + pill("x", "shell")
}
