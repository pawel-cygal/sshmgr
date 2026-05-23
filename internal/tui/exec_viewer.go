package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sshmgr/internal/exec"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ExecChoice is what the user picked at the end of an exec viewer session.
type ExecChoice int

const (
	ExecBackToUI ExecChoice = iota // user pressed q — return to host list
	ExecToShell                    // user pressed x — drop to the shell
)

// resultFilter selects which hosts the rich exec viewer shows.
type resultFilter int

const (
	filterAll resultFilter = iota
	filterOK
	filterFailed
)

func (f resultFilter) label() string {
	switch f {
	case filterOK:
		return "ok"
	case filterFailed:
		return "failed"
	default:
		return "all"
	}
}

// ShowHostResults shows per-host exec output: scrollable, filterable
// (all / ok / failed), with save-to-file and host-to-host jumps. Returns
// the user's exit choice.
func ShowHostResults(title string, results []exec.Result) ExecChoice {
	applyTheme(nil)
	app := tview.NewApplication()

	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false).
		SetScrollable(true)
	tv.SetBorder(true).
		SetTitle(" " + title + " ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

	footer := tview.NewTextView().SetDynamicColors(true).SetWrap(false)

	filter := filterAll
	curBlock := 0
	var blockLines []int

	render := func() {
		body, summary, lines := formatResults(results, filter)
		blockLines = lines
		curBlock = 0
		tv.SetText(body)
		tv.ScrollToBeginning()
		footer.SetText(execFooter(summary, filter))
	}
	render()

	choice := ExecBackToUI
	tv.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		switch e.Rune() {
		case 'q':
			choice = ExecBackToUI
			app.Stop()
			return nil
		case 'x':
			choice = ExecToShell
			app.Stop()
			return nil
		case 'o':
			filter = (filter + 1) % 3
			render()
			return nil
		case 'w':
			if path, err := saveExecOutput(results); err != nil {
				footer.SetText(theme.Current.ErrorTag() + "save failed: " + err.Error() + "[-]")
			} else {
				footer.SetText(theme.Current.AccentBTag() + "saved -> " + path + "[-]")
			}
			return nil
		case 'n':
			if len(blockLines) > 0 {
				curBlock = (curBlock + 1) % len(blockLines)
				tv.ScrollTo(blockLines[curBlock], 0)
			}
			return nil
		case 'p':
			if len(blockLines) > 0 {
				curBlock = (curBlock - 1 + len(blockLines)) % len(blockLines)
				tv.ScrollTo(blockLines[curBlock], 0)
			}
			return nil
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		case 'g':
			tv.ScrollToBeginning()
			curBlock = 0
			return nil
		case 'G':
			tv.ScrollToEnd()
			return nil
		}
		if e.Key() == tcell.KeyEsc {
			choice = ExecBackToUI
			app.Stop()
			return nil
		}
		return e
	})

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tv, 0, 1, true).
		AddItem(footer, 1, 0, false)
	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "exec viewer: %v\n", err)
	}
	return choice
}

// formatResults renders results filtered by f, returning the body, a
// summary line and the start line of each rendered host block (for n/p
// host jumps). The summary always counts the full result set.
func formatResults(results []exec.Result, f resultFilter) (body, summary string, blockLines []int) {
	ok, fail := 0, 0
	for _, r := range results {
		if r.ExitCode == 0 {
			ok++
		} else {
			fail++
		}
	}
	summary = fmt.Sprintf("%d ok  %d failed", ok, fail)

	primary := theme.Current.PrimaryTag()
	dim := theme.Current.DimTag()
	errc := theme.Current.ErrorTag()

	var b strings.Builder
	line := 0
	for _, r := range results {
		failed := r.ExitCode != 0
		if (f == filterOK && failed) || (f == filterFailed && !failed) {
			continue
		}
		blockLines = append(blockLines, line)
		mark := primary + "OK[-]"
		if failed {
			mark = errc + "FAIL[-]"
		}
		fmt.Fprintf(&b, "%s===[-] %s%s[-]  %s  %sexit %d  %s%s[-]\n",
			primary, primary, tview.Escape(r.Alias), mark, dim, r.ExitCode,
			dim, r.Duration.Round(time.Millisecond))
		line++
		if r.Err != nil {
			fmt.Fprintf(&b, "  %serror: %v[-]\n", errc, r.Err)
			line++
		}
		out := strings.TrimRight(r.Output, "\n")
		if out != "" {
			for _, l := range strings.Split(out, "\n") {
				fmt.Fprintf(&b, "  %s\n", tview.Escape(l))
				line++
			}
		} else if r.Err == nil {
			fmt.Fprintf(&b, "  %s(no output)[-]\n", dim)
			line++
		}
		b.WriteString("\n")
		line++
	}
	if len(blockLines) == 0 {
		b.WriteString("  " + dim + "(no hosts match this filter)[-]\n")
	}
	return b.String(), summary, blockLines
}

// execFooter builds the rich viewer's footer line.
func execFooter(summary string, f resultFilter) string {
	return strings.TrimSpace(summary) + "    " +
		pill("o", "filter:"+f.label()) + " " + pill("n/p", "host") + " " +
		pill("j/k", "scroll") + " " + pill("w", "save") + " " +
		pill("q", "back") + " " + pill("x", "shell")
}

// saveExecOutput writes a plain-text dump of every host's output to a
// timestamped file in the current directory; returns its absolute path.
// A name clash (two saves in the same second) is resolved with a counter
// suffix and an O_EXCL create, so an earlier export is never clobbered.
func saveExecOutput(results []exec.Result) (string, error) {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "=== %s  exit %d  %s ===\n",
			r.Alias, r.ExitCode, r.Duration.Round(time.Millisecond))
		if r.Err != nil {
			fmt.Fprintf(&b, "error: %v\n", r.Err)
		}
		if out := strings.TrimRight(r.Output, "\n"); out != "" {
			b.WriteString(out + "\n")
		}
		b.WriteString("\n")
	}

	base := "sshmgr-exec-" + time.Now().Format("20060102-150405")
	for i := 1; i <= 1000; i++ {
		name := base + ".txt"
		if i > 1 {
			name = fmt.Sprintf("%s-%d.txt", base, i)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.WriteString(b.String())
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
		if abs, aerr := filepath.Abs(name); aerr == nil {
			return abs, nil
		}
		return name, nil
	}
	return "", fmt.Errorf("could not find a free filename for %s", base)
}
