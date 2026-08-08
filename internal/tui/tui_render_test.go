package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// drawToSim renders the host table onto a simulation screen and returns the
// cell grid. This is the only test that needs a screen: it checks colour,
// which is invisible to every other kind of assertion.
func drawToSim(t *testing.T, s *uiState, width, height int) ([]tcell.SimCell, int, int) {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("init simulation screen: %v", err)
	}
	defer screen.Fini()
	screen.SetSize(width, height)

	s.table.SetRect(0, 0, width, height)
	s.table.Draw(screen)
	screen.Show()

	cells, w, h := screen.GetContents()
	return cells, w, h
}

// The defect this guards: tview.List could not colour cells independently, so
// alias and host rendered identically. If the Table is ever configured in a
// way that flattens that back to one colour, this fails.
func TestTableRowCarriesMoreThanOneColour(t *testing.T) {
	theme.Set("catppuccin")
	defer theme.Set("default")

	s := newTestState(t, fixture())
	s.refreshList("")

	// tview draws the selected row with one uniform SetSelectedStyle that
	// overrides every per-cell colour on that row. refreshList's first body
	// row is selected by default, so inspecting it as-is would make this
	// test pass even if every column shared the same colour — the "second
	// colour" would just be the selection highlight. Move the cursor off it
	// so the row under inspection renders with its own per-cell colours.
	selectRow(s, 1)

	cells, w, _ := drawToSim(t, s, 58, 12)

	// Row 2 of the screen is the first host row: row 0 is the border, row 1
	// the header. Verified by printing the rendered rune grid during
	// development ("┌ hosts (flat) ─…┐" / "│ ALIAS HOST TAGS LAST │" /
	// "│ ◌ alpha 10.0.0.1 web — │" for the fixture's first host, alpha) —
	// buildHostWidget's SetBorder(true) puts the box top at row 0.
	const line = 2

	// Reconstruct the line's text and per-column foreground so we can find
	// specific cells by content rather than by hard-coded column offsets,
	// which would drift if hostColAlias/hostColHost ever change.
	runes := make([]rune, w)
	fgAt := make([]tcell.Color, w)
	seen := map[tcell.Color]bool{}
	for x := 0; x < w; x++ {
		c := cells[line*w+x]
		if len(c.Runes) == 0 {
			runes[x] = ' '
		} else {
			runes[x] = c.Runes[0]
		}
		fg, _, _ := c.Style.Decompose()
		fgAt[x] = fg
		// Interior columns only (exclude the box-drawing border at x=0 and
		// x=w-1): a monochrome table would still show the border colour
		// plus the body colour and falsely look like 2 distinct colours.
		if x > 0 && x < w-1 && runes[x] != ' ' {
			seen[fg] = true
		}
	}
	lineText := string(runes)

	// The core assertion: alias and host must render in different colours.
	// A count of distinct colours on the row is not enough on its own — the
	// status-dot column (colMark) carries its own colour independently of
	// colAlias/colHost/colTags/colLast, so even if every *text* column were
	// collapsed to one colour, the row would still show 2 distinct
	// foregrounds (dot colour + text colour) and a bare count would miss
	// the regression. Locate the alias and host substrings by content and
	// compare their foregrounds directly.
	aliasIdx := strings.Index(lineText, "alpha")
	hostIdx := strings.Index(lineText, "10.0.0.1")
	if aliasIdx < 0 || hostIdx < 0 {
		t.Fatalf("could not locate alias/host text on rendered line %q (alias idx=%d, host idx=%d)",
			lineText, aliasIdx, hostIdx)
	}
	fgAlias := fgAt[aliasIdx]
	fgHost := fgAt[hostIdx]
	if fgAlias == fgHost {
		t.Errorf("alias and host render in the same colour %v; "+
			"the whole point of the Table migration is that they can differ", fgAlias)
	}

	// Keep the distinct-count check too, as a coarser guard against other
	// ways the row could go flat (e.g. every column, dot included).
	if len(seen) < 2 {
		t.Errorf("host row uses %d distinct foreground colours, want at least 2 "+
			"(alias and host must differ) — colours seen: %v", len(seen), seen)
	}
}

// TestUpFromFirstHostRowStaysOffTheHeader is the real form of what used to
// be TestHeaderRowIsNotSelectable, which called s.table.Select(0, 0)
// directly. That made row == 0 by construction and aliasAtRow(0) == "" by
// the row < 1 guard in aliasAtRow, regardless of any header-selectability
// bug -- the old assertion (got != "" && row == 0) could not fail in either
// direction and never sent a keystroke, so it exercised nothing.
//
// The real property is that pressing Up from the first host row must not
// move the cursor onto the header: drive it through the table's actual
// InputHandler, the same code path a real Up keypress takes.
func TestUpFromFirstHostRowStaysOffTheHeader(t *testing.T) {
	s := newTestState(t, fixture())
	s.refreshList("")
	selectRow(s, 0) // first host row (table row 1; row 0 is the header)

	// tview's InputHandler moves the cursor by scanning for the next
	// selectable cell in a loop that only terminates by finding one or by
	// reaching the scan boundary (see TestEmptyRefreshLeavesASelectableRow).
	// A regression here could in principle hang that scan, so drive it on a
	// goroutine and bound the wait instead of calling it inline.
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler := s.table.InputHandler()
		handler(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone), func(tview.Primitive) {})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Up from the first host row did not return -- InputHandler hung")
	}

	row, _ := s.table.GetSelection()
	if got := s.aliasAtRow(row); got == "" {
		t.Errorf("Up from the first host row landed on row %d with no alias (the header, or off the table); want to stay on a host row", row)
	}
}
