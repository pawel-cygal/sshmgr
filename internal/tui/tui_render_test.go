package tui

import (
	"testing"

	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
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
	// the header. Collect the distinct foregrounds on that line, ignoring
	// blanks (default style) and the leftmost/rightmost columns, which are
	// the table's box-drawing border, not cell content.
	seen := map[tcell.Color]bool{}
	const line = 2
	for x := 1; x < w-1; x++ {
		c := cells[line*w+x]
		if len(c.Runes) == 0 || c.Runes[0] == ' ' {
			continue
		}
		fg, _, _ := c.Style.Decompose()
		seen[fg] = true
	}
	if len(seen) < 2 {
		t.Errorf("host row uses %d distinct foreground colours, want at least 2 "+
			"(alias and host must differ) — colours seen: %v", len(seen), seen)
	}
}

func TestHeaderRowIsNotSelectable(t *testing.T) {
	s := newTestState(t, fixture())
	s.refreshList("")

	// Select the first host, then try to move above it.
	selectRow(s, 0)
	s.table.Select(0, 0)
	row, _ := s.table.GetSelection()
	if got := s.aliasAtRow(row); got != "" && row == 0 {
		t.Errorf("header row resolved to alias %q, want empty", got)
	}
}
