package logo

import (
	"testing"

	"github.com/gdamore/tcell/v2"
)

func TestCellsReturnsExactGrid(t *testing.T) {
	cells, err := Cells(Width, Height, tcell.NewRGBColor(30, 30, 46))
	if err != nil {
		t.Fatalf("Cells: %v", err)
	}
	if got, want := len(cells), Width*Height; got != want {
		t.Fatalf("Cells returned %d cells, want %d", got, want)
	}
	for i, c := range cells {
		if c.Ch != '▀' {
			t.Fatalf("cell %d has glyph %q, want ▀", i, c.Ch)
		}
	}
}

func TestCellsRejectsNonPositiveSize(t *testing.T) {
	for _, tc := range [][2]int{{0, 10}, {10, 0}, {-1, 5}} {
		if _, err := Cells(tc[0], tc[1], tcell.ColorBlack); err == nil {
			t.Errorf("Cells(%d, %d) returned no error", tc[0], tc[1])
		}
	}
}

// Fully transparent regions must resolve to the background colour passed in,
// not to black. The asset is a circle on transparency, so the extreme
// corners are guaranteed to be outside it.
func TestTransparentCornersCompositeOntoBackground(t *testing.T) {
	bg := tcell.NewRGBColor(30, 30, 46)
	cells, err := Cells(Width, Height, bg)
	if err != nil {
		t.Fatalf("Cells: %v", err)
	}
	corners := map[string]int{
		"top-left":     0,
		"top-right":    Width - 1,
		"bottom-left":  (Height - 1) * Width,
		"bottom-right": Height*Width - 1,
	}
	wr, wg, wb := bg.RGB()
	for name, idx := range corners {
		gr, gg, gb := cells[idx].Fg.RGB()
		if absDiff(gr, wr) > 2 || absDiff(gg, wg) > 2 || absDiff(gb, wb) > 2 {
			t.Errorf("%s corner fg = (%d,%d,%d), want background (%d,%d,%d)",
				name, gr, gg, gb, wr, wg, wb)
		}
	}
}

func absDiff(a, b int32) int32 {
	if a > b {
		return a - b
	}
	return b - a
}

// The centre of the logo is opaque artwork, so it must NOT equal the
// background. This is what proves the asset is actually being sampled
// rather than the whole grid resolving to the fallback colour.
func TestCentreIsNotBackground(t *testing.T) {
	bg := tcell.NewRGBColor(30, 30, 46)
	cells, err := Cells(Width, Height, bg)
	if err != nil {
		t.Fatalf("Cells: %v", err)
	}
	centre := cells[(Height/2)*Width+Width/2]
	wr, wg, wb := bg.RGB()
	gr, gg, gb := centre.Fg.RGB()
	if gr == wr && gg == wg && gb == wb {
		t.Errorf("centre cell equals the background; the asset is not being sampled")
	}
}

func TestViable(t *testing.T) {
	cases := []struct {
		colors, width int
		want          bool
	}{
		{1 << 24, 100, true},
		{256, 100, true},
		{16, 100, false},     // too few colours for the neon gradients
		{1 << 24, 99, false}, // too narrow
		{0, 100, false},
	}
	for _, tc := range cases {
		if got := Viable(tc.colors, tc.width); got != tc.want {
			t.Errorf("Viable(%d, %d) = %v, want %v", tc.colors, tc.width, got, tc.want)
		}
	}
}

func TestCellsIsCached(t *testing.T) {
	bg := tcell.ColorBlack
	a, err := Cells(Width, Height, bg)
	if err != nil {
		t.Fatalf("Cells: %v", err)
	}
	b, err := Cells(Width, Height, bg)
	if err != nil {
		t.Fatalf("Cells: %v", err)
	}
	if &a[0] != &b[0] {
		t.Errorf("repeated Cells calls with identical arguments should return the cached slice")
	}
}
