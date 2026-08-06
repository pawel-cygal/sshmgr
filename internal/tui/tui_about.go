package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/systeampl/sshmgr/internal/banner"
	"github.com/systeampl/sshmgr/internal/logo"
	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// aboutRows returns the label/value pairs shown under the wordmark. Pure, so
// the content can be tested without a screen.
func aboutRows(version, commit, configPath string, hosts int) [][2]string {
	ver := version
	// `go install module@version` cannot inject linker flags, so commit can
	// legitimately be "unknown" -- show the version alone rather than a
	// parenthesised placeholder.
	if commit != "" && commit != "unknown" {
		if len(commit) > 7 {
			commit = commit[:7]
		}
		ver = fmt.Sprintf("%s (%s)", version, commit)
	}
	return [][2]string{
		{"version", ver},
		{"config", configPath},
		{"hosts", strconv.Itoa(hosts)},
		{"license", "MIT"},
		{"source", "github.com/systeampl/sshmgr"},
	}
}

// wordmarkWidth is the width of the block-letter wordmark in banner.ASCII --
// the widest line with no trailing face/tagline art (line 4, "███████║...").
// Slicing every line to this width strips the face and tagline reliably;
// pattern-matching against the art itself is fragile because the face and
// tagline start at different columns on different lines.
const wordmarkWidth = 52

// aboutWidth and aboutHeight size the overlay. With the logo shown, the
// layout is side by side: left margin + logo + gap + wordmark + right
// margin. logo.Viable already requires a terminal at least 100 columns
// wide, so a 99-column overlay is safe by construction -- the two
// thresholds are consistent on purpose, not two unrelated magic numbers.
// aboutWidthNoLogo is the wordmark plus margins, used when the logo is not
// drawn.
const (
	aboutWidth       = 2 + logo.Width + 3 + wordmarkWidth + 2 // = 99
	aboutWidthNoLogo = 58
	aboutHeight      = 24
)

// newAboutBox draws the logo on the left and the wordmark plus build
// information on the right. It draws cell by cell rather than composing
// widgets because a half-block image is exactly what tview's higher-level
// primitives cannot express.
func newAboutBox(rows [][2]string, withLogo bool) *tview.Box {
	box := tview.NewBox()
	box.SetBorder(true).
		SetTitle(" about ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	box.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		t := theme.Current
		inX, inY := x+2, y+1

		textX := inX
		if withLogo {
			bg := t.PanelBg
			if bg == tcell.ColorDefault {
				// Compositing needs a concrete colour and the terminal's own
				// background cannot be queried. Near-black is the safe
				// assumption on the dark terminals every palette targets.
				bg = tcell.NewRGBColor(0, 0, 0)
			}
			if cells, err := logo.Cells(logo.Width, logo.Height, bg); err == nil {
				for row := 0; row < logo.Height; row++ {
					for col := 0; col < logo.Width; col++ {
						c := cells[row*logo.Width+col]
						screen.SetContent(inX+col, inY+row, c.Ch, nil,
							tcell.StyleDefault.Foreground(c.Fg).Background(c.Bg))
					}
				}
				textX = inX + logo.Width + 3
			}
		}

		// wordmark: the ASCII art without its trailing face and tagline,
		// which the logo beside it already says better. Every line is cut
		// to wordmarkWidth runes -- the width of the one line (the block
		// letters' bottom row) that carries no trailing art -- rather than
		// pattern-matched, since the face and tagline start at different
		// columns on different lines.
		wy := inY + 1
		for i, line := range strings.Split(banner.ASCII, "\n") {
			r := []rune(line)
			if len(r) > wordmarkWidth {
				r = r[:wordmarkWidth]
			}
			drawRunes(screen, textX, wy+i, strings.TrimRight(string(r), " "),
				tcell.StyleDefault.Foreground(t.Primary))
		}

		by := wy + 7
		drawRunes(screen, textX, by, "by ", tcell.StyleDefault.Foreground(t.Dim))
		drawRunes(screen, textX+3, by, "SysTeam", tcell.StyleDefault.Foreground(t.AccentB))
		drawRunes(screen, textX+10, by, " · SysTeam.pl", tcell.StyleDefault.Foreground(t.Dim))

		ry := by + 2
		for i, r := range rows {
			drawRunes(screen, textX, ry+i, fmt.Sprintf("%-9s", r[0]),
				tcell.StyleDefault.Foreground(t.Dim))
			drawRunes(screen, textX+9, ry+i, r[1],
				tcell.StyleDefault.Foreground(t.Text))
		}

		drawRunes(screen, inX, y+height-2, "Esc / q  close",
			tcell.StyleDefault.Foreground(t.Dim))

		return x, y, width, height
	})
	return box
}

// drawRunes writes s starting at (x, y) in the given style.
func drawRunes(screen tcell.Screen, x, y int, s string, st tcell.Style) {
	for i, r := range []rune(s) {
		screen.SetContent(x+i, y, r, nil, st)
	}
}

// showAbout opens the about overlay. The logo is drawn only when the
// terminal can render it; otherwise the wordmark takes the whole width and
// the screen still works.
func (s *uiState) showAbout() {
	rows := aboutRows(buildVersion, buildCommit, shortenHome(s.configPath), len(s.cfg.Hosts))
	withLogo := logo.Viable(s.termColors, s.termWidth)

	box := newAboutBox(rows, withLogo)
	close := func() {
		s.pages.RemovePage("about")
		s.focusList()
	}
	box.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEsc || e.Rune() == 'q' || e.Key() == tcell.KeyF1 {
			close()
			return nil
		}
		return nil
	})

	w := aboutWidth
	if !withLogo {
		w = aboutWidthNoLogo
	}
	s.pages.AddPage("about", centered(box, w, aboutHeight), true, true)
	s.app.SetFocus(box)
}
