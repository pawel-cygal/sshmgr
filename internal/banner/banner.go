// Package banner holds the sshmgr banner shown at the top of the TUI and in
// CLI help output. It comes in two variants: the six-row ASCII art, and a
// one-row line that trades the art for the context a running session
// actually needs.
package banner

import (
	"fmt"
	"strings"

	"github.com/systeampl/sshmgr/internal/theme"
)

// ASCII is the multi-line banner. Its widest line is 71 columns including
// the wolf head on the right. Designed to fit a standard 80-column terminal.
const ASCII = `███████╗███████╗██╗  ██╗███╗   ███╗ ██████╗ ██████╗      /\___/\
██╔════╝██╔════╝██║  ██║████╗ ████║██╔════╝ ██╔══██╗    ( o . o )
███████╗███████╗███████║██╔████╔██║██║  ███╗██████╔╝     \  v  /
╚════██║╚════██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗      \___/
███████║███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝     modern SSH mgr`

// asciiHeight is the row count of ASCII. Kept in sync by a test.
const asciiHeight = 6

// asciiWidth is the column budget the ASCII art needs — the width of its
// widest line, measured in runes.
const asciiWidth = 71

// fullMinHeight is the terminal height below which the six-row banner costs
// more rows than it is worth. Below this the compact line is used instead.
const fullMinHeight = 30

// Variant selects which form of the banner to draw.
type Variant int

const (
	// Full is the six-row ASCII art.
	Full Variant = iota
	// Compact is the one-row context line.
	Compact
)

// Context is what the compact banner shows in place of the art.
type Context struct {
	Version    string
	ConfigPath string
	Theme      string
	Hosts      int
	Forwards   int
}

// ChooseVariant picks the banner form for a terminal of the given size. The
// art needs both vertical room to spare and 80 columns to render without
// wrapping; anything less gets the compact line.
func ChooseVariant(termHeight, termWidth int) Variant {
	if termHeight >= fullMinHeight && termWidth >= asciiWidth {
		return Full
	}
	return Compact
}

// Height returns the number of rows the given variant occupies.
func Height(v Variant) int {
	if v == Full {
		return asciiHeight
	}
	return 1
}

// Render returns the banner as a colour-tagged string for a TextView.
func Render(v Variant, ctx Context) string {
	t := theme.Current
	if v == Full {
		return t.PrimaryTag() + ASCII + "[-]"
	}

	sep := t.DimTag() + " · [-]"
	var parts []string
	parts = append(parts, fmt.Sprintf("%ssshmgr %s[-] %sby[-] %sSysTeam[-]",
		t.PrimaryTag(), ctx.Version, t.DimTag(), t.AccentBTag()))
	if ctx.ConfigPath != "" {
		parts = append(parts, t.DimTag()+ctx.ConfigPath+"[-]")
	}
	if ctx.Theme != "" {
		parts = append(parts, t.AccentBTag()+ctx.Theme+"[-]")
	}
	parts = append(parts, fmt.Sprintf("%s%d hosts[-]", t.DimTag(), ctx.Hosts))
	if ctx.Forwards > 0 {
		parts = append(parts, fmt.Sprintf("%s%d fwd[-]", t.SuccessTag(), ctx.Forwards))
	}
	return " " + strings.Join(parts, sep)
}
