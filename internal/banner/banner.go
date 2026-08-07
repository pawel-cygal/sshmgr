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

// ChooseVariant picks the banner form for a terminal of the given size.
//
// The compact line is the default at every size, because it carries
// information the art does not -- config path, active theme, host count,
// live forward count -- and gives the host list five more rows. Basing the
// choice on available height instead made the redesign invisible to exactly
// the people with the largest terminals, who saw the same six-row art as
// before.
//
// wantFull opts back into the art. It still needs the vertical room and the
// columns to render without wrapping, so an oversized request on a small
// terminal falls back rather than clipping.
func ChooseVariant(termHeight, termWidth int, wantFull bool) Variant {
	if wantFull && termHeight >= fullMinHeight && termWidth >= asciiWidth {
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

// Render returns the banner as a colour-tagged string for a TextView, sized
// to fit width columns.
//
// The compact line has to survive a long version label and a long config
// path together — the real-world pairing of a release label and
// ~/.config/sshmgr/config.yaml runs past 110 columns, which silently pushed
// the host and forward counts off the right edge. So it degrades: the parts
// are dropped in order of how little they change during a session, and the
// live counts are what survive.
func Render(v Variant, ctx Context, width int) string {
	t := theme.Current
	if v == Full {
		return t.PrimaryTag() + ASCII + "[-]"
	}
	if width <= 0 {
		width = asciiWidth
	}

	// Richest first. The first layout that fits wins; the last is the floor
	// and is emitted even if it does not fit, since something must render.
	for _, layout := range []struct{ version, path, theme bool }{
		{version: true, path: true, theme: true},
		{version: true, path: true, theme: false},
		{version: true, path: false, theme: true},
		{version: true, path: false, theme: false},
		{version: false, path: false, theme: false},
	} {
		plain, tagged := compactParts(ctx, layout.version, layout.path, layout.theme)
		if len([]rune(plain)) <= width || !layout.version {
			return tagged
		}
	}
	return "" // unreachable: the final layout always returns
}

// compactParts builds the compact line twice — once as plain text for
// measuring, once with colour tags for rendering — so the two cannot drift.
func compactParts(ctx Context, withVersion, withPath, withTheme bool) (plain, tagged string) {
	t := theme.Current
	var plainParts, taggedParts []string

	add := func(p, g string) {
		plainParts = append(plainParts, p)
		taggedParts = append(taggedParts, g)
	}

	if withVersion {
		add(fmt.Sprintf("sshmgr %s by SysTeam", ctx.Version),
			fmt.Sprintf("%ssshmgr %s[-] %sby[-] %sSysTeam[-]",
				t.PrimaryTag(), ctx.Version, t.DimTag(), t.AccentBTag()))
	} else {
		add("sshmgr", t.PrimaryTag()+"sshmgr[-]")
	}
	if withPath && ctx.ConfigPath != "" {
		add(ctx.ConfigPath, t.DimTag()+ctx.ConfigPath+"[-]")
	}
	if withTheme && ctx.Theme != "" {
		add(ctx.Theme, t.AccentBTag()+ctx.Theme+"[-]")
	}
	add(fmt.Sprintf("%d hosts", ctx.Hosts),
		fmt.Sprintf("%s%d hosts[-]", t.DimTag(), ctx.Hosts))
	if ctx.Forwards > 0 {
		add(fmt.Sprintf("%d fwd", ctx.Forwards),
			fmt.Sprintf("%s%d fwd[-]", t.SuccessTag(), ctx.Forwards))
	}

	sep := " · "
	taggedSep := t.DimTag() + " · [-]"
	return " " + strings.Join(plainParts, sep), " " + strings.Join(taggedParts, taggedSep)
}
