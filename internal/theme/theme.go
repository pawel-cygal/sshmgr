// Package theme centralises every color used by the TUI so a single name —
// e.g. "hacker" or "cyberpunk" — recolours the whole app coherently.
package theme

import (
	"fmt"
	"os"
	"strings"

	"github.com/gdamore/tcell/v2"
)

// Palette holds every semantic color slot used by the TUI. New widgets pick
// their colors by role (Primary, Secondary, …) rather than by literal value.
type Palette struct {
	Name    string
	Primary tcell.Color // borders, titles, group names, header cells, accents
	// AccentB is a secondary accent used to distinguish things that need to
	// stand out against Primary (e.g., active panel vs inactive in the file
	// manager, secondary highlights).
	AccentB   tcell.Color
	Text      tcell.Color // ordinary text (host names, file names)
	Dim       tcell.Color // metadata (sizes, mtimes, secondary chips)
	Inverse   tcell.Color // text on highlight (almost always near-black)
	Selection tcell.Color // selection background (usually = Primary)
	// SelText is the foreground on a selected row. Before this slot existed
	// the foreground was pinned to Inverse (near-black), which is why every
	// palette had to pick a very light Selection background. With SelText
	// free, a palette can pair a subtle tint with its own readable
	// foreground.
	SelText tcell.Color
	// Success marks a reachable host / an ok result. Distinct from Primary,
	// which is structural (borders, titles).
	Success tcell.Color
	// PanelBg is the panel background. Left as tcell.ColorDefault by
	// palettes that want the terminal's own background (and therefore its
	// transparency) to show through.
	PanelBg    tcell.Color
	FocusBdr   tcell.Color // border color for focused/active widget
	UnfocusBdr tcell.Color // border color for unfocused widget
	FieldBg    tcell.Color // input field / form field background
	FieldText  tcell.Color // input field text
	Warning    tcell.Color // info flashes
	Error      tcell.Color // error flashes
	HelpKey    tcell.Color // keyboard shortcut labels in help line
}

// PrimaryTag returns the tview color-tag form of Primary (e.g. "[aqua]")
// suitable for inline use in TextView strings.
func (p Palette) PrimaryTag() string { return "[" + colorName(p.Primary) + "]" }
func (p Palette) AccentBTag() string { return "[" + colorName(p.AccentB) + "]" }
func (p Palette) DimTag() string     { return "[" + colorName(p.Dim) + "]" }
func (p Palette) HelpKeyTag() string { return "[" + colorName(p.HelpKey) + "]" }
func (p Palette) WarningTag() string { return "[" + colorName(p.Warning) + "]" }
func (p Palette) ErrorTag() string   { return "[" + colorName(p.Error) + "]" }
func (p Palette) SuccessTag() string { return "[" + colorName(p.Success) + "]" }

// ColorTag returns the bare tview color-tag name for c (without brackets),
// e.g. "aqua" or "#00ff41". Wrap it yourself: "[" + ColorTag(c) + "]".
func ColorTag(c tcell.Color) string { return colorName(c) }

// colorName converts a tcell.Color to a tview color-tag string. For named
// colors it uses the lowercase name; for RGB it falls back to hex.
func colorName(c tcell.Color) string {
	switch c {
	case tcell.ColorAqua:
		return "aqua"
	case tcell.ColorWhite:
		return "white"
	case tcell.ColorGray:
		return "gray"
	case tcell.ColorYellow:
		return "yellow"
	case tcell.ColorRed:
		return "red"
	case tcell.ColorBlack:
		return "black"
	case tcell.ColorGreen:
		return "green"
	case tcell.ColorLime:
		return "lime"
	case tcell.ColorBlue:
		return "blue"
	case tcell.ColorFuchsia:
		return "fuchsia"
	}
	r, g, b := c.RGB()
	const hex = "0123456789abcdef"
	return string([]byte{
		'#',
		hex[r>>4&0xf], hex[r&0xf],
		hex[g>>4&0xf], hex[g&0xf],
		hex[b>>4&0xf], hex[b&0xf],
	})
}

// Default — original aqua-on-default-background palette.
// Selection is bright yellow with black text — that combo reads cleanly on
// both dark and light terminals and never collides with the theme's accents.
var Default = Palette{
	Name:       "default",
	Primary:    tcell.ColorAqua,
	AccentB:    tcell.ColorYellow,
	Text:       tcell.ColorWhite,
	Dim:        tcell.ColorGray,
	Inverse:    tcell.ColorBlack,
	Selection:  tcell.NewRGBColor(255, 215, 0), // bright yellow
	SelText:    tcell.ColorBlack,
	Success:    tcell.NewRGBColor(95, 215, 95),
	PanelBg:    tcell.ColorDefault,
	FocusBdr:   tcell.ColorAqua,
	UnfocusBdr: tcell.ColorGray,
	FieldBg:    tcell.ColorDarkSlateGray,
	FieldText:  tcell.ColorWhite,
	Warning:    tcell.ColorYellow,
	Error:      tcell.ColorRed,
	HelpKey:    tcell.ColorYellow,
}

// Hacker — matrix-style bright green on near-black. Selection deliberately
// breaks the green palette (yellow on black) so highlighted rows never
// disappear into the green-on-green background of the rest of the UI.
var Hacker = Palette{
	Name:       "hacker",
	Primary:    tcell.NewRGBColor(0, 255, 65),
	AccentB:    tcell.NewRGBColor(150, 255, 80),
	Text:       tcell.NewRGBColor(180, 255, 180),
	Dim:        tcell.NewRGBColor(60, 160, 60),
	Inverse:    tcell.ColorBlack,
	Selection:  tcell.NewRGBColor(255, 215, 0), // bright yellow
	SelText:    tcell.ColorBlack,
	Success:    tcell.NewRGBColor(0, 255, 65),
	PanelBg:    tcell.ColorDefault,
	FocusBdr:   tcell.NewRGBColor(0, 255, 65),
	UnfocusBdr: tcell.NewRGBColor(40, 100, 40),
	FieldBg:    tcell.NewRGBColor(0, 30, 10),
	FieldText:  tcell.NewRGBColor(0, 255, 65),
	Warning:    tcell.NewRGBColor(255, 200, 0),
	Error:      tcell.NewRGBColor(255, 70, 70),
	HelpKey:    tcell.NewRGBColor(150, 255, 80),
}

// Cyberpunk — neon magenta / cyan duo on dark. Selection is bright yellow
// so highlights pop against either a dark or a light terminal background
// (the neon magenta + black combo can fade into a white terminal background).
var Cyberpunk = Palette{
	Name:       "cyberpunk",
	Primary:    tcell.NewRGBColor(255, 60, 220), // magenta/pink (borders, titles)
	AccentB:    tcell.NewRGBColor(0, 240, 255),  // electric cyan (accents)
	Text:       tcell.NewRGBColor(240, 240, 250),
	Dim:        tcell.NewRGBColor(140, 130, 180),
	Inverse:    tcell.ColorBlack,
	Selection:  tcell.NewRGBColor(255, 220, 70), // bright yellow — highlight bg
	SelText:    tcell.ColorBlack,
	Success:    tcell.NewRGBColor(94, 240, 138),
	PanelBg:    tcell.ColorDefault,
	FocusBdr:   tcell.NewRGBColor(0, 240, 255),
	UnfocusBdr: tcell.NewRGBColor(80, 60, 110),
	FieldBg:    tcell.NewRGBColor(25, 0, 45),
	FieldText:  tcell.NewRGBColor(0, 240, 255),
	Warning:    tcell.NewRGBColor(255, 220, 70),
	Error:      tcell.NewRGBColor(255, 60, 90),
	HelpKey:    tcell.NewRGBColor(0, 240, 255),
}

// Catppuccin Mocha. Unlike the three palettes above, the new palettes use a
// subtle surface tint for Selection rather than a shouting yellow — the
// SelText slot makes that readable without pinning the foreground to black.
var Catppuccin = Palette{
	Name:       "catppuccin",
	Primary:    tcell.NewRGBColor(137, 180, 250),
	AccentB:    tcell.NewRGBColor(203, 166, 247),
	Text:       tcell.NewRGBColor(205, 214, 244),
	Dim:        tcell.NewRGBColor(127, 132, 156),
	Inverse:    tcell.NewRGBColor(30, 30, 46),
	Selection:  tcell.NewRGBColor(49, 50, 68),
	SelText:    tcell.NewRGBColor(245, 224, 220),
	Success:    tcell.NewRGBColor(166, 227, 161),
	FocusBdr:   tcell.NewRGBColor(137, 180, 250),
	UnfocusBdr: tcell.NewRGBColor(69, 71, 90),
	FieldBg:    tcell.NewRGBColor(49, 50, 68),
	FieldText:  tcell.NewRGBColor(205, 214, 244),
	Warning:    tcell.NewRGBColor(249, 226, 175),
	Error:      tcell.NewRGBColor(243, 139, 168),
	HelpKey:    tcell.NewRGBColor(148, 226, 213),
	PanelBg:    tcell.ColorDefault,
}

// Tokyo Night (storm-leaning dark).
var TokyoNight = Palette{
	Name:       "tokyonight",
	Primary:    tcell.NewRGBColor(122, 162, 247),
	AccentB:    tcell.NewRGBColor(187, 154, 247),
	Text:       tcell.NewRGBColor(192, 202, 245),
	Dim:        tcell.NewRGBColor(86, 95, 137),
	Inverse:    tcell.NewRGBColor(26, 27, 38),
	Selection:  tcell.NewRGBColor(41, 46, 66),
	SelText:    tcell.NewRGBColor(192, 202, 245),
	Success:    tcell.NewRGBColor(158, 206, 106),
	FocusBdr:   tcell.NewRGBColor(122, 162, 247),
	UnfocusBdr: tcell.NewRGBColor(47, 53, 73),
	FieldBg:    tcell.NewRGBColor(41, 46, 66),
	FieldText:  tcell.NewRGBColor(192, 202, 245),
	Warning:    tcell.NewRGBColor(224, 175, 104),
	Error:      tcell.NewRGBColor(247, 118, 142),
	HelpKey:    tcell.NewRGBColor(125, 207, 255),
	PanelBg:    tcell.ColorDefault,
}

// Nord.
var Nord = Palette{
	Name:       "nord",
	Primary:    tcell.NewRGBColor(136, 192, 208),
	AccentB:    tcell.NewRGBColor(180, 142, 173),
	Text:       tcell.NewRGBColor(229, 233, 240),
	Dim:        tcell.NewRGBColor(123, 136, 161),
	Inverse:    tcell.NewRGBColor(46, 52, 64),
	Selection:  tcell.NewRGBColor(59, 66, 82),
	SelText:    tcell.NewRGBColor(236, 239, 244),
	Success:    tcell.NewRGBColor(163, 190, 140),
	FocusBdr:   tcell.NewRGBColor(136, 192, 208),
	UnfocusBdr: tcell.NewRGBColor(67, 76, 94),
	FieldBg:    tcell.NewRGBColor(59, 66, 82),
	FieldText:  tcell.NewRGBColor(229, 233, 240),
	Warning:    tcell.NewRGBColor(235, 203, 139),
	Error:      tcell.NewRGBColor(191, 97, 106),
	HelpKey:    tcell.NewRGBColor(143, 188, 187),
	PanelBg:    tcell.ColorDefault,
}

// Rosé Pine (main).
var RosePine = Palette{
	Name:       "rosepine",
	Primary:    tcell.NewRGBColor(156, 207, 216),
	AccentB:    tcell.NewRGBColor(196, 167, 231),
	Text:       tcell.NewRGBColor(224, 222, 244),
	Dim:        tcell.NewRGBColor(110, 106, 134),
	Inverse:    tcell.NewRGBColor(25, 23, 36),
	Selection:  tcell.NewRGBColor(38, 35, 58),
	SelText:    tcell.NewRGBColor(224, 222, 244),
	Success:    tcell.NewRGBColor(62, 143, 168),
	FocusBdr:   tcell.NewRGBColor(156, 207, 216),
	UnfocusBdr: tcell.NewRGBColor(42, 39, 63),
	FieldBg:    tcell.NewRGBColor(38, 35, 58),
	FieldText:  tcell.NewRGBColor(224, 222, 244),
	Warning:    tcell.NewRGBColor(246, 193, 119),
	Error:      tcell.NewRGBColor(235, 111, 146),
	HelpKey:    tcell.NewRGBColor(235, 188, 186),
	PanelBg:    tcell.ColorDefault,
}

// Gruvbox (dark, medium contrast).
var Gruvbox = Palette{
	Name:       "gruvbox",
	Primary:    tcell.NewRGBColor(131, 165, 152),
	AccentB:    tcell.NewRGBColor(211, 134, 155),
	Text:       tcell.NewRGBColor(235, 219, 178),
	Dim:        tcell.NewRGBColor(146, 131, 116),
	Inverse:    tcell.NewRGBColor(40, 40, 40),
	Selection:  tcell.NewRGBColor(60, 56, 54),
	SelText:    tcell.NewRGBColor(251, 241, 199),
	Success:    tcell.NewRGBColor(184, 187, 38),
	FocusBdr:   tcell.NewRGBColor(131, 165, 152),
	UnfocusBdr: tcell.NewRGBColor(80, 73, 69),
	FieldBg:    tcell.NewRGBColor(60, 56, 54),
	FieldText:  tcell.NewRGBColor(235, 219, 178),
	Warning:    tcell.NewRGBColor(250, 189, 47),
	Error:      tcell.NewRGBColor(251, 73, 52),
	HelpKey:    tcell.NewRGBColor(142, 192, 124),
	PanelBg:    tcell.ColorDefault,
}

// Current is the active palette. Mutated by Set() at startup.
var Current = Default

// Set switches the active palette by name (case-insensitive). Unknown names
// fall back to Default.
func Set(name string) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "hacker", "matrix":
		Current = Hacker
	case "cyberpunk", "synthwave", "neon":
		Current = Cyberpunk
	case "catppuccin", "mocha":
		Current = Catppuccin
	case "tokyonight", "tokyo-night", "tokyo":
		Current = TokyoNight
	case "nord":
		Current = Nord
	case "rosepine", "rose-pine", "rose":
		Current = RosePine
	case "gruvbox":
		Current = Gruvbox
	case "default", "system", "":
		Current = Default
	default:
		Current = Default
	}
}

// Names lists the available theme identifiers, in the order they should be
// offered to a user: the original three first, then the added palettes.
func Names() []string {
	return []string{
		"default", "hacker", "cyberpunk",
		"catppuccin", "tokyonight", "nord", "rosepine", "gruvbox",
	}
}

// --- ANSI escape helpers for plain CLI output (scp/sftp REPL/status lines) ---

var colorEnabled = isStderrTTY()

func isStderrTTY() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ANSI returns the truecolor escape sequence for c, or "" when stderr isn't
// a TTY (so logs/pipes don't get garbage escapes).
func ANSI(c tcell.Color) string {
	if !colorEnabled {
		return ""
	}
	r, g, b := c.RGB()
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
}

// Reset returns the ANSI reset code, or "" when colors are off.
func Reset() string {
	if !colorEnabled {
		return ""
	}
	return "\x1b[0m"
}

// Wrap colors a single string with c and resets.
func Wrap(c tcell.Color, s string) string {
	return ANSI(c) + s + Reset()
}
