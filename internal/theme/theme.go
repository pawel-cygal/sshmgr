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
	AccentB    tcell.Color
	Text       tcell.Color // ordinary text (host names, file names)
	Dim        tcell.Color // metadata (sizes, mtimes, secondary chips)
	Inverse    tcell.Color // text on highlight (almost always near-black)
	Selection  tcell.Color // selection background (usually = Primary)
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
func (p Palette) PrimaryTag() string  { return "[" + colorName(p.Primary) + "]" }
func (p Palette) AccentBTag() string  { return "[" + colorName(p.AccentB) + "]" }
func (p Palette) DimTag() string      { return "[" + colorName(p.Dim) + "]" }
func (p Palette) HelpKeyTag() string  { return "[" + colorName(p.HelpKey) + "]" }
func (p Palette) WarningTag() string  { return "[" + colorName(p.Warning) + "]" }
func (p Palette) ErrorTag() string    { return "[" + colorName(p.Error) + "]" }

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
	FocusBdr:   tcell.NewRGBColor(0, 240, 255),
	UnfocusBdr: tcell.NewRGBColor(80, 60, 110),
	FieldBg:    tcell.NewRGBColor(25, 0, 45),
	FieldText:  tcell.NewRGBColor(0, 240, 255),
	Warning:    tcell.NewRGBColor(255, 220, 70),
	Error:      tcell.NewRGBColor(255, 60, 90),
	HelpKey:    tcell.NewRGBColor(0, 240, 255),
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
	case "default", "system", "":
		Current = Default
	default:
		Current = Default
	}
}

// Names lists the available theme identifiers.
func Names() []string {
	return []string{"default", "hacker", "cyberpunk"}
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
