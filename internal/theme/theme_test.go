package theme

import (
	"math"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// relLuminance implements the WCAG 2.1 relative luminance formula.
func relLuminance(c tcell.Color) float64 {
	r, g, b := c.RGB()
	f := func(v int32) float64 {
		s := float64(v) / 255.0
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*f(r) + 0.7152*f(g) + 0.0722*f(b)
}

// contrastRatio is the WCAG 2.1 contrast ratio between two colours.
func contrastRatio(a, b tcell.Color) float64 {
	la, lb := relLuminance(a), relLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func TestNamesResolveToThemselves(t *testing.T) {
	defer Set("default")
	for _, name := range Names() {
		Set(name)
		if Current.Name != name {
			t.Errorf("Set(%q) selected palette %q, want %q", name, Current.Name, name)
		}
	}
}

func TestNamesIncludesNewPalettes(t *testing.T) {
	want := []string{"default", "hacker", "cyberpunk",
		"catppuccin", "tokyonight", "nord", "rosepine", "gruvbox"}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() returned %d entries, want %d: %v", len(got), len(want), got)
	}
	index := map[string]bool{}
	for _, n := range got {
		index[n] = true
	}
	for _, n := range want {
		if !index[n] {
			t.Errorf("Names() is missing %q", n)
		}
	}
}

// A colour left at its zero value is tcell.ColorDefault, which renders as
// the terminal default and silently loses the palette's intent. PanelBg is
// deliberately allowed to be ColorDefault so terminal transparency works.
func TestEveryColourSlotIsSetExceptPanelBg(t *testing.T) {
	defer Set("default")
	for _, name := range Names() {
		Set(name)
		p := Current
		slots := map[string]tcell.Color{
			"Primary": p.Primary, "AccentB": p.AccentB, "Text": p.Text,
			"Dim": p.Dim, "Inverse": p.Inverse, "Selection": p.Selection,
			"SelText": p.SelText, "Success": p.Success,
			"FocusBdr": p.FocusBdr, "UnfocusBdr": p.UnfocusBdr,
			"FieldBg": p.FieldBg, "FieldText": p.FieldText,
			"Warning": p.Warning, "Error": p.Error, "HelpKey": p.HelpKey,
		}
		for slot, c := range slots {
			if c == tcell.ColorDefault {
				t.Errorf("palette %q: slot %s is unset (ColorDefault)", name, slot)
			}
		}
	}
}

// The selected row must stay readable in every palette. 4.5 is the WCAG AA
// threshold for body text; a highlighted row that fails it is the exact
// defect that forced every palette to a shouting yellow selection.
//
// This asserts contrast between SelText and Selection — the same pair that
// every selection site in internal/tui actually paints on screen (e.g.
// tview's List.SetSelectedTextColor(theme.Current.SelText) alongside
// List.SetSelectedBackgroundColor(theme.Current.Selection), the pattern
// tui.go's SetSelectedTextColor call uses). Asserting Inverse/Selection
// here instead would be tautological: SelText was added specifically so
// the foreground could stop being pinned to Inverse, so a test that checks
// the pair the UI does NOT draw can never catch a palette that forgot to
// wire SelText in.
func TestSelectionIsReadableInEveryPalette(t *testing.T) {
	defer Set("default")
	const min = 4.5
	for _, name := range Names() {
		Set(name)
		if got := contrastRatio(Current.SelText, Current.Selection); got < min {
			t.Errorf("palette %q: SelText/Selection contrast %.2f, want >= %.2f",
				name, got, min)
		}
	}
}

func TestUnknownNameFallsBackToDefault(t *testing.T) {
	defer Set("default")
	Set("no-such-palette")
	if Current.Name != "default" {
		t.Errorf("unknown name selected %q, want default", Current.Name)
	}
}

func TestSuccessTagMatchesSuccessColour(t *testing.T) {
	defer Set("default")
	Set("nord")
	want := "[" + ColorTag(Current.Success) + "]"
	if got := Current.SuccessTag(); got != want {
		t.Errorf("SuccessTag() = %q, want %q", got, want)
	}
}
