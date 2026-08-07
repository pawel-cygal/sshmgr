package banner

import (
	"strings"
	"testing"
)

func testContext() Context {
	return Context{
		Version:    "0.9.1",
		ConfigPath: "~/.sshmgr.yaml",
		Theme:      "catppuccin",
		Hosts:      20,
		Forwards:   2,
	}
}

func TestChooseVariantDefaultsToCompactAtEverySize(t *testing.T) {
	// The regression this guards: basing the choice on available height
	// meant a user with a tall terminal saw the same six-row art as before
	// and concluded nothing had changed.
	for _, tc := range []struct{ h, w int }{
		{24, 80}, {30, 100}, {45, 120}, {60, 200},
	} {
		if got := ChooseVariant(tc.h, tc.w, false); got != Compact {
			t.Errorf("ChooseVariant(%d, %d, false) = %v, want Compact", tc.h, tc.w, got)
		}
	}
}

func TestChooseVariantHonoursFullRequestWhenItFits(t *testing.T) {
	cases := []struct {
		h, w int
		want Variant
	}{
		{30, 100, Full},
		{40, 100, Full},
		{29, 100, Compact}, // one row short of the art's minimum
		{40, 70, Compact},  // too narrow for the 71-column ASCII banner
	}
	for _, tc := range cases {
		if got := ChooseVariant(tc.h, tc.w, true); got != tc.want {
			t.Errorf("ChooseVariant(%d, %d, true) = %v, want %v", tc.h, tc.w, got, tc.want)
		}
	}
}

// Height must agree with what Render actually produces, or the Flex
// allocation and the drawn content disagree and the layout clips.
func TestHeightMatchesRenderedLineCount(t *testing.T) {
	for _, v := range []Variant{Full, Compact} {
		lines := strings.Count(Render(v, testContext(), 120), "\n") + 1
		if got := Height(v); got != lines {
			t.Errorf("Height(%v) = %d but Render produced %d lines", v, got, lines)
		}
	}
}

// The compact line must fit whatever width it is given, including with a
// realistic release label and a real config path — the pairing that pushed
// the live counts off the right edge before Render became width-aware.
func TestCompactRenderFitsTheWidthItIsGiven(t *testing.T) {
	long := Context{
		Version:    "v0.1.0-rc.3+ui-redesign-p1.20260806",
		ConfigPath: "~/.config/sshmgr/config.yaml",
		Theme:      "catppuccin",
		Hosts:      388,
		Forwards:   2,
	}
	for _, ctx := range []Context{testContext(), long} {
		for _, width := range []int{200, 120, 100, 80, 60, 40} {
			out := stripTags(Render(Compact, ctx, width))
			if n := len([]rune(out)); n > width {
				t.Errorf("width %d: compact banner is %d columns: %q", width, n, out)
			}
		}
	}
}

// Whatever else is dropped to fit, the live counts must survive — they are
// the only parts that change during a session.
func TestCompactRenderKeepsLiveCountsWhenNarrow(t *testing.T) {
	long := Context{
		Version:    "v0.1.0-rc.3+ui-redesign-p1.20260806",
		ConfigPath: "~/.config/sshmgr/config.yaml",
		Theme:      "catppuccin",
		Hosts:      388,
		Forwards:   2,
	}
	for _, width := range []int{120, 100, 80, 60, 40} {
		out := stripTags(Render(Compact, long, width))
		for _, want := range []string{"388 hosts", "2 fwd"} {
			if !strings.Contains(out, want) {
				t.Errorf("width %d: dropped %q from %q", width, want, out)
			}
		}
	}
}

func TestCompactRenderCarriesContext(t *testing.T) {
	out := stripTags(Render(Compact, testContext(), 120))
	for _, want := range []string{"0.9.1", "SysTeam", "catppuccin", "20"} {
		if !strings.Contains(out, want) {
			t.Errorf("compact banner missing %q: %q", want, out)
		}
	}
}

func TestFullRenderIsUnchangedASCII(t *testing.T) {
	out := stripTags(Render(Full, testContext(), 120))
	if !strings.Contains(out, "modern SSH mgr") {
		t.Errorf("full banner should still contain the ASCII art tagline: %q", out)
	}
}

// stripTags removes tview colour tags so assertions run against the text.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '[':
			depth++
		case r == ']':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}
