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

func TestChooseVariantPrefersCompactOnShortTerminals(t *testing.T) {
	cases := []struct {
		h, w int
		want Variant
	}{
		{24, 100, Compact},
		{29, 100, Compact},
		{30, 100, Full},
		{40, 100, Full},
		{40, 79, Compact}, // too narrow for the 78-column ASCII banner
	}
	for _, tc := range cases {
		if got := ChooseVariant(tc.h, tc.w); got != tc.want {
			t.Errorf("ChooseVariant(%d, %d) = %v, want %v", tc.h, tc.w, got, tc.want)
		}
	}
}

// Height must agree with what Render actually produces, or the Flex
// allocation and the drawn content disagree and the layout clips.
func TestHeightMatchesRenderedLineCount(t *testing.T) {
	for _, v := range []Variant{Full, Compact} {
		lines := strings.Count(Render(v, testContext()), "\n") + 1
		if got := Height(v); got != lines {
			t.Errorf("Height(%v) = %d but Render produced %d lines", v, got, lines)
		}
	}
}

func TestCompactRenderFitsEightyColumns(t *testing.T) {
	out := stripTags(Render(Compact, testContext()))
	for _, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > 80 {
			t.Errorf("compact banner line is %d columns, want <= 80: %q", n, line)
		}
	}
}

func TestCompactRenderCarriesContext(t *testing.T) {
	out := stripTags(Render(Compact, testContext()))
	for _, want := range []string{"0.9.1", "SysTeam", "catppuccin", "20"} {
		if !strings.Contains(out, want) {
			t.Errorf("compact banner missing %q: %q", want, out)
		}
	}
}

func TestFullRenderIsUnchangedASCII(t *testing.T) {
	out := stripTags(Render(Full, testContext()))
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
