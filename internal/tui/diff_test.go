package tui

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"sshmgr/internal/exec"

	"github.com/rivo/tview"
)

func TestDefaultBaselineIndexLargestWins(t *testing.T) {
	groups := []exec.OutputGroup{
		{Aliases: []string{"a"}},
		{Aliases: []string{"b", "c", "d"}},
		{Aliases: []string{"e", "f"}},
	}
	if got := defaultBaselineIndex(groups); got != 1 {
		t.Errorf("largest group must be baseline: got %d, want 1", got)
	}
}

func TestDefaultBaselineIndexTieBreaksByLowerIndex(t *testing.T) {
	groups := []exec.OutputGroup{
		{Aliases: []string{"a", "b"}},
		{Aliases: []string{"c", "d"}},
	}
	if got := defaultBaselineIndex(groups); got != 0 {
		t.Errorf("tie must break by lower index: got %d, want 0", got)
	}
}

func TestSplitLines(t *testing.T) {
	if got := splitLines(""); got != nil {
		t.Errorf("empty input must yield nil, got %v", got)
	}
	if got := splitLines("a\nb\nc"); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("split: got %v", got)
	}
}

func TestLineDiffAddRemoveEqual(t *testing.T) {
	a := []string{"alpha", "beta", "gamma"}
	b := []string{"alpha", "beta-modified", "gamma"}
	ops := lineDiff(a, b)
	var dels, adds, eq int
	for _, op := range ops {
		switch op.Kind {
		case '-':
			dels++
		case '+':
			adds++
		case ' ':
			eq++
		}
	}
	if dels != 1 || adds != 1 || eq != 2 {
		t.Errorf("expected 1 del, 1 add, 2 eq; got dels=%d adds=%d eq=%d", dels, adds, eq)
	}
}

func TestUnifiedDiffNoDifferences(t *testing.T) {
	got := unifiedDiff([]string{"x", "y"}, []string{"x", "y"}, "base", "sel", 3, false)
	if !strings.Contains(got, "no differences from baseline") {
		t.Errorf("identical inputs must return the no-diff marker: %q", got)
	}
}

func TestUnifiedDiffContainsAddedRemovedAndLabels(t *testing.T) {
	got := unifiedDiff([]string{"keep", "old"}, []string{"keep", "new"}, "BASE-LABEL", "SEL-LABEL", 3, false)
	if !strings.Contains(got, "--- BASE-LABEL") || !strings.Contains(got, "+++ SEL-LABEL") {
		t.Errorf("file headers missing: %q", got)
	}
	if !strings.Contains(got, "-old") {
		t.Errorf("removed line missing: %q", got)
	}
	if !strings.Contains(got, "+new") {
		t.Errorf("added line missing: %q", got)
	}
	if !strings.Contains(got, "@@") {
		t.Errorf("hunk header missing: %q", got)
	}
}

func TestUnifiedDiffColoredVsPlainResets(t *testing.T) {
	colored := unifiedDiff([]string{"old"}, []string{"new"}, "b", "s", 3, true)
	if !strings.Contains(colored, "[-]") {
		t.Errorf("colored diff must reset with [-] so color never bleeds: %q", colored)
	}
	plain := unifiedDiff([]string{"old"}, []string{"new"}, "b", "s", 3, false)
	if strings.Contains(plain, "[-]") {
		t.Errorf("plain diff must not carry tview color resets: %q", plain)
	}
}

func TestUnifiedDiffEscapesBracketContent(t *testing.T) {
	// A remote line like `[INFO] starting` looks like a tview tag — the
	// colored diff must run content through tview.Escape so the closing `]`
	// no longer terminates an actual tag. The plain (file-save) rendering
	// must NOT carry the escape artefact.
	line := "[INFO] new"
	escaped := tview.Escape(line)
	if escaped == line {
		t.Fatalf("test premise broken — tview.Escape changed nothing for %q", line)
	}
	colored := unifiedDiff([]string{"keep"}, []string{"keep", line}, "b", "s", 3, true)
	if !strings.Contains(colored, escaped) {
		t.Errorf("colored diff must escape content via tview.Escape: %q", colored)
	}
	plain := unifiedDiff([]string{"keep"}, []string{"keep", line}, "b", "s", 3, false)
	if !strings.Contains(plain, line) {
		t.Errorf("plain (save-to-file) diff must keep content as-is: %q", plain)
	}
}

func TestDriftRowLineMarkers(t *testing.T) {
	label := func(g exec.OutputGroup, i int) string {
		return "g" // keep the assertion focused on prefix/suffix
	}
	cases := []struct {
		name     string
		g        exec.OutputGroup
		i        int
		baseline int
		want     string
	}{
		{"baseline ok", exec.OutputGroup{}, 0, 0, "[baseline] g"},
		{"non-baseline ok", exec.OutputGroup{}, 1, 0, "g  ⚠ drift"},
		{"non-baseline failed", exec.OutputGroup{Failed: true}, 2, 0, "g  ⚠ failed"},
		{"baseline failed", exec.OutputGroup{Failed: true}, 0, 0, "[baseline] g  ⚠ failed"},
	}
	for _, c := range cases {
		if got := driftRowLine(c.g, c.i, c.baseline, label); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSaveDiffOutputNoClobber(t *testing.T) {
	t.Chdir(t.TempDir())
	p1, err := saveDiffOutput("diff one\n")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := saveDiffOutput("diff two\n")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Fatalf("two quick saves must not reuse the same file: %s", p1)
	}
	for _, p := range []string{p1, p2} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("saved diff missing: %s", p)
		}
	}
}
