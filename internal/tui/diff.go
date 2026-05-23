// Diff helpers for the drift-detail viewer: pure line-level LCS, hunked
// unified-diff rendering (colored for tview or plain text for save), the
// baseline-selection rule, and a no-clobber save helper.

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sshmgr/internal/exec"
	"sshmgr/internal/theme"

	"github.com/rivo/tview"
)

// DiffOp is one entry in the line-level edit script produced by lineDiff:
// Kind is ' ' (context / equal), '-' (only in A, the baseline) or '+' (only
// in B, the selected). A and B are 1-based line numbers in the respective
// input — 0 means "no corresponding line". Text is the line without its
// trailing newline.
type DiffOp struct {
	Kind byte
	A, B int
	Text string
}

// lineDiff returns the line-level edit script between a and b using a
// straightforward LCS DP. O(n·m) — fine for the short remote outputs that
// drift detection usually compares.
func lineDiff(a, b []string) []DiffOp {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	ops := make([]DiffOp, 0, n+m)
	i, j := n, m
	for i > 0 && j > 0 {
		switch {
		case a[i-1] == b[j-1]:
			ops = append(ops, DiffOp{' ', i, j, a[i-1]})
			i--
			j--
		case dp[i-1][j] >= dp[i][j-1]:
			ops = append(ops, DiffOp{'-', i, 0, a[i-1]})
			i--
		default:
			ops = append(ops, DiffOp{'+', 0, j, b[j-1]})
			j--
		}
	}
	for i > 0 {
		ops = append(ops, DiffOp{'-', i, 0, a[i-1]})
		i--
	}
	for j > 0 {
		ops = append(ops, DiffOp{'+', 0, j, b[j-1]})
		j--
	}
	for l, r := 0, len(ops)-1; l < r; l, r = l+1, r-1 {
		ops[l], ops[r] = ops[r], ops[l]
	}
	return ops
}

// hunk groups a contiguous run of change ops with surrounding context, ready
// for a unified-diff `@@ -ba,bl +sa,sl @@` header.
type hunk struct {
	baseStart, baseLen int
	selStart, selLen   int
	ops                []DiffOp
}

// buildHunks groups change ops with up to ctx lines of surrounding context;
// adjacent windows that touch or overlap merge into a single hunk.
func buildHunks(ops []DiffOp, ctx int) []hunk {
	var ranges [][2]int
	for i, op := range ops {
		if op.Kind == ' ' {
			continue
		}
		lo := i - ctx
		if lo < 0 {
			lo = 0
		}
		hi := i + ctx
		if hi >= len(ops) {
			hi = len(ops) - 1
		}
		if len(ranges) > 0 && ranges[len(ranges)-1][1] >= lo-1 {
			if hi > ranges[len(ranges)-1][1] {
				ranges[len(ranges)-1][1] = hi
			}
		} else {
			ranges = append(ranges, [2]int{lo, hi})
		}
	}
	hunks := make([]hunk, 0, len(ranges))
	for _, r := range ranges {
		h := hunk{ops: ops[r[0] : r[1]+1]}
		for _, op := range h.ops {
			if h.baseStart == 0 && op.A > 0 {
				h.baseStart = op.A
			}
			if h.selStart == 0 && op.B > 0 {
				h.selStart = op.B
			}
			switch op.Kind {
			case ' ':
				h.baseLen++
				h.selLen++
			case '-':
				h.baseLen++
			case '+':
				h.selLen++
			}
		}
		hunks = append(hunks, h)
	}
	return hunks
}

// splitLines splits s on "\n" but treats an empty string as zero lines, so
// an empty output diffs against a non-empty one as N pure-add (or pure-del)
// ops rather than confusing a trailing empty line for content.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// unifiedDiff renders a unified diff between baseLines and selLines. ctx is
// the number of context lines around each change (3 is conventional). When
// colored is true the output carries tview color tags (theme-aware); when
// false the output is plain text suitable for saving to a file.
func unifiedDiff(baseLines, selLines []string, baseLabel, selLabel string, ctx int, colored bool) string {
	ops := lineDiff(baseLines, selLines)
	allEqual := true
	for _, op := range ops {
		if op.Kind != ' ' {
			allEqual = false
			break
		}
	}
	if allEqual {
		if colored {
			return theme.Current.DimTag() + "(no differences from baseline)[-]\n"
		}
		return "(no differences from baseline)\n"
	}

	hunks := buildHunks(ops, ctx)
	var b strings.Builder
	if colored {
		head := theme.Current.PrimaryTag()
		b.WriteString(head + "--- " + tview.Escape(baseLabel) + "[-]\n")
		b.WriteString(head + "+++ " + tview.Escape(selLabel) + "[-]\n")
	} else {
		b.WriteString("--- " + baseLabel + "\n")
		b.WriteString("+++ " + selLabel + "\n")
	}
	for _, h := range hunks {
		header := fmt.Sprintf("@@ -%d,%d +%d,%d @@", oneIfZero(h.baseStart), h.baseLen, oneIfZero(h.selStart), h.selLen)
		if colored {
			b.WriteString(theme.Current.DimTag() + header + "[-]\n")
		} else {
			b.WriteString(header + "\n")
		}
		for _, op := range h.ops {
			text := op.Text
			if colored {
				text = tview.Escape(text)
			}
			switch op.Kind {
			case ' ':
				b.WriteString(" " + text + "\n")
			case '-':
				if colored {
					b.WriteString(theme.Current.ErrorTag() + "-" + text + "[-]\n")
				} else {
					b.WriteString("-" + text + "\n")
				}
			case '+':
				if colored {
					b.WriteString(theme.Current.AccentBTag() + "+" + text + "[-]\n")
				} else {
					b.WriteString("+" + text + "\n")
				}
			}
		}
	}
	return b.String()
}

// oneIfZero keeps unified-diff line numbers ≥1; conventional output uses 1
// even when a side is empty.
func oneIfZero(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// defaultBaselineIndex returns the index of the largest group (most aliases),
// ties broken by lower index. GroupByOutput already returns largest-first, so
// for a normal report this is 0 — but pulling the rule into a helper lets it
// be tested and keeps the caller independent of upstream sort order.
func defaultBaselineIndex(groups []exec.OutputGroup) int {
	best, bestN := 0, -1
	for i, g := range groups {
		if len(g.Aliases) > bestN {
			best, bestN = i, len(g.Aliases)
		}
	}
	return best
}

// saveDiffOutput writes diff to a timestamped file in the current directory
// using O_EXCL no-clobber discipline; returns the absolute path. A same-
// second name clash gets a counter suffix so a quick second save never
// overwrites the first.
func saveDiffOutput(diff string) (string, error) {
	base := "sshmgr-diff-" + time.Now().Format("20060102-150405")
	for i := 1; i <= 1000; i++ {
		name := base + ".diff"
		if i > 1 {
			name = fmt.Sprintf("%s-%d.diff", base, i)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.WriteString(diff)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
		if abs, aerr := filepath.Abs(name); aerr == nil {
			return abs, nil
		}
		return name, nil
	}
	return "", fmt.Errorf("could not find a free filename for %s", base)
}
