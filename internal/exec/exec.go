// Package exec runs the same shell command across many hosts in parallel,
// streaming each host's output with an alias prefix and reporting a summary
// at the end. Reuses sshc.ConnectAlias for the full connect chain so
// proxy_command/proxy_jump/passwords work transparently.
package exec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/external"
	"sshmgr/internal/sshc"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"golang.org/x/crypto/ssh"
)

// Selector picks hosts from cfg.Hosts. Empty selector matches nothing —
// callers must explicitly request --all if they want every alias.
type Selector struct {
	Group   string   // match hosts in this group (after ResolveHost merge)
	Tag     string   // match hosts with this tag
	Hosts   []string // explicit alias list
	All     bool     // match every alias in cfg
}

// Select returns the alphabetically-sorted aliases matching s.
func Select(cfg *config.Config, s Selector) []string {
	out := []string{}
	for alias := range cfg.Hosts {
		h, _ := cfg.ResolveHost(alias)
		switch {
		case s.All:
			out = append(out, alias)
		case s.Group != "" && containsString(h.Groups, s.Group):
			out = append(out, alias)
		case s.Tag != "" && containsString(h.Tags, s.Tag):
			out = append(out, alias)
		case len(s.Hosts) > 0 && containsString(s.Hosts, alias):
			out = append(out, alias)
		}
	}
	sort.Strings(out)
	return out
}

// Result is one host's outcome.
type Result struct {
	Alias    string
	ExitCode int
	Err      error
	Duration time.Duration
	Output   string // combined stdout+stderr
	Attempts int    // tries made (1 = succeeded first time)
	TimedOut bool   // the per-host timeout fired
	// FailedStage is where it went wrong: "connect", "command", "timeout"
	// or "skipped" (fail-fast). Empty on success.
	FailedStage string
}

// Options configures a fleet exec run.
type Options struct {
	Parallel int           // max concurrent hosts (<=0 → 8)
	Timeout  time.Duration // per-attempt timeout (0 → no limit)
	Retry    int           // extra attempts for a failed host (0 → try once)
	FailFast bool           // stop launching new hosts once one has failed
	Quiet    bool           // suppress live [alias] streaming (machine-readable mode)
}

// Run executes cmd on each alias, bounded by opts.Parallel. Unless opts.Quiet
// is set, each host's output is streamed live to stderr prefixed with
// [alias]. Returns one Result per alias in input order. The caller renders
// the summary (PrintSummary) so quiet/JSON callers can stay silent.
func Run(cfg *config.Config, aliases []string, cmd string, opts Options) []Result {
	return runFleet(aliases, opts, func(alias string) Result {
		return runAttempt(cfg, alias, cmd, opts)
	})
}

// runFleet is the worker pool: it applies attempt() to each alias with the
// configured parallelism, retry and fail-fast policy. The per-host runner is
// injected so the policy logic is testable with a stub.
func runFleet(aliases []string, opts Options, attempt func(alias string) Result) []Result {
	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 8
	}
	sem := make(chan struct{}, parallel)
	results := make([]Result, len(aliases))
	var wg sync.WaitGroup
	var sawFailure atomic.Bool

	for i, alias := range aliases {
		// Acquire a slot first, then decide: a freed slot means an earlier
		// host's goroutine has finished and recorded its outcome, so the
		// fail-fast check sees an up-to-date sawFailure.
		sem <- struct{}{}
		if opts.FailFast && sawFailure.Load() {
			// An earlier host failed — don't launch this one. Hosts already
			// running are left to finish.
			<-sem
			results[i] = Result{
				Alias:       alias,
				ExitCode:    -1,
				FailedStage: "skipped",
				Err:         errors.New("skipped — fail-fast: an earlier host failed"),
			}
			continue
		}
		wg.Add(1)
		go func(i int, alias string) {
			defer wg.Done()
			defer func() { <-sem }()
			var r Result
			for try := 1; try <= opts.Retry+1; try++ {
				r = attempt(alias)
				r.Attempts = try
				if r.Err == nil && r.ExitCode == 0 {
					break
				}
			}
			results[i] = r
			if r.ExitCode != 0 || r.Err != nil {
				sawFailure.Store(true)
			}
		}(i, alias)
	}
	wg.Wait()
	return results
}

// withTimeout runs fn, returning a timeout Result for alias if it does not
// finish within d. d<=0 runs fn directly. On timeout the context passed to
// fn is cancelled so a context-aware fn (the external backend) can stop its
// child process.
func withTimeout(alias string, d time.Duration, fn func(context.Context) Result) Result {
	if d <= 0 {
		return fn(context.Background())
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	ch := make(chan Result, 1)
	go func() { ch <- fn(ctx) }()
	select {
	case r := <-ch:
		return r
	case <-ctx.Done():
		return Result{
			Alias:       alias,
			ExitCode:    255,
			TimedOut:    true,
			FailedStage: "timeout",
			Err:         fmt.Errorf("timed out after %s", d),
		}
	}
}

func runAttempt(cfg *config.Config, alias, cmd string, opts Options) Result {
	return withTimeout(alias, opts.Timeout, func(ctx context.Context) Result {
		return runOne(ctx, cfg, alias, cmd, opts.Quiet)
	})
}

func runOne(ctx context.Context, cfg *config.Config, alias, cmd string, quiet bool) (r Result) {
	start := time.Now()
	r = Result{Alias: alias}
	defer func() { r.Duration = time.Since(start) }()

	emit := func(color tcell.Color, line string) {
		if !quiet {
			writeLine(alias, color, line)
		}
	}

	// External hosts run through the system ssh client. Output is captured
	// then emitted into the live stream (it can't truly stream).
	if h, ok := cfg.ResolveHost(alias); ok && h.External {
		out, code, err := external.RunCapturedContext(ctx, h, cmd)
		r.Output = out
		if err != nil {
			r.Err = err
			r.ExitCode = 255
			r.FailedStage = "connect"
			emit(theme.Current.Error, "external ssh failed: "+err.Error())
			return r
		}
		r.ExitCode = code
		if code != 0 {
			// 255 is ssh's own failure code (connect/auth); anything else is
			// the remote command's exit status.
			r.FailedStage = "command"
			if code == 255 {
				r.FailedStage = "connect"
			}
		}
		for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			if line != "" {
				emit(theme.Current.Text, line)
			}
		}
		return r
	}

	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		r.Err = err
		r.ExitCode = 255
		r.FailedStage = "connect"
		emit(theme.Current.Error, "connect failed: "+err.Error())
		return r
	}
	// Close the connection exactly once — via the timeout watcher or the
	// normal-exit defer.
	var closeOnce sync.Once
	closeClient := func() { closeOnce.Do(func() { sshc.CloseChain(client) }) }
	defer closeClient()
	// Honour ctx: when the per-host timeout fires, closing the connection
	// unblocks session.Run so the attempt actually stops. Otherwise it would
	// keep running while runFleet starts a retry — duplicating a
	// side-effecting command and interleaving stale output.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			closeClient()
		case <-watchDone:
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		r.Err = err
		r.ExitCode = 255
		r.FailedStage = "connect"
		return r
	}
	defer session.Close()

	var combined bytes.Buffer
	pr, pw := io.Pipe()
	session.Stdout = pw
	session.Stderr = pw
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		// bufio.Scanner so a line spanning two reads doesn't print as two
		// `[alias]`-prefixed fragments. Combined buffer captures bytes
		// verbatim for the final Result.
		tee := io.TeeReader(pr, &combined)
		sc := bufio.NewScanner(tee)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			emit(theme.Current.Text, sc.Text())
		}
	}()

	err = session.Run(cmd)
	pw.Close()
	<-streamDone

	r.Output = combined.String()
	if err == nil {
		r.ExitCode = 0
		return r
	}
	if ee, ok := err.(*ssh.ExitError); ok {
		r.ExitCode = ee.ExitStatus()
		r.FailedStage = "command"
		return r
	}
	r.Err = err
	r.ExitCode = 1
	r.FailedStage = "command"
	return r
}

func writeLine(alias string, lineColor tcell.Color, line string) {
	prefix := fmt.Sprintf("%s[%s]%s ", theme.ANSI(theme.Current.AccentB), alias, theme.Reset())
	body := line
	if lineColor != tcell.ColorDefault {
		body = theme.ANSI(lineColor) + line + theme.Reset()
	}
	fmt.Fprintln(os.Stderr, prefix+body)
}

// PrintSummary writes the coloured pass/fail summary to stderr. Callers skip
// it in machine-readable (quiet) mode.
func PrintSummary(results []Result) {
	if len(results) == 0 {
		return
	}
	primary := theme.ANSI(theme.Current.Primary)
	dim := theme.ANSI(theme.Current.Dim)
	red := theme.ANSI(theme.Current.Error)
	green := theme.ANSI(tcell.ColorGreen)
	reset := theme.Reset()

	ok, fail := 0, 0
	for _, r := range results {
		if r.ExitCode == 0 {
			ok++
		} else {
			fail++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s=== exec summary ===%s  %s%d ok%s  %s%d failed%s\n",
		primary, reset, green, ok, reset, red, fail, reset)
	for _, r := range results {
		mark, color := "✓", green
		if r.ExitCode != 0 {
			mark, color = "✗", red
		}
		info := fmt.Sprintf("exit %d", r.ExitCode)
		if r.Err != nil {
			info = r.Err.Error()
		}
		if r.Attempts > 1 {
			info += fmt.Sprintf(" [%d attempts]", r.Attempts)
		}
		fmt.Fprintf(os.Stderr, "  %s%s%s  %-24s  %s%s%s  %s%s%s\n",
			color, mark, reset, r.Alias,
			dim, r.Duration.Round(time.Millisecond), reset,
			dim, info, reset)
	}
}

// AnyFailed reports whether any result is a failure — a non-zero exit, an
// error, or a fail-fast skip.
func AnyFailed(results []Result) bool {
	for _, r := range results {
		if r.ExitCode != 0 || r.Err != nil {
			return true
		}
	}
	return false
}

// OutputGroup is a set of hosts that produced byte-identical output (after
// trailing-whitespace trim). Drift detection: a fleet command should yield
// one big group; small groups are the outliers.
type OutputGroup struct {
	Output  string   // representative output (empty for the failure bucket)
	Aliases []string // hosts in this group, sorted
	Failed  bool     // true when this bucket is connect failures / non-zero exits
	Label   string   // short summary line (e.g. "nginx/1.24.0" or "exit 1")
}

// GroupByOutput buckets results by identical output. Failed hosts (connect
// error or non-zero exit) are bucketed separately by their error/exit so a
// flapping host doesn't masquerade as drift. Groups are returned largest
// first.
func GroupByOutput(results []Result) []OutputGroup {
	groups := map[string]*OutputGroup{}
	order := []string{}
	for _, r := range results {
		var key string
		var g OutputGroup
		switch {
		case r.Err != nil:
			key = "\x00err:" + r.Err.Error()
			g.Failed = true
			g.Label = "FAILED: " + r.Err.Error()
		case r.ExitCode != 0:
			out := strings.TrimRight(r.Output, "\n")
			key = fmt.Sprintf("\x00exit%d:%s", r.ExitCode, out)
			g.Failed = true
			g.Output = out
			g.Label = fmt.Sprintf("exit %d", r.ExitCode)
		default:
			out := strings.TrimRight(r.Output, "\n")
			key = out
			g.Output = out
			g.Label = firstLine(out)
		}
		existing := groups[key]
		if existing == nil {
			gp := g
			groups[key] = &gp
			order = append(order, key)
			existing = &gp
		}
		existing.Aliases = append(existing.Aliases, r.Alias)
	}
	out := make([]OutputGroup, 0, len(groups))
	for _, k := range order {
		g := groups[k]
		sort.Strings(g.Aliases)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Aliases) > len(out[j].Aliases)
	})
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "(no output)"
	}
	return s
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ResultJSON is the machine-readable form of a Result (`exec --json`).
type ResultJSON struct {
	Alias       string `json:"alias"`
	ExitCode    int    `json:"exit_code"`
	DurationMS  int64  `json:"duration_ms"`
	Output      string `json:"output"`
	Error       string `json:"error,omitempty"`
	Attempts    int    `json:"attempts"`
	TimedOut    bool   `json:"timed_out"`
	FailedStage string `json:"failed_stage,omitempty"`
}

// JSON converts a Result to its machine-readable form.
func (r Result) JSON() ResultJSON {
	j := ResultJSON{
		Alias:       r.Alias,
		ExitCode:    r.ExitCode,
		DurationMS:  r.Duration.Milliseconds(),
		Output:      r.Output,
		Attempts:    r.Attempts,
		TimedOut:    r.TimedOut,
		FailedStage: r.FailedStage,
	}
	if r.Err != nil {
		j.Error = r.Err.Error()
	}
	return j
}

// DriftGroupJSON is one bucket of identical output in a `--diff --json` report.
type DriftGroupJSON struct {
	Aliases []string `json:"aliases"`
	Failed  bool     `json:"failed"`
	Label   string   `json:"label"`
	Output  string   `json:"output"`
}

// DriftJSON is the machine-readable form of a drift report.
type DriftJSON struct {
	TotalHosts     int              `json:"total_hosts"`
	DistinctGroups int              `json:"distinct_groups"`
	Groups         []DriftGroupJSON `json:"groups"`
}

// DriftReport builds the machine-readable drift report from results.
func DriftReport(results []Result) DriftJSON {
	groups := GroupByOutput(results)
	d := DriftJSON{TotalHosts: len(results), DistinctGroups: len(groups)}
	for _, g := range groups {
		d.Groups = append(d.Groups, DriftGroupJSON{
			Aliases: g.Aliases,
			Failed:  g.Failed,
			Label:   g.Label,
			Output:  g.Output,
		})
	}
	return d
}
