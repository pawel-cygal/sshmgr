package exec

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"sshmgr/internal/config"
)

func selectCfg() *config.Config {
	return &config.Config{
		Groups: map[string]config.GroupDefaults{"web": {}},
		Hosts: map[string]config.HostConfig{
			"a": {Host: "1", Groups: []string{"web"}},
			"b": {Host: "2", Groups: []string{"web"}, Tags: []string{"prod"}},
			"c": {Host: "3", Tags: []string{"prod"}},
			"d": {Host: "4"},
		},
	}
}

func TestSelectEmptyMatchesNothing(t *testing.T) {
	if got := Select(selectCfg(), Selector{}); len(got) != 0 {
		t.Fatalf("empty selector should match nothing, got %v", got)
	}
}

func TestSelectAll(t *testing.T) {
	got := Select(selectCfg(), Selector{All: true})
	if !reflect.DeepEqual(got, []string{"a", "b", "c", "d"}) {
		t.Fatalf("All: got %v", got)
	}
}

func TestSelectGroup(t *testing.T) {
	got := Select(selectCfg(), Selector{Group: "web"})
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("Group web: got %v", got)
	}
}

func TestSelectTag(t *testing.T) {
	got := Select(selectCfg(), Selector{Tag: "prod"})
	if !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatalf("Tag prod: got %v", got)
	}
}

func TestSelectExplicitHosts(t *testing.T) {
	got := Select(selectCfg(), Selector{Hosts: []string{"d", "a"}})
	if !reflect.DeepEqual(got, []string{"a", "d"}) {
		t.Fatalf("explicit hosts (should be sorted): got %v", got)
	}
}

func TestGroupByOutputBucketsIdentical(t *testing.T) {
	results := []Result{
		{Alias: "a", Output: "v1\n", ExitCode: 0},
		{Alias: "b", Output: "v1\n", ExitCode: 0},
		{Alias: "c", Output: "v2\n", ExitCode: 0},
	}
	groups := GroupByOutput(results)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	// Largest group first.
	if !reflect.DeepEqual(groups[0].Aliases, []string{"a", "b"}) {
		t.Errorf("largest group: got %v, want [a b]", groups[0].Aliases)
	}
	if !reflect.DeepEqual(groups[1].Aliases, []string{"c"}) {
		t.Errorf("second group: got %v, want [c]", groups[1].Aliases)
	}
}

func TestGroupByOutputSeparatesFailures(t *testing.T) {
	results := []Result{
		{Alias: "x", Output: "ok\n", ExitCode: 0},
		{Alias: "y", Err: errors.New("dial timeout"), ExitCode: 255},
		{Alias: "z", Output: "bad\n", ExitCode: 1},
	}
	groups := GroupByOutput(results)
	if len(groups) != 3 {
		t.Fatalf("expected 3 distinct buckets, got %d", len(groups))
	}
	byAlias := map[string]OutputGroup{}
	for _, g := range groups {
		byAlias[g.Aliases[0]] = g
	}
	if byAlias["x"].Failed {
		t.Error("exit-0 host should not be in a failed bucket")
	}
	if !byAlias["y"].Failed {
		t.Error("connect-error host should be in a failed bucket")
	}
	if !byAlias["z"].Failed || byAlias["z"].Label != "exit 1" {
		t.Errorf("non-zero exit host: failed=%v label=%q", byAlias["z"].Failed, byAlias["z"].Label)
	}
}

func TestFirstLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alpha\nbeta", "alpha"},
		{"single", "single"},
		{"", "(no output)"},
		{"trailing\n", "trailing"},
	}
	for _, c := range cases {
		if got := firstLine(c.in); got != c.want {
			t.Errorf("firstLine(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestContainsString(t *testing.T) {
	hay := []string{"one", "two", "three"}
	if !containsString(hay, "two") {
		t.Error("expected to find 'two'")
	}
	if containsString(hay, "four") {
		t.Error("did not expect to find 'four'")
	}
	if containsString(nil, "x") {
		t.Error("nil haystack should contain nothing")
	}
}

func TestRunFleetRetrySucceedsEventually(t *testing.T) {
	calls := 0
	attempt := func(alias string) Result {
		calls++
		if calls < 3 {
			return Result{Alias: alias, ExitCode: 1}
		}
		return Result{Alias: alias, ExitCode: 0}
	}
	res := runFleet([]string{"a"}, Options{Retry: 3}, attempt)
	if len(res) != 1 || res[0].ExitCode != 0 {
		t.Fatalf("should succeed by the 3rd attempt: %+v", res)
	}
	if res[0].Attempts != 3 {
		t.Errorf("Attempts: got %d, want 3", res[0].Attempts)
	}
}

func TestRunFleetRetryExhausted(t *testing.T) {
	attempt := func(alias string) Result { return Result{Alias: alias, ExitCode: 1} }
	res := runFleet([]string{"a"}, Options{Retry: 2}, attempt)
	if res[0].Attempts != 3 {
		t.Errorf("Attempts: got %d, want 3 (1 try + 2 retries)", res[0].Attempts)
	}
	if res[0].ExitCode == 0 {
		t.Error("exhausted retries should stay failed")
	}
}

func TestRunFleetFailFast(t *testing.T) {
	attempt := func(alias string) Result {
		if alias == "b" {
			return Result{Alias: alias, ExitCode: 1}
		}
		return Result{Alias: alias, ExitCode: 0}
	}
	// Parallel:1 makes ordering deterministic: a, then b (fails), then c/d skip.
	res := runFleet([]string{"a", "b", "c", "d"}, Options{Parallel: 1, FailFast: true}, attempt)
	if res[0].FailedStage == "skipped" {
		t.Error("the first host should always run")
	}
	if res[2].FailedStage != "skipped" || res[3].FailedStage != "skipped" {
		t.Errorf("hosts after the failure should be skipped: %+v", res)
	}
}

func TestRunFleetNoFailFastRunsEveryHost(t *testing.T) {
	attempt := func(alias string) Result {
		if alias == "b" {
			return Result{Alias: alias, ExitCode: 1}
		}
		return Result{Alias: alias, ExitCode: 0}
	}
	res := runFleet([]string{"a", "b", "c", "d"}, Options{Parallel: 1}, attempt)
	for _, r := range res {
		if r.FailedStage == "skipped" {
			t.Errorf("without --fail-fast no host should be skipped: %+v", res)
		}
	}
}

func TestWithTimeoutFires(t *testing.T) {
	r := withTimeout("slow", 15*time.Millisecond, func(ctx context.Context) Result {
		time.Sleep(200 * time.Millisecond)
		return Result{Alias: "slow", ExitCode: 0}
	})
	if !r.TimedOut || r.FailedStage != "timeout" || r.ExitCode == 0 {
		t.Fatalf("expected a timeout result, got %+v", r)
	}
}

func TestWithTimeoutPassThrough(t *testing.T) {
	r := withTimeout("fast", time.Second, func(ctx context.Context) Result {
		return Result{Alias: "fast", ExitCode: 0}
	})
	if r.TimedOut || r.ExitCode != 0 {
		t.Fatalf("a fast fn should pass straight through, got %+v", r)
	}
}

func TestWithTimeoutDisabled(t *testing.T) {
	r := withTimeout("x", 0, func(ctx context.Context) Result {
		return Result{Alias: "x", ExitCode: 7}
	})
	if r.ExitCode != 7 || r.TimedOut {
		t.Fatalf("timeout<=0 should run fn directly, got %+v", r)
	}
}

func TestResultJSON(t *testing.T) {
	r := Result{
		Alias: "web1", ExitCode: 2, Duration: 1500 * time.Millisecond,
		Output: "boom", Err: errors.New("nope"),
		Attempts: 3, TimedOut: true, FailedStage: "timeout",
	}
	j := r.JSON()
	if j.Alias != "web1" || j.ExitCode != 2 || j.DurationMS != 1500 ||
		j.Output != "boom" || j.Error != "nope" || j.Attempts != 3 ||
		!j.TimedOut || j.FailedStage != "timeout" {
		t.Fatalf("ResultJSON shape wrong: %+v", j)
	}
}

func TestResultJSONCleanHasNoError(t *testing.T) {
	j := Result{Alias: "a", ExitCode: 0}.JSON()
	if j.Error != "" {
		t.Errorf("Error should be empty for a clean result, got %q", j.Error)
	}
}

func TestDriftReport(t *testing.T) {
	results := []Result{
		{Alias: "a", Output: "v1\n"},
		{Alias: "b", Output: "v1\n"},
		{Alias: "c", Output: "v2\n"},
	}
	d := DriftReport(results)
	if d.TotalHosts != 3 || d.DistinctGroups != 2 {
		t.Fatalf("drift counts: got total=%d distinct=%d", d.TotalHosts, d.DistinctGroups)
	}
	if len(d.Groups) != 2 || !reflect.DeepEqual(d.Groups[0].Aliases, []string{"a", "b"}) {
		t.Fatalf("drift groups wrong: %+v", d.Groups)
	}
	if d.Groups[0].Output != "v1" {
		t.Errorf("group output should be trailing-newline trimmed: %q", d.Groups[0].Output)
	}
}

func TestAnyFailed(t *testing.T) {
	if AnyFailed([]Result{{Alias: "a", ExitCode: 0}, {Alias: "b", ExitCode: 0}}) {
		t.Error("all-zero results should report no failure")
	}
	if !AnyFailed([]Result{{Alias: "a", ExitCode: 0}, {Alias: "b", ExitCode: 1}}) {
		t.Error("a non-zero exit is a failure")
	}
	if !AnyFailed([]Result{{Alias: "a", Err: errors.New("x")}}) {
		t.Error("an error is a failure")
	}
	if !AnyFailed([]Result{{Alias: "a", ExitCode: -1, FailedStage: "skipped"}}) {
		t.Error("a fail-fast skip is a failure")
	}
	if AnyFailed(nil) {
		t.Error("no results means no failure")
	}
}
