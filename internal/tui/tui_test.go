package tui

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sshmgr/internal/config"
	"sshmgr/internal/exec"
	"sshmgr/internal/snippets"
)

func TestPlaybookExtraArgs(t *testing.T) {
	cases := []struct {
		name      string
		playbook  string
		selector  []string
		check     bool
		diff      bool
		extraVars string
		want      []string
	}{
		{
			"host selector, no flags",
			"deploy.yml", []string{"--host", "web1,web2"}, false, false, "",
			[]string{"deploy.yml", "--host", "web1,web2"},
		},
		{
			"group selector, all flags",
			"site.yml", []string{"--group", "prod"}, true, true, "env=stage",
			[]string{"site.yml", "--group", "prod", "--check", "--diff", "--extra-vars", "env=stage"},
		},
		{
			"blank extra-vars is dropped",
			"p.yml", []string{"--host", "a"}, false, false, "   ",
			[]string{"p.yml", "--host", "a"},
		},
	}
	for _, c := range cases {
		got := playbookExtraArgs(c.playbook, c.selector, c.check, c.diff, c.extraVars)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSourceLabel(t *testing.T) {
	cases := map[string]string{
		"host:web01":    "host",
		"group:prod":    "group:prod",
		"file:lib.yaml": "file:lib.yaml",
	}
	for in, want := range cases {
		if got := sourceLabel(in); got != want {
			t.Errorf("sourceLabel(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestSharedSnippetsExcludesConflictingCommand(t *testing.T) {
	cfg := &config.Config{
		// Point at a nonexistent dir so no real file libraries leak in.
		SnippetsDir: filepath.Join(t.TempDir(), "none"),
		Hosts: map[string]config.HostConfig{
			"web1": {Host: "1", Snippets: []config.Snippet{
				{Name: "deploy", Command: "deploy-blue.sh"},
				{Name: "uptime", Command: "uptime"},
			}},
			"web2": {Host: "2", Snippets: []config.Snippet{
				{Name: "deploy", Command: "deploy-green.sh"},
				{Name: "uptime", Command: "uptime"},
			}},
		},
	}
	got := (&uiState{cfg: cfg}).sharedSnippets([]string{"web1", "web2"})
	// "uptime" is byte-identical on both hosts → shared. "deploy" resolves
	// to a different command per host → must NOT be offered as shared.
	if len(got) != 1 || got[0].Name != "uptime" {
		t.Fatalf("only the identical snippet should be shared, got %+v", got)
	}
}

func TestExecExtraArgs(t *testing.T) {
	cases := []struct {
		name     string
		diff     bool
		selector []string
		command  string
		want     []string
	}{
		{"plain command", false, []string{"--host", "web1"}, "uptime",
			[]string{"--host", "web1", "--", "uptime"}},
		{"dash command stays a command", false, []string{"--host", "web1"}, "--version",
			[]string{"--host", "web1", "--", "--version"}},
		{"with diff", true, []string{"--group", "prod"}, "nginx -v",
			[]string{"--diff", "--group", "prod", "--", "nginx -v"}},
	}
	for _, c := range cases {
		got := execExtraArgs(c.diff, c.selector, c.command)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHostBadges(t *testing.T) {
	if got := hostBadges(config.HostConfig{Host: "h"}); got != "" {
		t.Errorf("a plain host should have no badges, got %q", got)
	}
	full := hostBadges(config.HostConfig{
		Host: "h", External: true, AutoDuoPush: true,
		Persistent: "tmux", Tags: []string{"web", "prod"},
	})
	for _, want := range []string{"external", "duo", "tmux", "#web", "#prod"} {
		if !strings.Contains(full, want) {
			t.Errorf("badge strip missing %q: %q", want, full)
		}
	}
	if got := hostBadges(config.HostConfig{Host: "h", KVM: &config.KVMConfig{Host: "h-kvm"}}); !strings.Contains(got, "KVM") {
		t.Errorf("host with a kvm block should show a KVM badge, got %q", got)
	}
}

func TestFormatResultsFilter(t *testing.T) {
	results := []exec.Result{
		{Alias: "web1", ExitCode: 0, Output: "ok\n"},
		{Alias: "web2", ExitCode: 1, Output: "boom\n"},
		{Alias: "web3", ExitCode: 0, Output: "ok\n"},
	}
	_, summary, all := formatResults(results, filterAll)
	if len(all) != 3 {
		t.Errorf("filterAll: expected 3 host blocks, got %d", len(all))
	}
	if !strings.Contains(summary, "2 ok") || !strings.Contains(summary, "1 failed") {
		t.Errorf("summary should count the full set: %q", summary)
	}
	if _, _, okBlocks := formatResults(results, filterOK); len(okBlocks) != 2 {
		t.Errorf("filterOK: expected 2 blocks, got %d", len(okBlocks))
	}
	body, _, failBlocks := formatResults(results, filterFailed)
	if len(failBlocks) != 1 {
		t.Errorf("filterFailed: expected 1 block, got %d", len(failBlocks))
	}
	if !strings.Contains(body, "web2") || strings.Contains(body, "web1") {
		t.Errorf("filterFailed body should show only the failed host: %q", body)
	}
}

func TestSaveExecOutputNoClobber(t *testing.T) {
	t.Chdir(t.TempDir())
	results := []exec.Result{{Alias: "h", ExitCode: 0, Output: "out"}}
	p1, err := saveExecOutput(results)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := saveExecOutput(results)
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Fatalf("two quick saves must not reuse the same file: %s", p1)
	}
	for _, p := range []string{p1, p2} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("saved file missing: %s", p)
		}
	}
}

func TestHostMatchesQuery(t *testing.T) {
	web := config.HostConfig{
		Host: "10.0.0.1", User: "deploy",
		Tags: []string{"web", "prod"}, Groups: []string{"frontend"},
	}
	ext := config.HostConfig{Host: "bastion", External: true}
	cases := []struct {
		name  string
		h     config.HostConfig
		alias string
		query string
		want  bool
	}{
		{"tag match", web, "web1", "tag:web", true},
		{"tag miss", web, "web1", "tag:db", false},
		{"group match", web, "web1", "group:frontend", true},
		{"group miss", web, "web1", "group:backend", false},
		{"backend external", ext, "bastion", "backend:external", true},
		{"backend external on native host", web, "web1", "backend:external", false},
		{"backend native", web, "web1", "backend:native", true},
		{"backend short prefix", ext, "bastion", "backend:ext", true},
		{"plain text on alias", web, "web1", "web1", true},
		{"plain text on host", web, "web1", "10.0.0", true},
		{"plain text miss", web, "web1", "zzz", false},
		{"unknown prefix falls back to plain text, no error", web, "web1", "foo:bar", false},
		{"empty query matches", web, "web1", "", true},
	}
	for _, c := range cases {
		if got := hostMatchesQuery(c.h, c.alias, c.query); got != c.want {
			t.Errorf("%s: hostMatchesQuery(%q)=%v, want %v", c.name, c.query, got, c.want)
		}
	}
}

func TestAliasOrderPinnedFirst(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"alpha": {Host: "1"},
		"zeta":  {Host: "2", Pinned: true},
		"beta":  {Host: "3"},
	}}
	got := (&uiState{cfg: cfg, sort: sortName}).aliasOrder()
	// zeta is pinned -> first despite sorting last by name; the rest keep
	// their name order.
	want := []string{"zeta", "alpha", "beta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aliasOrder: got %v, want %v", got, want)
	}
}

func TestFilterStrings(t *testing.T) {
	items := []string{"deploy-app.yml", "rotate-keys.yml", "patch-debian.yml", "deploy-db.yml"}
	cases := []struct {
		q    string
		want []string
	}{
		{"", items},
		{"deploy", []string{"deploy-app.yml", "deploy-db.yml"}},
		{"DEB", []string{"patch-debian.yml"}}, // case-insensitive
		{".yml", items},
		{"nope", nil},
	}
	for _, c := range cases {
		got := filterStrings(items, c.q)
		var copy []string
		copy = append(copy, got...)
		if !reflect.DeepEqual(copy, c.want) {
			t.Errorf("filterStrings(%q): got %v, want %v", c.q, copy, c.want)
		}
	}
}

func TestFilterResolved(t *testing.T) {
	items := []snippets.Resolved{
		{Snippet: config.Snippet{Name: "uptime", Command: "uptime"}, Source: "host:web1"},
		{Snippet: config.Snippet{Name: "docker-logs", Command: "find /var/lib/docker/containers", Description: "Find big container logs"}, Source: "file:fleet.yaml"},
		{Snippet: config.Snippet{Name: "deploy", Command: "deploy-blue.sh"}, Source: "group:prod"},
	}
	cases := []struct {
		q    string
		want []string // names expected in result, in input order
	}{
		{"", []string{"uptime", "docker-logs", "deploy"}},
		{"docker", []string{"docker-logs"}},
		{"BIG", []string{"docker-logs"}},        // case-insensitive on Description
		{"deploy-blue", []string{"deploy"}},     // matches Command
		{"file:fleet", []string{"docker-logs"}}, // matches Source
		{"nope", nil},
	}
	for _, c := range cases {
		got := filterResolved(items, c.q)
		var names []string
		for _, r := range got {
			names = append(names, r.Name)
		}
		if !reflect.DeepEqual(names, c.want) {
			t.Errorf("filterResolved(%q): got %v, want %v", c.q, names, c.want)
		}
	}
}

func TestSnippetScopeRespectsMultiSelect(t *testing.T) {
	s := &uiState{multiSelected: map[string]bool{"web1": true, "web3": true}}
	aliases, selector, multi := s.snippetScope("web2")
	if !multi {
		t.Fatalf("multi-selection must take precedence over the highlighted host")
	}
	if !reflect.DeepEqual(aliases, []string{"web1", "web3"}) {
		t.Errorf("aliases: got %v, want [web1 web3]", aliases)
	}
	if !reflect.DeepEqual(selector, []string{"--host", "web1,web3"}) {
		t.Errorf("selector: got %v, want [--host web1,web3]", selector)
	}
}

func TestSnippetScopeFallsBackToHighlighted(t *testing.T) {
	s := &uiState{multiSelected: map[string]bool{}}
	aliases, selector, multi := s.snippetScope("web2")
	if multi {
		t.Fatalf("no multi-selection: must not be multi")
	}
	if !reflect.DeepEqual(aliases, []string{"web2"}) {
		t.Errorf("aliases: got %v, want [web2]", aliases)
	}
	if !reflect.DeepEqual(selector, []string{"--host", "web2"}) {
		t.Errorf("selector: got %v, want [--host web2]", selector)
	}
}

func TestPill(t *testing.T) {
	got := pill("x", "exec")
	if !strings.Contains(got, "x") || !strings.Contains(got, "exec") {
		t.Errorf("pill should carry both key and label: %q", got)
	}
	// The fg+bg reset must be present, or the pill color bleeds into the
	// rest of the footer line.
	if !strings.Contains(got, "[-:-]") {
		t.Errorf("pill must reset foreground and background: %q", got)
	}
}

func TestHelpTextCoversFooterActions(t *testing.T) {
	got := helpText()
	for _, label := range []string{
		"shell", "sftp", "files", "fwd", "snippet", "exec", "watch", "playbook",
		"mark", "tree", "sort", "host", "group", "filter", "help", "quit",
	} {
		if !strings.Contains(got, label) {
			t.Errorf("footer is missing the %q action", label)
		}
	}
}
