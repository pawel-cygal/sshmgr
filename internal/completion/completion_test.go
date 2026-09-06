package completion

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useConfig points config.Load at a temp config file with the given YAML body.
func useConfig(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHMGR_CONFIG", p)
}

func suggestions(t *testing.T, argv []string, word string) []string {
	t.Helper()
	var buf bytes.Buffer
	if err := Suggest(&buf, argv, word); err != nil {
		t.Fatal(err)
	}
	return strings.Fields(buf.String())
}

func TestSuggestOffersOnlyTaskOrientedSubcommands(t *testing.T) {
	useConfig(t, "hosts:\n  web01:\n    host: 10.0.0.1\n")
	got := map[string]bool{}
	for _, s := range suggestions(t, nil, "") {
		got[s] = true
	}
	for _, want := range []string{
		"connect", "audit", "login", "logout", "whoami", "access", "cloud", "ui", "version", "help",
	} {
		if !got[want] {
			t.Errorf("completion is missing subcommand %q", want)
		}
	}
	for _, hidden := range []string{"scan", "exec", "rotate-key", "bundle-build", "history"} {
		if got[hidden] {
			t.Errorf("expert command %q leaked into default completion", hidden)
		}
	}
}

func TestSuggestOffersAccessSubcommands(t *testing.T) {
	useConfig(t, "hosts:\n  graph-host:\n    host: 10.0.0.1\n")
	got := suggestions(t, []string{"access"}, "")
	want := []string{"approve", "help", "invite", "revoke", "status", "sync"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("access completion = %v, want %v", got, want)
	}
}

func TestSuggestOffersCloudSubcommands(t *testing.T) {
	useConfig(t, "hosts:\n  cloud-host:\n    host: 10.0.0.1\n")
	got := suggestions(t, []string{"cloud"}, "")
	want := []string{"help", "login", "project", "status"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cloud completion = %v, want %v", got, want)
	}
}

func TestSuggestOffersAuditTasks(t *testing.T) {
	useConfig(t, "hosts:\n  web01:\n    host: 10.0.0.1\n")
	got := suggestions(t, []string{"audit"}, "")
	want := []string{"diff", "help", "push", "show", "where-is-key", "who-has"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit completion = %v, want %v", got, want)
	}
}

func TestSuggestIncludesAliases(t *testing.T) {
	useConfig(t, "hosts:\n  web01:\n    host: 10.0.0.1\n  db01:\n    host: 10.0.0.2\n")
	got := map[string]bool{}
	for _, s := range suggestions(t, nil, "") {
		got[s] = true
	}
	if !got["web01"] || !got["db01"] {
		t.Errorf("alias suggestions missing, got %v", got)
	}
}

func TestSuggestNoSubcommandsPastPositionZero(t *testing.T) {
	useConfig(t, "hosts:\n  web01:\n    host: 10.0.0.1\n")
	for _, s := range suggestions(t, []string{"web01"}, "") {
		if s == "exec" || s == "completion" {
			t.Errorf("subcommand %q offered past position 0", s)
		}
	}
}

func TestSuggestPrefixFilter(t *testing.T) {
	useConfig(t, "hosts:\n  web01:\n    host: 1\n  web02:\n    host: 2\n  db01:\n    host: 3\n")
	got := suggestions(t, []string{"web01"}, "web")
	if len(got) != 2 {
		t.Fatalf("prefix 'web' should match 2 aliases, got %v", got)
	}
	for _, s := range got {
		if !strings.HasPrefix(s, "web") {
			t.Errorf("prefix filter leaked non-matching candidate %q", s)
		}
	}
}
