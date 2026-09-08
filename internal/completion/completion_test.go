package completion

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/cloudprofile"
)

func TestAccountCompletionDoesNotLoadInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yaml")
	t.Setenv("SSHMGR_CONFIG", path)
	t.Setenv("SSHMGR_CLOUD_CONFIG", filepath.Join(t.TempDir(), "cloud.json"))
	for _, tc := range []struct {
		argv       []string
		word, want string
	}{
		{[]string{"login"}, "--p", "--profile,--project"},
		{[]string{"logout"}, "", "--help,--local,--profile"},
		{[]string{"whoami"}, "", "--help,--json,--profile"},
		{[]string{"login", "--profile", "personal"}, "--p", "--project"},
		{[]string{"login", "--profile=personal"}, "--p", "--project"},
		{[]string{"login", "--endpoint"}, "", ""},
		{[]string{"login", "--project"}, "", ""},
		{[]string{"login", "--organization"}, "", ""},
		{[]string{"login", "--timeout"}, "", ""},
		{[]string{"login", "--profile"}, "", ""},
		{[]string{"login", "--"}, "", ""},
		{[]string{"cloud"}, "pro", "project"},
		{[]string{"access"}, "inv", "invite"},
		{[]string{"audit"}, "pu", "push"},
	} {
		got := suggestions(t, tc.argv, tc.word)
		if strings.Join(got, ",") != tc.want {
			t.Errorf("argv=%v word=%q got=%v want=%s", tc.argv, tc.word, got, tc.want)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completion created inventory: %v", err)
	}
	// A broken inventory must not break account flag completion either.
	if err := os.WriteFile(path, []byte("invalid: [yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := suggestions(t, []string{"login"}, "--end"); len(got) != 1 || got[0] != "--endpoint" {
		t.Fatalf("account completion depends on inventory: %v", got)
	}
}

func TestAccountCompletionReadsOnlyCloudProfileNames(t *testing.T) {
	t.Setenv("SSHMGR_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	path := filepath.Join(t.TempDir(), "cloud.json")
	t.Setenv("SSHMGR_CLOUD_CONFIG", path)
	if _, err := cloudprofile.Update(func(cfg *cloudprofile.Config) error {
		for _, name := range []string{"prod", "personal"} {
			if err := cloudprofile.Upsert(cfg, name, cloudprofile.Profile{Endpoint: "https://cloud.example.test", Workspace: "demo", TokenKeyring: cloudprofile.TokenKey(name)}, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"login", "logout", "whoami"} {
		if got := suggestions(t, []string{command, "--profile"}, "pr"); strings.Join(got, ",") != "prod" {
			t.Fatalf("profile prefix completion=%v", got)
		}
		if got := suggestions(t, []string{command}, "--profile=pe"); strings.Join(got, ",") != "--profile=personal" {
			t.Fatalf("inline profile completion=%v", got)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("completion modified Cloud metadata")
	}
}

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
