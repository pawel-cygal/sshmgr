package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/external"
	"github.com/systeampl/sshmgr/internal/snippets"
)

func TestExternalSnippetCommandArgv(t *testing.T) {
	// `sshmgr <ext-alias> :deploy` resolves the snippet name to its command,
	// which is then handed to the external ssh argv builder.
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"ext1": {
			Host:     "h",
			User:     "u",
			External: true,
			Snippets: []config.Snippet{{Name: "deploy", Command: "sudo systemctl restart app"}},
		},
	}}
	snip, ok := snippets.Find(cfg, "ext1", "deploy")
	if !ok {
		t.Fatal("snippet deploy should resolve")
	}
	argv := external.SSHCommandArgv(cfg.Hosts["ext1"], snip.Command, false)
	if argv[len(argv)-1] != "sudo systemctl restart app" {
		t.Fatalf("resolved snippet command should be the last argv element: %v", argv)
	}
}

func TestSplitFwdArgs(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		alias    string
		flagArgs []string
	}{
		{"alias first (documented form)", []string{"web1", "-L", "9999:localhost:80"}, "web1", []string{"-L", "9999:localhost:80"}},
		{"flags first", []string{"-L", "9999:localhost:80", "web1"}, "web1", []string{"-L", "9999:localhost:80"}},
		{"equals form", []string{"web1", "-D=1080"}, "web1", []string{"-D=1080"}},
		{"remote forward", []string{"box", "-R", "8000:localhost:8000"}, "box", []string{"-R", "8000:localhost:8000"}},
		{"alias only", []string{"web1"}, "web1", nil},
		{"empty", nil, "", nil},
	}
	for _, c := range cases {
		alias, flagArgs := splitFwdArgs(c.in)
		if alias != c.alias || !reflect.DeepEqual(flagArgs, c.flagArgs) {
			t.Errorf("%s: got (alias=%q, flagArgs=%v), want (alias=%q, flagArgs=%v)",
				c.name, alias, flagArgs, c.alias, c.flagArgs)
		}
	}
}

func TestSplitPlaybookArgs(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		playbook string
		flagArgs []string
	}{
		{"playbook first (documented form)", []string{"deploy.yml", "--group", "prod"}, "deploy.yml", []string{"--group", "prod"}},
		{"flags first", []string{"--group", "prod", "deploy.yml"}, "deploy.yml", []string{"--group", "prod"}},
		{"bool flags", []string{"site.yml", "--check", "--diff"}, "site.yml", []string{"--check", "--diff"}},
		{"equals form", []string{"site.yml", "--limit=web"}, "site.yml", []string{"--limit=web"}},
		{"playbook only", []string{"p.yml"}, "p.yml", nil},
		{"empty", nil, "", nil},
	}
	for _, c := range cases {
		pb, fa := splitPlaybookArgs(c.in)
		if pb != c.playbook || !reflect.DeepEqual(fa, c.flagArgs) {
			t.Errorf("%s: got (pb=%q, flagArgs=%v), want (pb=%q, flagArgs=%v)",
				c.name, pb, fa, c.playbook, c.flagArgs)
		}
	}
}

func TestParseCompleteArgs(t *testing.T) {
	cases := []struct {
		name   string
		in     []string
		word   string
		passed []string
	}{
		{"empty", nil, "", nil},
		{"word only", []string{"li"}, "li", nil},
		{"word plus passed", []string{"li", "web01"}, "li", []string{"web01"}},
		{"fish separator", []string{"--", "li", "web01"}, "li", []string{"web01"}},
		{"fish separator empty word", []string{"--"}, "", nil},
	}
	for _, c := range cases {
		passed, word := parseCompleteArgs(c.in)
		if word != c.word || !reflect.DeepEqual(passed, c.passed) {
			t.Errorf("%s: got (passed=%v, word=%q), want (passed=%v, word=%q)",
				c.name, passed, word, c.passed, c.word)
		}
	}
}

func TestHasFwdDirectFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"direct -L", []string{"web01", "-L", "3000:internal:3000"}, true},
		{"direct -R", []string{"web01", "-R", "9000:localhost:3000"}, true},
		{"direct -D", []string{"bastion", "-D", "1080"}, true},
		{"joined -L=spec", []string{"web01", "-L=3000:internal:3000"}, true},
		{"glued -Lspec", []string{"web01", "-L3000:internal:3000"}, true},
		// Alias literally named `run` keeps working through the direct form:
		// the flag-first rule lets us reach it even though `run` is also a
		// subcommand name.
		{"alias named run", []string{"run", "-L", "3000:internal:3000"}, true},
		{"subcommand: fwd ls", []string{"ls"}, false},
		{"subcommand: fwd run grafana", []string{"run", "grafana"}, false},
		{"subcommand: fwd add", []string{"add", "j", "--type", "L", "--spec", "8080:j:8080"}, false},
		{"subcommand: fwd active", []string{"active"}, false},
		{"empty", []string{}, false},
	}
	for _, c := range cases {
		if got := hasFwdDirectFlag(c.args); got != c.want {
			t.Errorf("%s: got %v, want %v (args=%v)", c.name, got, c.want, c.args)
		}
	}
}

func TestSafeFilenameComponent(t *testing.T) {
	for input, want := range map[string]string{
		"web-01.example": "web-01.example",
		"../../escape":   "_.._escape",
		"host/name":      "host_name",
		"...":            "host",
	} {
		if got := safeFilenameComponent(input); got != want {
			t.Errorf("safeFilenameComponent(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOpenDetachedLogNeverReusesAName(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 123, time.UTC)
	p1, f1, err := openDetachedLog(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(p1)
	_ = f1.Close()
	p2, f2, err := openDetachedLog(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = f2.Close()
	if p1 == p2 {
		t.Fatalf("detached logs collided: %s", p1)
	}
	if st, err := os.Stat(p2); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("log permissions: stat=%v err=%v", st, err)
	}
}

func TestSplitEditorCommand(t *testing.T) {
	got, err := splitEditorCommand(`code --wait --reuse-window "profile one"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"code", "--wait", "--reuse-window", "profile one"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("editor argv: got %v want %v", got, want)
	}
	if _, err := splitEditorCommand(`code "unterminated`); err == nil {
		t.Fatal("unterminated editor quote accepted")
	}
}
