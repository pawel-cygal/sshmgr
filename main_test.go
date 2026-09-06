package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
	exec_ "github.com/systeampl/sshmgr/internal/exec"
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

func TestSplitAccessOnePositional(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		value  string
		flags  []string
		extras []string
	}{
		{"snapshot first", []string{"scan.json", "--html", "report.html"}, "scan.json", []string{"--html", "report.html"}, nil},
		{"flags first", []string{"--scan", "scan.json", "SHA256:key"}, "SHA256:key", []string{"--scan", "scan.json"}, nil},
		{"extra positional", []string{"one", "two"}, "one", nil, []string{"two"}},
	}
	for _, test := range cases {
		value, flags, extras := splitAccessOnePositional(test.args, map[string]bool{"--html": true, "--scan": true})
		if value != test.value || !reflect.DeepEqual(flags, test.flags) || !reflect.DeepEqual(extras, test.extras) {
			t.Errorf("%s: got (%q, %v, %v), want (%q, %v, %v)", test.name, value, flags, extras, test.value, test.flags, test.extras)
		}
	}
}

func TestSplitAccessPositionals(t *testing.T) {
	values, flags := splitAccessPositionals(
		[]string{"one.json", "--out", "merged.json", "two.json", "three.json"},
		map[string]bool{"--out": true},
	)
	if !reflect.DeepEqual(values, []string{"one.json", "two.json", "three.json"}) || !reflect.DeepEqual(flags, []string{"--out", "merged.json"}) {
		t.Fatalf("values=%v flags=%v", values, flags)
	}
}

func TestSameAccessPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	if !sameAccessPath(path, filepath.Join(filepath.Dir(path), ".", "scan.json")) {
		t.Fatal("equivalent paths were not detected")
	}
	if sameAccessPath(path, filepath.Join(filepath.Dir(path), "other.json")) {
		t.Fatal("different paths were treated as equal")
	}
	aliasDir := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, aliasDir); err != nil {
		t.Fatal(err)
	}
	if !sameAccessPath(path, filepath.Join(aliasDir, "scan.json")) {
		t.Fatal("equivalent paths through a symlinked parent were not detected")
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(t.TempDir(), "hardlink.json")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if !sameAccessPath(path, hardlink) {
		t.Fatal("hardlinked paths to the same input were not detected")
	}
}

func TestValidateAccessReviewPathsRejectsInputOverwriteAndOutputCollision(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "scan.json")
	identities := filepath.Join(dir, "identities.yaml")
	if err := validateAccessReviewPaths(snapshot, identities, map[string]string{"JSON": snapshot}); err == nil {
		t.Fatal("review accepted snapshot overwrite")
	}
	shared := filepath.Join(dir, "review.out")
	if err := validateAccessReviewPaths(snapshot, identities, map[string]string{"JSON": shared, "HTML": shared}); err == nil {
		t.Fatal("review accepted colliding outputs")
	}
	if err := validateAccessReviewPaths(snapshot, identities, map[string]string{
		"JSON": filepath.Join(dir, "review.json"), "HTML": filepath.Join(dir, "review.html"), "CSV": filepath.Join(dir, "review.csv"),
	}); err != nil {
		t.Fatalf("valid review paths rejected: %v", err)
	}
}

func TestValidateOffboardingOutputPathsRejectsInputOverwriteAndOutputCollision(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "scan.json")
	review := filepath.Join(dir, "review.json")
	if err := validateOffboardingOutputPaths([]string{snapshot, review}, map[string]string{"JSON": review}); err == nil {
		t.Fatal("offboarding accepted ownership-review overwrite")
	}
	shared := filepath.Join(dir, "offboarding.out")
	if err := validateOffboardingOutputPaths([]string{snapshot, review}, map[string]string{"JSON": shared, "HTML": shared}); err == nil {
		t.Fatal("offboarding accepted colliding outputs")
	}
	if err := os.WriteFile(shared, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(dir, "offboarding-hardlink.out")
	if err := os.Link(shared, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := validateOffboardingOutputPaths([]string{snapshot, review}, map[string]string{"JSON": shared, "HTML": hardlink}); err == nil {
		t.Fatal("offboarding accepted hardlinked output collision")
	}
	if err := validateOffboardingOutputPaths([]string{snapshot, review}, map[string]string{
		"JSON": filepath.Join(dir, "offboarding.json"), "HTML": filepath.Join(dir, "offboarding.html"), "CSV": filepath.Join(dir, "offboarding.csv"),
	}); err != nil {
		t.Fatalf("valid offboarding paths rejected: %v", err)
	}
}

func TestValidateOffboardingCheckPathsRejectInputOverwrite(t *testing.T) {
	dir := t.TempDir()
	inputs := []string{
		filepath.Join(dir, "baseline.json"), filepath.Join(dir, "before.json"),
		filepath.Join(dir, "before-review.json"), filepath.Join(dir, "after.json"),
		filepath.Join(dir, "after-review.json"),
	}
	if err := validateOffboardingOutputPaths(inputs, map[string]string{"JSON": inputs[3]}); err == nil {
		t.Fatal("offboarding check accepted overwrite of the after snapshot")
	}
	if err := validateOffboardingOutputPaths(inputs, map[string]string{
		"JSON": filepath.Join(dir, "check.json"), "HTML": filepath.Join(dir, "check.html"), "CSV": filepath.Join(dir, "check.csv"),
	}); err != nil {
		t.Fatalf("valid offboarding check paths rejected: %v", err)
	}
}

func TestExcludeAccessHosts(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"esprit": {Tags: []string{"protected"}},
		"web-01": {Tags: []string{"prod"}},
		"web-02": {Tags: []string{"prod", "skip"}},
	}}
	selected, excluded, err := excludeAccessHosts(cfg, []string{"esprit", "web-01", "web-02"}, []string{"esprit"}, []string{"skip"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selected, []string{"web-01"}) || !reflect.DeepEqual(excluded, []string{"esprit", "web-02"}) {
		t.Fatalf("selected=%v excluded=%v", selected, excluded)
	}
	if _, _, err := excludeAccessHosts(cfg, []string{"web-01"}, []string{"typo"}, nil); err == nil {
		t.Fatal("unknown excluded alias accepted")
	}
	if _, _, err := excludeAccessHosts(cfg, []string{"web-01"}, nil, []string{"typo"}); err == nil {
		t.Fatal("unknown excluded tag accepted")
	}
}

func TestAccessSelectorDescription(t *testing.T) {
	if got := accessSelectorDescription(exec_.Selector{Group: "prod"}); got != "group:prod" {
		t.Fatalf("group selector = %q", got)
	}
	if got := accessSelectorDescription(exec_.Selector{Groups: []string{"systeam", "cygal.lan", "systeam"}}); got != "groups:cygal.lan,systeam" {
		t.Fatalf("repeated group selector = %q", got)
	}
}

func TestAccessGroupFlagsPreserveRepeatedValues(t *testing.T) {
	var groups accessGroupFlags
	if err := groups.Set(" systeam "); err != nil {
		t.Fatal(err)
	}
	if err := groups.Set("cygal.lan"); err != nil {
		t.Fatal(err)
	}
	if got := groups.String(); got != "systeam,cygal.lan" {
		t.Fatalf("groups=%q", got)
	}
	if err := groups.Set(" "); err == nil {
		t.Fatal("empty repeated group was accepted")
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
