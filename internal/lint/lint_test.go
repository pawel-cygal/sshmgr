package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sshmgr/internal/config"
)

// hasFinding reports whether findings contains one of the given severity
// whose message contains substr.
func hasFinding(findings []Finding, sev Severity, substr string) bool {
	for _, f := range findings {
		if f.Severity == sev && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestSummarizeCounts(t *testing.T) {
	findings := []Finding{
		{Severity: SevError, Scope: "a", Message: "broken"},
		{Severity: SevWarn, Scope: "b", Message: "iffy"},
		{Severity: SevWarn, Scope: "c", Message: "iffy"},
		{Severity: SevInfo, Scope: "d", Message: "tidy up"},
	}
	r := Summarize(findings)
	if r.Errors != 1 || r.Warnings != 2 || r.Infos != 1 {
		t.Fatalf("counts: got errors=%d warnings=%d infos=%d", r.Errors, r.Warnings, r.Infos)
	}
	if len(r.Findings) != 4 {
		t.Errorf("Findings should be carried through: got %d", len(r.Findings))
	}
}

func TestSummarizeNilFindingsIsEmptySlice(t *testing.T) {
	// A stable JSON schema needs [] not null when there are no findings.
	r := Summarize(nil)
	if r.Findings == nil {
		t.Error("Findings should be a non-nil empty slice")
	}
	if r.Errors != 0 || r.Warnings != 0 || r.Infos != 0 {
		t.Errorf("empty run should have zero counts: %+v", r)
	}
}

func TestSummarizeOverBrokenConfig(t *testing.T) {
	// proxy_jump to an unknown alias is a SevError finding.
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"web": {Host: "10.0.0.1", ProxyJump: "ghost"},
	}}
	r := Summarize(Run(cfg))
	if r.Errors == 0 {
		t.Fatalf("a broken proxy_jump should produce an error finding: %+v", r)
	}
}

func TestLintFileSnippetParseError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("snippets: [bad: yaml: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{SnippetsDir: dir}
	findings := Run(cfg)
	if !hasFinding(findings, SevError, "broken.yaml") {
		t.Errorf("a malformed snippet file should be an error finding: %+v", findings)
	}
}

func TestLintFileSnippetDuplicate(t *testing.T) {
	dir := t.TempDir()
	body := "snippets:\n  - name: dup\n    command: c\n"
	for _, n := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{SnippetsDir: dir}
	if !hasFinding(Run(cfg), SevWarn, "dup") {
		t.Error("a snippet name duplicated across file libraries should warn")
	}
}

func TestLintMissingSnippetsDir(t *testing.T) {
	cfg := &config.Config{SnippetsDir: filepath.Join(t.TempDir(), "does-not-exist")}
	if !hasFinding(Run(cfg), SevWarn, "does not exist") {
		t.Error("an explicitly configured but missing snippets_dir should warn")
	}
}

func TestLintInvalidSnippetGlob(t *testing.T) {
	cfg := &config.Config{SnippetsDir: t.TempDir(), SnippetGlob: "["}
	if !hasFinding(Run(cfg), SevError, "snippet_glob") {
		t.Error("an invalid snippet_glob should be an error finding")
	}
}

func TestLintForwardProfileInvalidType(t *testing.T) {
	cfg := &config.Config{
		Hosts: map[string]config.HostConfig{"bastion": {Host: "10.0.0.1"}},
		Forwards: map[string]config.ForwardProfile{
			"bad": {Alias: "bastion", Type: "X", Spec: "1080"},
		},
	}
	if !hasFinding(Run(cfg), SevError, "is invalid") {
		t.Errorf("forward with invalid type must surface a SevError finding")
	}
}

func TestLintForwardProfileUnknownAlias(t *testing.T) {
	cfg := &config.Config{
		Hosts: map[string]config.HostConfig{"bastion": {Host: "10.0.0.1"}},
		Forwards: map[string]config.ForwardProfile{
			"orphan": {Alias: "ghost", Type: "L", Spec: "3000:h:3000"},
		},
	}
	if !hasFinding(Run(cfg), SevError, "unknown alias") {
		t.Errorf("forward referencing an unknown alias must error")
	}
}

func TestLintForwardProfileValidIsClean(t *testing.T) {
	cfg := &config.Config{
		Hosts: map[string]config.HostConfig{"bastion": {Host: "10.0.0.1"}},
		Forwards: map[string]config.ForwardProfile{
			"grafana": {Alias: "bastion", Type: "L", Spec: "3000:grafana:3000"},
		},
	}
	for _, f := range Run(cfg) {
		if f.Severity == SevError {
			t.Errorf("a well-formed forward must not produce SevError: %+v", f)
		}
	}
}

func TestLintSelfReferentialProxyCommand(t *testing.T) {
	cfg := &config.Config{
		Groups: map[string]config.GroupDefaults{
			"fleet": {ProxyCommand: "ssh bastion-eu -W %h:%p"},
		},
		Hosts: map[string]config.HostConfig{
			"bastion-eu": {Host: "bastion-eu", Groups: []string{"fleet"}},
			"behind": {Host: "10.0.0.2", Groups: []string{"fleet"}},
		},
	}
	findings := Run(cfg)
	if !hasFinding(findings, SevWarn, "routes the host through itself") {
		t.Errorf("a host whose group proxy_command targets itself should warn: %+v", findings)
	}
	for _, f := range findings {
		if f.Scope == "behind" && strings.Contains(f.Message, "through itself") {
			t.Errorf("behind sits behind the jump — must not be flagged: %+v", f)
		}
	}
}
