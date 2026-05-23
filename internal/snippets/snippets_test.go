package snippets

import (
	"os"
	"path/filepath"
	"testing"

	"sshmgr/internal/config"
)

// writeLib writes a snippet library file into dir and returns dir.
func writeLib(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFileSnippetsLoad(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "common.yaml", `snippets:
  - name: uptime
    command: uptime
    description: load check
    tags: [common]
  - name: disk
    command: df -h
`)
	cfg := &config.Config{SnippetsDir: dir}
	got, errs := FileSnippets(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 snippets, got %d", len(got))
	}
	// Files are sorted by name; snippets keep their in-file order.
	if got[0].Name != "uptime" || got[1].Name != "disk" {
		t.Errorf("snippets should keep in-file order: %+v", got)
	}
	for _, s := range got {
		if s.Source != "file:common.yaml" {
			t.Errorf("source: got %q, want file:common.yaml", s.Source)
		}
	}
}

func TestFileSnippetsMalformed(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "broken.yaml", "snippets: [this is not valid: yaml: here")
	writeLib(t, dir, "ok.yaml", "snippets:\n  - name: ok\n    command: echo ok\n")
	cfg := &config.Config{SnippetsDir: dir}
	got, errs := FileSnippets(cfg)
	if len(errs) == 0 {
		t.Fatal("a malformed file should produce an error")
	}
	// the valid file should still load
	if len(got) != 1 || got[0].Name != "ok" {
		t.Errorf("the valid file should still load: %+v", got)
	}
}

func TestFileSnippetsMissingFields(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "lib.yaml", "snippets:\n  - name: noCommand\n  - command: noName\n")
	cfg := &config.Config{SnippetsDir: dir}
	got, errs := FileSnippets(cfg)
	if len(errs) == 0 {
		t.Error("snippets missing name or command should be reported")
	}
	if len(got) != 0 {
		t.Errorf("incomplete snippets should not be loaded: %+v", got)
	}
}

func TestFileSnippetsMissingDir(t *testing.T) {
	cfg := &config.Config{SnippetsDir: filepath.Join(t.TempDir(), "nope")}
	got, errs := FileSnippets(cfg)
	if len(errs) != 0 || len(got) != 0 {
		t.Errorf("a missing snippets dir should be silent: got=%v errs=%v", got, errs)
	}
}

func TestFileSnippetsGlob(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "a.yaml", "snippets:\n  - name: y\n    command: c\n")
	writeLib(t, dir, "b.txt", "snippets:\n  - name: t\n    command: c\n")
	cfg := &config.Config{SnippetsDir: dir} // default glob *.yaml
	got, _ := FileSnippets(cfg)
	if len(got) != 1 || got[0].Name != "y" {
		t.Errorf("default glob should load only *.yaml: %+v", got)
	}
}

func TestForPrecedenceHostWins(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "lib.yaml", "snippets:\n  - name: deploy\n    command: file-deploy\n")
	cfg := &config.Config{
		SnippetsDir: dir,
		Groups: map[string]config.GroupDefaults{
			"web": {Snippets: []config.Snippet{{Name: "deploy", Command: "group-deploy"}}},
		},
		Hosts: map[string]config.HostConfig{
			"web1": {
				Host:     "1",
				Groups:   []string{"web"},
				Snippets: []config.Snippet{{Name: "deploy", Command: "host-deploy"}},
			},
		},
	}
	got := For(cfg, "web1")
	if len(got) != 1 {
		t.Fatalf("expected the three layers to merge to 1 snippet, got %d", len(got))
	}
	if got[0].Command != "host-deploy" || got[0].Source != "host:web1" {
		t.Errorf("host should win: got command=%q source=%q", got[0].Command, got[0].Source)
	}
}

func TestForGroupOverridesFile(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "lib.yaml", "snippets:\n  - name: x\n    command: file-x\n")
	cfg := &config.Config{
		SnippetsDir: dir,
		Groups: map[string]config.GroupDefaults{
			"web": {Snippets: []config.Snippet{{Name: "x", Command: "group-x"}}},
		},
		Hosts: map[string]config.HostConfig{
			"web1": {Host: "1", Groups: []string{"web"}},
		},
	}
	got := For(cfg, "web1")
	if len(got) != 1 || got[0].Command != "group-x" || got[0].Source != "group:web" {
		t.Errorf("group should override file: %+v", got)
	}
}

func TestForSourceTracking(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "lib.yaml", "snippets:\n  - name: a\n    command: ca\n")
	cfg := &config.Config{
		SnippetsDir: dir,
		Groups: map[string]config.GroupDefaults{
			"web": {Snippets: []config.Snippet{{Name: "b", Command: "cb"}}},
		},
		Hosts: map[string]config.HostConfig{
			"web1": {
				Host:     "1",
				Groups:   []string{"web"},
				Snippets: []config.Snippet{{Name: "c", Command: "cc"}},
			},
		},
	}
	src := map[string]string{}
	for _, s := range For(cfg, "web1") {
		src[s.Name] = s.Source
	}
	want := map[string]string{"a": "file:lib.yaml", "b": "group:web", "c": "host:web1"}
	for name, wantSrc := range want {
		if src[name] != wantSrc {
			t.Errorf("snippet %q: source got %q, want %q", name, src[name], wantSrc)
		}
	}
}

func TestFind(t *testing.T) {
	cfg := &config.Config{
		SnippetsDir: filepath.Join(t.TempDir(), "none"), // no file libraries
		Hosts: map[string]config.HostConfig{
			"web1": {Host: "1", Snippets: []config.Snippet{{Name: "deploy", Command: "run-it"}}},
		},
	}
	if s, ok := Find(cfg, "web1", "deploy"); !ok || s.Command != "run-it" {
		t.Errorf("Find deploy: got (%+v, %v)", s, ok)
	}
	if _, ok := Find(cfg, "web1", "missing"); ok {
		t.Error("Find should miss an unknown snippet name")
	}
}

func TestFileSnippetsInvalidGlob(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, dir, "a.yaml", "snippets:\n  - name: x\n    command: c\n")
	cfg := &config.Config{SnippetsDir: dir, SnippetGlob: "["}
	got, errs := FileSnippets(cfg)
	if len(errs) == 0 {
		t.Fatal("an invalid snippet_glob should be reported as an error")
	}
	if len(got) != 0 {
		t.Errorf("no snippets should load with an invalid glob: %+v", got)
	}
}
