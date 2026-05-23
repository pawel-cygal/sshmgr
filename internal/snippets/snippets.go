// Package snippets resolves named command snippets for a host from three
// layers — file-based libraries, group snippets and host snippets — with
// host overriding group overriding file by name. It tracks where each
// snippet came from, for the TUI picker and for lint.
package snippets

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"sshmgr/internal/config"

	"gopkg.in/yaml.v3"
)

// Resolved is a snippet plus its origin.
type Resolved struct {
	config.Snippet
	Source string // "file:<filename>", "group:<name>" or "host:<alias>"
}

type fileDoc struct {
	Snippets []config.Snippet `yaml:"snippets"`
}

// FileSnippets loads the file-based snippet libraries from the config's
// snippets_dir. Every snippet found is returned; a malformed file is skipped
// and reported in the error slice. A missing directory yields no snippets
// and no error — file libraries are optional.
func FileSnippets(cfg *config.Config) ([]Resolved, []error) {
	dir := cfg.ResolveSnippetsDir()
	glob := cfg.ResolveSnippetGlob()
	// Validate the glob up front — an invalid pattern would otherwise match
	// nothing on every file, silently making all libraries disappear.
	if _, err := filepath.Match(glob, "probe"); err != nil {
		return nil, []error{fmt.Errorf("invalid snippet_glob %q: %w", glob, err)}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read snippets dir %s: %w", dir, err)}
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ok, _ := filepath.Match(glob, e.Name()); ok {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []Resolved
	var errs []error
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			errs = append(errs, fmt.Errorf("snippet file %s: %w", name, err))
			continue
		}
		var doc fileDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			errs = append(errs, fmt.Errorf("snippet file %s: %w", name, err))
			continue
		}
		for _, s := range doc.Snippets {
			if s.Name == "" || s.Command == "" {
				errs = append(errs, fmt.Errorf("snippet file %s: a snippet is missing name or command", name))
				continue
			}
			out = append(out, Resolved{Snippet: s, Source: "file:" + name})
		}
	}
	return out, errs
}

// For returns the snippets visible on host alias, merged with precedence
// host > group > file (a later layer overrides an earlier one by name),
// sorted by name. Malformed snippet files are skipped — use FileSnippets (or
// lint) to surface their errors.
func For(cfg *config.Config, alias string) []Resolved {
	merged := map[string]Resolved{}

	files, _ := FileSnippets(cfg)
	for _, s := range files {
		merged[s.Name] = s
	}

	host, ok := cfg.Hosts[alias]
	if !ok {
		return sortResolved(merged)
	}

	// First group to define a name wins (matches config.ResolveHost), but
	// any group still overrides the file layer.
	fromGroup := map[string]bool{}
	for _, g := range host.Groups {
		for _, s := range cfg.Groups[g].Snippets {
			if fromGroup[s.Name] {
				continue
			}
			fromGroup[s.Name] = true
			merged[s.Name] = Resolved{Snippet: s, Source: "group:" + g}
		}
	}
	for _, s := range host.Snippets {
		merged[s.Name] = Resolved{Snippet: s, Source: "host:" + alias}
	}
	return sortResolved(merged)
}

// Find looks up a single snippet by name on host alias, honouring the
// host > group > file precedence.
func Find(cfg *config.Config, alias, name string) (Resolved, bool) {
	for _, s := range For(cfg, alias) {
		if s.Name == name {
			return s, true
		}
	}
	return Resolved{}, false
}

func sortResolved(m map[string]Resolved) []Resolved {
	out := make([]Resolved, 0, len(m))
	for _, s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
