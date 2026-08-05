// Package forwards loads saved port-forward profiles from the file
// libraries under forwards_dir and merges them with the inline
// cfg.Forwards map. Validation is shared with `sshmgr lint`. The inline
// layer wins on a name collision (mirrors snippet host > file precedence).
package forwards

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/fwd"

	"gopkg.in/yaml.v3"
)

// Resolved is one loaded forward profile with its origin.
type Resolved struct {
	Name string
	config.ForwardProfile
	Source string // "inline" or "file:<filename>"
}

// fileDoc is the on-disk shape of a forward library file. The map shape
// mirrors the inline cfg.Forwards so a profile can move between locations
// without rewriting.
type fileDoc struct {
	Forwards map[string]config.ForwardProfile `yaml:"forwards"`
}

// FileForwards loads file-based forward libraries from cfg.forwards_dir.
// Every profile found is returned; a malformed file is skipped and reported
// in the error slice. A missing directory yields no profiles and no error —
// file libraries are optional.
func FileForwards(cfg *config.Config) ([]Resolved, []error) {
	dir := cfg.ResolveForwardsDir()
	glob := cfg.ResolveForwardGlob()
	if _, err := filepath.Match(glob, "probe"); err != nil {
		return nil, []error{fmt.Errorf("invalid forward_glob %q: %w", glob, err)}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read forwards dir %s: %w", dir, err)}
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
			errs = append(errs, fmt.Errorf("forward file %s: %w", name, err))
			continue
		}
		var doc fileDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			errs = append(errs, fmt.Errorf("forward file %s: %w", name, err))
			continue
		}
		for n, p := range doc.Forwards {
			if n == "" {
				errs = append(errs, fmt.Errorf("forward file %s: a profile has an empty name", name))
				continue
			}
			out = append(out, Resolved{Name: n, ForwardProfile: p, Source: "file:" + name})
		}
	}
	return out, errs
}

// All returns every visible forward profile, with the inline cfg.Forwards
// layer overriding any file-library entry that shares a name. Sorted by name.
func All(cfg *config.Config) []Resolved {
	merged := map[string]Resolved{}
	files, _ := FileForwards(cfg)
	for _, r := range files {
		merged[r.Name] = r
	}
	for name, p := range cfg.Forwards {
		merged[name] = Resolved{Name: name, ForwardProfile: p, Source: "inline"}
	}
	out := make([]Resolved, 0, len(merged))
	for _, r := range merged {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Find returns the profile by name, or (zero, false) if no such profile
// exists in either the inline map or the file libraries.
func Find(cfg *config.Config, name string) (Resolved, bool) {
	for _, r := range All(cfg) {
		if r.Name == name {
			return r, true
		}
	}
	return Resolved{}, false
}

// ForAlias returns the profiles whose Alias matches host alias. Useful for
// the TUI p-menu's "saved forwards for this host" section.
func ForAlias(cfg *config.Config, alias string) []Resolved {
	all := All(cfg)
	out := make([]Resolved, 0, len(all))
	for _, r := range all {
		if r.Alias == alias {
			out = append(out, r)
		}
	}
	return out
}

// FileAliasReferences returns file-library profiles that structurally refer
// to alias. They cannot be rewritten by config.Save, so host deletion must
// ask the user to edit those files first.
func FileAliasReferences(cfg *config.Config, alias string) []string {
	files, _ := FileForwards(cfg)
	var refs []string
	for _, r := range files {
		if r.Alias == alias {
			refs = append(refs, fmt.Sprintf("forward %s (%s)", r.Name, r.Source))
		}
	}
	sort.Strings(refs)
	return refs
}

// ValidateProfile checks structural fields: required alias / type / spec,
// type ∈ {L, R, D}, and a basic shape check on spec (number of colon-
// separated parts plus numeric ports). Runtime parsing in internal/fwd
// does deeper validation.
func ValidateProfile(p config.ForwardProfile) error {
	if p.Alias == "" {
		return fmt.Errorf("alias is required")
	}
	if p.Type == "" {
		return fmt.Errorf("type is required (L | R | D)")
	}
	if p.Spec == "" {
		return fmt.Errorf("spec is required")
	}
	switch p.Type {
	case "L":
		if _, _, err := fwd.ParseLocalSpec(p.Spec); err != nil {
			return fmt.Errorf("type L spec %q: %w", p.Spec, err)
		}
	case "R":
		if _, _, err := fwd.ParseRemoteSpec(p.Spec); err != nil {
			return fmt.Errorf("type R spec %q: %w", p.Spec, err)
		}
	case "D":
		if _, err := fwd.ParseDynamicSpec(p.Spec); err != nil {
			return fmt.Errorf("type D spec %q: %w", p.Spec, err)
		}
	default:
		return fmt.Errorf("type %q is invalid (must be L | R | D)", p.Type)
	}
	return nil
}
