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
	"strconv"
	"strings"

	"sshmgr/internal/config"

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
	parts := strings.Split(p.Spec, ":")
	switch p.Type {
	case "L", "R":
		// [bind:]localPort:remoteHost:remotePort  →  3 or 4 colon-separated parts
		if len(parts) < 3 || len(parts) > 4 {
			return fmt.Errorf("type %s requires spec [bind:]port:host:port, got %q", p.Type, p.Spec)
		}
		// The host part is parts[len-2]; the two port parts must be numeric.
		portIdx := []int{0, len(parts) - 1}
		if len(parts) == 4 {
			portIdx = []int{1, 3}
		}
		for _, i := range portIdx {
			if _, err := strconv.Atoi(parts[i]); err != nil {
				return fmt.Errorf("type %s spec %q: %q is not a valid port", p.Type, p.Spec, parts[i])
			}
		}
	case "D":
		// [bind:]port  →  1 or 2 parts
		if len(parts) < 1 || len(parts) > 2 {
			return fmt.Errorf("type D requires spec [bind:]port, got %q", p.Spec)
		}
		port := parts[len(parts)-1]
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("type D spec %q: %q is not a valid port", p.Spec, port)
		}
	default:
		return fmt.Errorf("type %q is invalid (must be L | R | D)", p.Type)
	}
	return nil
}
