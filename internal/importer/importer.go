// Package importer pulls hosts into sshmgr config from external sources:
// an OpenSSH client config, an Ansible INI inventory, or an /etc/hosts file.
//
// All importers are additive and non-destructive: an alias that already
// exists in the config is left untouched and reported as skipped.
package importer

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/systeampl/sshmgr/internal/config"
)

// matchesOnly reports whether alias should be imported given the optional
// glob filter. An empty filter matches everything.
func matchesOnly(only []string, alias string) bool {
	if len(only) == 0 {
		return true
	}
	for _, pat := range only {
		if ok, _ := path.Match(pat, alias); ok {
			return true
		}
	}
	return false
}

// Result summarizes one import run.
type Result struct {
	Added   []string // new aliases written
	Skipped []string // aliases that already existed
	Groups  []string // groups created or referenced
}

// addHost records h under alias unless the alias already exists. Returns
// whether it was added.
func addHost(cfg *config.Config, r *Result, alias string, h config.HostConfig) bool {
	if _, exists := cfg.Hosts[alias]; exists {
		r.Skipped = append(r.Skipped, alias)
		return false
	}
	cfg.Hosts[alias] = h
	r.Added = append(r.Added, alias)
	return true
}

// SSHConfig parses an OpenSSH client config and returns hosts. Each non-
// wildcard `Host` block becomes one host. group, if non-empty, is assigned
// to every imported host. only, if non-empty, is a list of glob patterns —
// an alias is imported only when it matches at least one.
func SSHConfig(cfg *config.Config, cfgPath, group string, only []string) (*Result, error) {
	root := config.ExpandPath(cfgPath)
	lines, err := readSSHConfigLines(root, 0, map[string]bool{})
	if err != nil {
		return nil, err
	}

	r := &Result{}
	type block struct {
		patterns []string
		fields   map[string]string
	}
	// OpenSSH applies matching blocks in file order and the first value won for
	// each scalar option. Model that directly so `Host *` defaults and concrete
	// blocks behave like `ssh`, independent of their order in the file.
	blocks := []block{{patterns: []string{"*"}, fields: map[string]string{}}}
	cur := &blocks[0]
	active := true
	concrete := map[string]bool{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val := splitConfigLine(line)
		lkey := strings.ToLower(key)
		if lkey == "host" {
			patterns := splitWords(val)
			blocks = append(blocks, block{patterns: patterns, fields: map[string]string{}})
			cur = &blocks[len(blocks)-1]
			active = true
			for _, alias := range patterns {
				if !strings.HasPrefix(alias, "!") && !strings.ContainsAny(alias, "*?") {
					concrete[alias] = true
				}
			}
			continue
		}
		if lkey == "match" {
			active = false
			continue
		}
		if !active || cur == nil {
			continue // inside a Match block or a pre-Host directive — ignore
		}
		switch lkey {
		case "hostname", "user", "port", "proxyjump", "proxycommand":
			if cur.fields[lkey] == "" {
				cur.fields[lkey] = val
			}
		case "identityfile":
			// keep only the first IdentityFile
			if cur.fields["identityfile"] == "" {
				cur.fields["identityfile"] = val
			}
		}
	}
	aliases := make([]string, 0, len(concrete))
	for alias := range concrete {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		if !matchesOnly(only, alias) {
			continue
		}
		fields := map[string]string{}
		for _, b := range blocks {
			if !sshHostPatternsMatch(b.patterns, alias) {
				continue
			}
			for key, val := range b.fields {
				if fields[key] == "" {
					fields[key] = val
				}
			}
		}
		h := config.HostConfig{Host: strings.ReplaceAll(fields["hostname"], "%h", alias)}
		if h.Host == "" {
			h.Host = alias
		}
		h.User = fields["user"]
		if p := fields["port"]; p != "" {
			if n, convErr := strconv.Atoi(p); convErr == nil {
				h.Port = n
			}
		}
		h.Key = fields["identityfile"]
		h.ProxyJump = fields["proxyjump"]
		h.ProxyCommand = fields["proxycommand"]
		if group != "" {
			h.Groups = []string{group}
		}
		addHost(cfg, r, alias, h)
	}
	if group != "" {
		ensureGroup(cfg, group)
		r.Groups = []string{group}
	}
	sort.Strings(r.Added)
	sort.Strings(r.Skipped)
	return r, nil
}

// Ansible parses an INI-format Ansible inventory. `[section]` becomes a
// group; `[section:vars]` populates that group's defaults; `[section:children]`
// is flattened transitively so child hosts also join every parent. Host lines
// map ansible_host/user/port/private_key_file and duplicate host declarations
// merge memberships without overwriting a pre-existing sshmgr host.
func Ansible(cfg *config.Config, invPath string) (*Result, error) {
	f, err := os.Open(config.ExpandPath(invPath))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", invPath, err)
	}
	defer f.Close()

	r := &Result{}
	groupSet := map[string]bool{}
	children := map[string]map[string]bool{}
	type parsedHost struct {
		h      config.HostConfig
		groups map[string]bool
	}
	parsed := map[string]*parsedHost{}
	section := ""     // current [section]
	sectionKind := "" // "", "vars", "children"

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.Trim(line, "[]")
			sectionKind = ""
			if i := strings.LastIndex(name, ":"); i >= 0 {
				sectionKind = name[i+1:]
				name = name[:i]
			}
			section = name
			if section != "" {
				groupSet[section] = true
				ensureGroup(cfg, section)
			}
			continue
		}
		switch sectionKind {
		case "vars":
			// [group:vars] — fold into the group defaults.
			k, v := ansibleKV(line)
			applyGroupVar(cfg, section, k, v)
		case "children":
			// Record the relationship now; after parsing, parent membership is
			// propagated transitively to every host in each child group.
			fields := splitWords(line)
			if len(fields) == 0 {
				continue
			}
			child := fields[0]
			groupSet[section], groupSet[child] = true, true
			ensureGroup(cfg, section)
			ensureGroup(cfg, child)
			if children[section] == nil {
				children[section] = map[string]bool{}
			}
			children[section][child] = true
		default:
			// host line: "name key=val key=val"
			fields := splitWords(line)
			if len(fields) == 0 {
				continue
			}
			alias := fields[0]
			ph := parsed[alias]
			if ph == nil {
				ph = &parsedHost{h: config.HostConfig{Host: alias}, groups: map[string]bool{}}
				parsed[alias] = ph
			}
			for _, kv := range fields[1:] {
				k, v := ansibleKV(kv)
				switch k {
				case "ansible_host", "ansible_ssh_host":
					if ph.h.Host == alias {
						ph.h.Host = v
					}
				case "ansible_user", "ansible_ssh_user":
					if ph.h.User == "" {
						ph.h.User = v
					}
				case "ansible_port", "ansible_ssh_port":
					if ph.h.Port == 0 {
						ph.h.Port, _ = strconv.Atoi(v)
					}
				case "ansible_ssh_private_key_file", "ansible_private_key_file":
					if ph.h.Key == "" {
						ph.h.Key = v
					}
				}
			}
			if section != "" {
				ph.groups[section] = true
				groupSet[section] = true
				ensureGroup(cfg, section)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// A host in a child joins every transitive parent as well. An explicitly
	// configured `all` group applies to every host, matching Ansible semantics.
	var contains func(string, string, map[string]bool) bool
	contains = func(parent, target string, seen map[string]bool) bool {
		if parent == target {
			return true
		}
		if seen[parent] {
			return false
		}
		seen[parent] = true
		for child := range children[parent] {
			if contains(child, target, seen) {
				return true
			}
		}
		return false
	}
	parsedAliases := make([]string, 0, len(parsed))
	for alias := range parsed {
		parsedAliases = append(parsedAliases, alias)
	}
	sort.Strings(parsedAliases)
	for _, alias := range parsedAliases {
		ph := parsed[alias]
		for parent := range groupSet {
			if parent == "all" {
				ph.groups[parent] = true
				continue
			}
			for direct := range ph.groups {
				if contains(parent, direct, map[string]bool{}) {
					ph.groups[parent] = true
					break
				}
			}
		}
		for g := range ph.groups {
			ph.h.Groups = append(ph.h.Groups, g)
		}
		sort.Strings(ph.h.Groups)
		addHost(cfg, r, alias, ph.h)
	}
	for g := range groupSet {
		r.Groups = append(r.Groups, g)
	}
	sort.Strings(r.Added)
	sort.Strings(r.Skipped)
	sort.Strings(r.Groups)
	return r, nil
}

// Hosts parses an /etc/hosts-style file: "IP name [name...]". localhost,
// IPv6 loopback names and comments are skipped. group, if set, is assigned.
func Hosts(cfg *config.Config, filePath, group string) (*Result, error) {
	f, err := os.Open(config.ExpandPath(filePath))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	r := &Result{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		for _, name := range fields[1:] {
			lname := strings.ToLower(name)
			if lname == "localhost" || strings.HasPrefix(lname, "ip6-") || lname == "broadcasthost" {
				continue
			}
			h := config.HostConfig{Host: ip}
			if group != "" {
				h.Groups = []string{group}
			}
			addHost(cfg, r, name, h)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if group != "" {
		ensureGroup(cfg, group)
		r.Groups = []string{group}
	}
	sort.Strings(r.Added)
	sort.Strings(r.Skipped)
	return r, nil
}

func ensureGroup(cfg *config.Config, name string) {
	if cfg.Groups == nil {
		cfg.Groups = map[string]config.GroupDefaults{}
	}
	if _, ok := cfg.Groups[name]; !ok {
		cfg.Groups[name] = config.GroupDefaults{}
	}
}

func applyGroupVar(cfg *config.Config, group, k, v string) {
	ensureGroup(cfg, group)
	g := cfg.Groups[group]
	switch k {
	case "ansible_user", "ansible_ssh_user":
		if g.User == "" {
			g.User = v
		}
	case "ansible_port", "ansible_ssh_port":
		if g.Port == 0 {
			g.Port, _ = strconv.Atoi(v)
		}
	case "ansible_ssh_private_key_file", "ansible_private_key_file":
		if g.Key == "" {
			g.Key = v
		}
	}
	cfg.Groups[group] = g
}

// splitConfigLine splits an ssh_config line into key and value, handling both
// "Key value" and "Key=value" forms.
func splitConfigLine(line string) (key, val string) {
	line = stripInlineComment(line)
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		key = line[:i]
		val = strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		return key, strings.Trim(val, "\"")
	}
	return line, ""
}

// ansibleKV splits "key=value" (value may be quoted).
func ansibleKV(s string) (key, val string) {
	if i := strings.IndexByte(s, '='); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.Trim(strings.TrimSpace(s[i+1:]), "\"'")
	}
	return strings.TrimSpace(s), ""
}

func sshHostPatternsMatch(patterns []string, alias string) bool {
	positive := false
	for _, pattern := range patterns {
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = strings.TrimPrefix(pattern, "!")
		}
		matched, err := path.Match(pattern, alias)
		if err != nil || !matched {
			continue
		}
		if negated {
			return false
		}
		positive = true
	}
	return positive
}

// readSSHConfigLines expands Include directives textually, with cycle and
// depth guards. Relative includes are resolved next to the including file,
// which is predictable for an explicitly selected import file.
func readSSHConfigLines(name string, depth int, active map[string]bool) ([]string, error) {
	if depth > 16 {
		return nil, fmt.Errorf("ssh config Include depth exceeds 16 at %s", name)
	}
	abs, err := filepath.Abs(config.ExpandPath(name))
	if err != nil {
		return nil, err
	}
	if active[abs] {
		return nil, fmt.Errorf("ssh config Include cycle at %s", abs)
	}
	active[abs] = true
	defer delete(active, abs)
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		key, val := splitConfigLine(strings.TrimSpace(line))
		if !strings.EqualFold(key, "include") {
			out = append(out, line)
			continue
		}
		for _, pattern := range splitWords(val) {
			pattern = config.ExpandPath(pattern)
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(abs), pattern)
			}
			matches, globErr := filepath.Glob(pattern)
			if globErr != nil {
				return nil, fmt.Errorf("invalid ssh Include pattern %q: %w", pattern, globErr)
			}
			sort.Strings(matches)
			for _, match := range matches {
				included, includeErr := readSSHConfigLines(match, depth+1, active)
				if includeErr != nil {
					return nil, includeErr
				}
				out = append(out, included...)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", abs, err)
	}
	return out, nil
}

// splitWords is a small shell-style lexer for config/inventory fields. It
// handles whitespace, single/double quotes, backslash escapes, and comments
// without invoking a shell.
func splitWords(s string) []string {
	var words []string
	var cur strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case '#':
			flush()
			return words
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if escaped {
		cur.WriteByte('\\')
	}
	flush()
	return words
}

func stripInlineComment(s string) string {
	var quote rune
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}
