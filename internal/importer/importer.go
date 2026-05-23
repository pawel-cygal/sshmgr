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
	"sort"
	"strings"

	"sshmgr/internal/config"
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
	f, err := os.Open(config.ExpandPath(cfgPath))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cfgPath, err)
	}
	defer f.Close()

	r := &Result{}
	type block struct {
		aliases []string
		fields  map[string]string
	}
	var cur *block
	flush := func() {
		if cur == nil {
			return
		}
		for _, alias := range cur.aliases {
			if strings.ContainsAny(alias, "*?!") {
				continue // wildcard / negated pattern — not a concrete host
			}
			if !matchesOnly(only, alias) {
				continue
			}
			h := config.HostConfig{Host: cur.fields["hostname"]}
			if h.Host == "" {
				h.Host = alias // no HostName → connect to the alias itself
			}
			h.User = cur.fields["user"]
			if p := cur.fields["port"]; p != "" {
				fmt.Sscanf(p, "%d", &h.Port)
			}
			h.Key = cur.fields["identityfile"]
			h.ProxyJump = cur.fields["proxyjump"]
			h.ProxyCommand = cur.fields["proxycommand"]
			if group != "" {
				h.Groups = []string{group}
			}
			addHost(cfg, r, alias, h)
		}
		cur = nil
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val := splitConfigLine(line)
		lkey := strings.ToLower(key)
		if lkey == "host" {
			flush()
			cur = &block{aliases: strings.Fields(val), fields: map[string]string{}}
			continue
		}
		if lkey == "match" {
			// A Match block ends the current Host block — close it and drop
			// the Match's directives (otherwise they'd bleed into the
			// preceding Host's fields).
			flush()
			cur = nil
			continue
		}
		if cur == nil {
			continue // inside a Match block or a pre-Host directive — ignore
		}
		switch lkey {
		case "hostname", "user", "port", "proxyjump", "proxycommand":
			cur.fields[lkey] = val
		case "identityfile":
			// keep only the first IdentityFile
			if cur.fields["identityfile"] == "" {
				cur.fields["identityfile"] = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
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
// is flattened (children's hosts also join the parent group's name only via
// their own section). Host lines map ansible_host/user/port/private_key_file.
func Ansible(cfg *config.Config, invPath string) (*Result, error) {
	f, err := os.Open(config.ExpandPath(invPath))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", invPath, err)
	}
	defer f.Close()

	r := &Result{}
	groupSet := map[string]bool{}
	section := ""    // current [section]
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
			if sectionKind == "" {
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
			// nested groups — ensure they exist; their own [section] handles hosts.
			groupSet[line] = true
			ensureGroup(cfg, strings.Fields(line)[0])
		default:
			// host line: "name key=val key=val"
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			alias := fields[0]
			h := config.HostConfig{Host: alias}
			for _, kv := range fields[1:] {
				k, v := ansibleKV(kv)
				switch k {
				case "ansible_host", "ansible_ssh_host":
					h.Host = v
				case "ansible_user", "ansible_ssh_user":
					h.User = v
				case "ansible_port", "ansible_ssh_port":
					fmt.Sscanf(v, "%d", &h.Port)
				case "ansible_ssh_private_key_file", "ansible_private_key_file":
					h.Key = v
				}
			}
			if section != "" {
				h.Groups = []string{section}
			}
			addHost(cfg, r, alias, h)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
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
		g.User = v
	case "ansible_port", "ansible_ssh_port":
		fmt.Sscanf(v, "%d", &g.Port)
	case "ansible_ssh_private_key_file", "ansible_private_key_file":
		g.Key = v
	}
	cfg.Groups[group] = g
}

// splitConfigLine splits an ssh_config line into key and value, handling both
// "Key value" and "Key=value" forms.
func splitConfigLine(line string) (key, val string) {
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
