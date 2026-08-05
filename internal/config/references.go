package config

import (
	"sort"
	"strings"
)

// AliasReferences lists declarative objects that would become broken if alias
// were removed. Callers use it to block destructive deletion until the user
// explicitly rewrites those access paths/profiles.
func (c *Config) AliasReferences(alias string) []string {
	var refs []string
	for name, h := range c.Hosts {
		if name == alias {
			continue
		}
		if jumpChainContains(h.ProxyJump, alias) || ExtractSSHJumpAlias(h.ProxyCommand) == alias {
			refs = append(refs, "host "+name)
		}
	}
	for name, g := range c.Groups {
		if jumpChainContains(g.ProxyJump, alias) || ExtractSSHJumpAlias(g.ProxyCommand) == alias {
			refs = append(refs, "group "+name)
		}
	}
	for name, profile := range c.Forwards {
		if profile.Alias == alias {
			refs = append(refs, "forward "+name)
		}
	}
	sort.Strings(refs)
	return refs
}

func jumpChainContains(chain, alias string) bool {
	for _, part := range strings.Split(chain, ",") {
		if strings.TrimSpace(part) == alias {
			return true
		}
	}
	return false
}
