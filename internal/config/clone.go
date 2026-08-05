package config

// Clone returns a deep-enough independent configuration snapshot for an
// edit-then-save transaction. Runtime source/CAS metadata is preserved, while
// maps, slices, nested KVM blocks and presence maps no longer alias the source.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Hosts = make(map[string]HostConfig, len(c.Hosts))
	for name, h := range c.Hosts {
		out.Hosts[name] = cloneHost(h)
	}
	out.Groups = make(map[string]GroupDefaults, len(c.Groups))
	for name, g := range c.Groups {
		out.Groups[name] = cloneGroup(g)
	}
	out.Forwards = make(map[string]ForwardProfile, len(c.Forwards))
	for name, profile := range c.Forwards {
		out.Forwards[name] = profile
	}
	out.ForwardHistory = append([]ForwardEntry(nil), c.ForwardHistory...)
	out.TransferHistory = append([]TransferEntry(nil), c.TransferHistory...)
	out.LoginHistory = append([]LoginEntry(nil), c.LoginHistory...)
	return &out
}

func cloneHost(h HostConfig) HostConfig {
	h.setFields = cloneStringBoolMap(h.setFields)
	h.Groups = append([]string(nil), h.Groups...)
	h.Tags = append([]string(nil), h.Tags...)
	h.LoginSteps = append([]LoginStep(nil), h.LoginSteps...)
	h.Commands = append([]string(nil), h.Commands...)
	h.Snippets = cloneSnippets(h.Snippets)
	h.SSHOptions = append([]string(nil), h.SSHOptions...)
	h.LoginStepsAuto = cloneBool(h.LoginStepsAuto)
	h.KVM = cloneKVM(h.KVM)
	return h
}

func cloneGroup(g GroupDefaults) GroupDefaults {
	g.PasswordPrompt = cloneBool(g.PasswordPrompt)
	g.AutoDuoPush = cloneBool(g.AutoDuoPush)
	g.AutoAcceptHostKey = cloneBool(g.AutoAcceptHostKey)
	g.LoginSteps = append([]LoginStep(nil), g.LoginSteps...)
	g.LoginStepsAuto = cloneBool(g.LoginStepsAuto)
	g.KVM = cloneKVM(g.KVM)
	g.Tags = append([]string(nil), g.Tags...)
	g.ForwardAgent = cloneBool(g.ForwardAgent)
	g.SSHOptions = append([]string(nil), g.SSHOptions...)
	g.Snippets = cloneSnippets(g.Snippets)
	g.SessionLog = cloneBool(g.SessionLog)
	return g
}

func cloneKVM(k *KVMConfig) *KVMConfig {
	if k == nil {
		return nil
	}
	out := *k
	out.setFields = cloneStringBoolMap(k.setFields)
	out.Insecure = cloneBool(k.Insecure)
	return &out
}

func cloneSnippets(in []Snippet) []Snippet {
	out := append([]Snippet(nil), in...)
	for i := range out {
		out[i].Tags = append([]string(nil), out[i].Tags...)
	}
	return out
}

func cloneBool(in *bool) *bool {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneStringBoolMap(in map[string]bool) map[string]bool {
	if in == nil {
		return nil
	}
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
