package config

import (
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestResolveHostUnknownAlias(t *testing.T) {
	c := &Config{Hosts: map[string]HostConfig{}}
	if h, ok := c.ResolveHost("nope"); ok || !reflect.DeepEqual(h, HostConfig{}) {
		t.Fatalf("unknown alias: got (%+v, %v), want (zero, false)", h, ok)
	}
}

func TestResolveHostDefaultPort(t *testing.T) {
	c := &Config{Hosts: map[string]HostConfig{"a": {Host: "1.2.3.4"}}}
	h, ok := c.ResolveHost("a")
	if !ok {
		t.Fatal("expected alias to resolve")
	}
	if h.Port != 22 {
		t.Fatalf("default port: got %d, want 22", h.Port)
	}
}

func TestResolveHostExplicitPortKept(t *testing.T) {
	c := &Config{Hosts: map[string]HostConfig{"a": {Host: "h", Port: 2222}}}
	h, _ := c.ResolveHost("a")
	if h.Port != 2222 {
		t.Fatalf("explicit port: got %d, want 2222", h.Port)
	}
}

func TestResolveHostGroupInheritance(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"web": {User: "deploy", Port: 2200, Key: "~/.ssh/web"},
		},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"web"}},
		},
	}
	h, _ := c.ResolveHost("a")
	if h.User != "deploy" || h.Port != 2200 || h.Key != "~/.ssh/web" {
		t.Fatalf("group inheritance: got user=%q port=%d key=%q", h.User, h.Port, h.Key)
	}
}

func TestResolveHostFieldOverridesGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"web": {User: "deploy", Port: 2200}},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", User: "root", Port: 22, Groups: []string{"web"}},
		},
	}
	h, _ := c.ResolveHost("a")
	if h.User != "root" {
		t.Fatalf("host user should win over group: got %q", h.User)
	}
	if h.Port != 22 {
		t.Fatalf("host port should win over group: got %d", h.Port)
	}
}

func TestResolveHostTagsUnion(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"web": {Tags: []string{"prod"}}},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Tags: []string{"edge"}, Groups: []string{"web"}},
		},
	}
	h, _ := c.ResolveHost("a")
	want := []string{"edge", "prod", "web"} // host tag + group tag + group name, sorted
	if !reflect.DeepEqual(h.Tags, want) {
		t.Fatalf("tags union: got %v, want %v", h.Tags, want)
	}
}

func TestResolveHostMissingGroupIgnored(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"ghost"}},
		},
	}
	h, ok := c.ResolveHost("a")
	if !ok {
		t.Fatal("expected alias to resolve despite missing group")
	}
	if h.Port != 22 {
		t.Fatalf("got port %d, want 22", h.Port)
	}
}

func TestResolveHostPointerFieldMerge(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"mfa": {AutoDuoPush: boolPtr(true)}},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"mfa"}},
		},
	}
	h, _ := c.ResolveHost("a")
	if !h.AutoDuoPush {
		t.Fatal("group AutoDuoPush=true should propagate to host")
	}
}

func TestResolveHostSSHOptionsPrepended(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"g": {SSHOptions: []string{"A=1"}}},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", SSHOptions: []string{"B=2"}, Groups: []string{"g"}},
		},
	}
	h, _ := c.ResolveHost("a")
	want := []string{"A=1", "B=2"} // group options first, host options appended
	if !reflect.DeepEqual(h.SSHOptions, want) {
		t.Fatalf("ssh options: got %v, want %v", h.SSHOptions, want)
	}
}

func TestExpandPath(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	cases := []struct{ in, want string }{
		{"/etc/ssh/config", "/etc/ssh/config"},
		{"relative/path", "relative/path"},
		{"~", usr.HomeDir},
		{"~/.ssh/id_ed25519", filepath.Join(usr.HomeDir, ".ssh/id_ed25519")},
	}
	for _, c := range cases {
		if got := ExpandPath(c.in); got != c.want {
			t.Errorf("ExpandPath(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPathHonorsSSHMGRConfig(t *testing.T) {
	t.Setenv("SSHMGR_CONFIG", "/custom/sshmgr.yaml")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	got, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/custom/sshmgr.yaml" {
		t.Fatalf("SSHMGR_CONFIG should take precedence: got %q", got)
	}
}

func TestPathFallsBackToXDG(t *testing.T) {
	t.Setenv("SSHMGR_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	got, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/xdg", "sshmgr", "config.yaml"); got != want {
		t.Fatalf("XDG fallback: got %q, want %q", got, want)
	}
}

func TestResolveTrace(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"prod": {User: "deploy", Key: "~/.ssh/prod"},
		},
		Hosts: map[string]HostConfig{
			"web1": {Host: "10.0.0.1", Groups: []string{"prod"}, ProxyJump: "bastion"},
		},
	}
	fields, ok := c.ResolveTrace("web1")
	if !ok {
		t.Fatal("expected web1 to resolve")
	}
	got := map[string]ResolvedField{}
	for _, f := range fields {
		got[f.Name] = f
	}
	if got["user"].Value != "deploy" || got["user"].Source != "group:prod" {
		t.Errorf("user should be inherited from prod: %+v", got["user"])
	}
	if got["key"].Source != "group:prod" {
		t.Errorf("key should be inherited from prod: %+v", got["key"])
	}
	if got["proxy_jump"].Value != "bastion" || got["proxy_jump"].Source != "host" {
		t.Errorf("proxy_jump is set on the host: %+v", got["proxy_jump"])
	}
	if _, ok := got["proxy_command"]; ok {
		t.Error("proxy_command is set nowhere — it should be omitted")
	}
	if _, ok := c.ResolveTrace("nope"); ok {
		t.Error("an unknown alias should return ok=false")
	}
}

func TestResolveHostDropsSelfReferentialProxyCommand(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"fleet": {ProxyCommand: "ssh bastion-eu -W %h:%p"},
		},
		Hosts: map[string]HostConfig{
			// bastion-eu is the jump host itself — the proxy targets its alias
			// even though its Host field differs.
			"bastion-eu": {Host: "10.0.0.1", Groups: []string{"fleet"}},
			"behind":     {Host: "10.0.0.2", Groups: []string{"fleet"}},
		},
	}
	if h, _ := c.ResolveHost("bastion-eu"); h.ProxyCommand != "" {
		t.Errorf("bastion-eu routes through itself — proxy_command must be dropped, got %q", h.ProxyCommand)
	}
	if h, _ := c.ResolveHost("behind"); h.ProxyCommand != "ssh bastion-eu -W %h:%p" {
		t.Errorf("behind sits behind the jump — proxy_command must be kept, got %q", h.ProxyCommand)
	}
}

func TestResolveHostDropsSelfReferentialProxyJump(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"g": {ProxyJump: "bastion"}},
		Hosts: map[string]HostConfig{
			"bastion": {Host: "bastion", Groups: []string{"g"}},
			"web":     {Host: "10.0.0.9", Groups: []string{"g"}},
		},
	}
	if h, _ := c.ResolveHost("bastion"); h.ProxyJump != "" {
		t.Errorf("bastion's proxy_jump points at itself — must be dropped, got %q", h.ProxyJump)
	}
	if h, _ := c.ResolveHost("web"); h.ProxyJump != "bastion" {
		t.Errorf("web sits behind bastion — proxy_jump must be kept, got %q", h.ProxyJump)
	}
}

func TestResolveHostSetsAlias(t *testing.T) {
	c := &Config{Hosts: map[string]HostConfig{"web1": {Host: "10.0.0.1"}}}
	h, ok := c.ResolveHost("web1")
	if !ok || h.Alias != "web1" {
		t.Fatalf("ResolveHost must set Alias: ok=%v alias=%q", ok, h.Alias)
	}
}

func TestExtractSSHJumpAlias(t *testing.T) {
	cases := map[string]string{
		"ssh bastion-eu -W %h:%p":     "bastion-eu",
		"ssh -W %h:%p bastion-eu":     "bastion-eu",
		"ssh -i k.pem -p 22 jump":     "jump",
		"~/.ssh/knock-proxy.sh %h %p": "", // not an `ssh ...` form — never a self-loop
		"":                            "",
	}
	for in, want := range cases {
		if got := ExtractSSHJumpAlias(in); got != want {
			t.Errorf("ExtractSSHJumpAlias(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestResolveHostLoginStepsInheritedFromGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"sbs": {LoginSteps: []LoginStep{{Command: "su - sbsadmin", Expect: "assword"}}},
		},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"sbs"}},
		},
	}
	h, _ := c.ResolveHost("a")
	if len(h.LoginSteps) != 1 || h.LoginSteps[0].Command != "su - sbsadmin" {
		t.Fatalf("group login_steps should propagate to host: got %+v", h.LoginSteps)
	}
}

func TestResolveHostLoginStepsOverrideGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"sbs": {LoginSteps: []LoginStep{{Command: "su - sbsadmin"}}},
		},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"sbs"}, LoginSteps: []LoginStep{{Command: "su - other"}}},
		},
	}
	h, _ := c.ResolveHost("a")
	if len(h.LoginSteps) != 1 || h.LoginSteps[0].Command != "su - other" {
		t.Fatalf("host login_steps should win over group: got %+v", h.LoginSteps)
	}
}

func TestResolveHostLoginStepsNoneExcludesGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"sbs": {LoginSteps: []LoginStep{{Command: "su - sbsadmin"}}},
		},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"sbs"}, LoginStepsNone: true},
		},
	}
	h, _ := c.ResolveHost("a")
	if len(h.LoginSteps) != 0 {
		t.Fatalf("login_steps_none should suppress group inheritance: got %+v", h.LoginSteps)
	}
}

func TestResolveHostLoginStepsAutoUnsetIsNil(t *testing.T) {
	c := &Config{Hosts: map[string]HostConfig{"a": {Host: "h"}}}
	h, _ := c.ResolveHost("a")
	if h.LoginStepsAuto != nil {
		t.Fatalf("unset login_steps_auto should stay nil (consumer defaults to true), got %v", *h.LoginStepsAuto)
	}
}

func TestResolveHostLoginStepsAutoInheritedFromGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"sbs": {LoginStepsAuto: boolPtr(false)}},
		Hosts:  map[string]HostConfig{"a": {Host: "h", Groups: []string{"sbs"}}},
	}
	h, _ := c.ResolveHost("a")
	if h.LoginStepsAuto == nil || *h.LoginStepsAuto != false {
		t.Fatalf("group login_steps_auto=false should propagate, got %v", h.LoginStepsAuto)
	}
}

func TestResolveHostLoginStepsAutoHostOverridesGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"sbs": {LoginStepsAuto: boolPtr(false)}},
		Hosts:  map[string]HostConfig{"a": {Host: "h", Groups: []string{"sbs"}, LoginStepsAuto: boolPtr(true)}},
	}
	h, _ := c.ResolveHost("a")
	if h.LoginStepsAuto == nil || *h.LoginStepsAuto != true {
		t.Fatalf("host login_steps_auto=true should win over group false, got %v", h.LoginStepsAuto)
	}
}

func TestResolveHostKVMInheritedFromGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{
			"sbs": {KVM: &KVMConfig{Host: "{{alias}}-kvm", User: "admin"}},
		},
		Hosts: map[string]HostConfig{"a": {Host: "h", Groups: []string{"sbs"}}},
	}
	h, _ := c.ResolveHost("a")
	if h.KVM == nil || h.KVM.User != "admin" || h.KVM.Host != "{{alias}}-kvm" {
		t.Fatalf("group kvm should propagate to host, got %+v", h.KVM)
	}
}

func TestResolveHostKVMOverridesGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"sbs": {KVM: &KVMConfig{Host: "group-kvm"}}},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"sbs"}, KVM: &KVMConfig{Host: "host-kvm"}},
		},
	}
	h, _ := c.ResolveHost("a")
	if h.KVM == nil || h.KVM.Host != "host-kvm" {
		t.Fatalf("host kvm should win over group, got %+v", h.KVM)
	}
}

func TestResolveHostKVMFieldMerge(t *testing.T) {
	// Group carries the shared credentials; the host supplies only its address
	// (e.g. a Tailscale IP). Both must survive resolution.
	c := &Config{
		Groups: map[string]GroupDefaults{
			"sbs": {KVM: &KVMConfig{User: "admin", PasswordKeyring: "kvm-root"}},
		},
		Hosts: map[string]HostConfig{
			"a": {Host: "h", Groups: []string{"sbs"}, KVM: &KVMConfig{Host: "100.64.0.5"}},
		},
	}
	h, _ := c.ResolveHost("a")
	if h.KVM == nil {
		t.Fatal("kvm should resolve")
	}
	if h.KVM.Host != "100.64.0.5" {
		t.Errorf("host address should come from the host block, got %q", h.KVM.Host)
	}
	if h.KVM.User != "admin" || h.KVM.PasswordKeyring != "kvm-root" {
		t.Errorf("group creds should fill in: got user=%q keyring=%q", h.KVM.User, h.KVM.PasswordKeyring)
	}
}

func TestKVMResolvedHostExpandsPlaceholders(t *testing.T) {
	k := KVMConfig{Host: "{{alias}}-kvm"}
	got := k.ResolvedHost(map[string]string{"alias": "alg00001"})
	if got != "alg00001-kvm" {
		t.Fatalf("ResolvedHost expansion: got %q, want alg00001-kvm", got)
	}
	// Group sharing must not be mutated by resolution (no pointer aliasing surprises).
	if k.Host != "{{alias}}-kvm" {
		t.Fatalf("ResolvedHost must not mutate the receiver, got %q", k.Host)
	}
}

func TestResolveHostEscalateKeyInheritedFromGroup(t *testing.T) {
	c := &Config{
		Groups: map[string]GroupDefaults{"sbs": {EscalateKey: "~"}},
		Hosts:  map[string]HostConfig{"a": {Host: "h", Groups: []string{"sbs"}}},
	}
	h, _ := c.ResolveHost("a")
	if h.EscalateKey != "~" {
		t.Fatalf("group escalate_key should propagate, got %q", h.EscalateKey)
	}
}
