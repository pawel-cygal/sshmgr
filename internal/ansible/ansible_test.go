package ansible

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sshmgr/internal/config"
)

func TestInventoryUnknownFormat(t *testing.T) {
	if _, err := Inventory(&config.Config{}, nil, "xml"); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestInventoryFieldMapping(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"web1": {Host: "10.0.0.1", User: "deploy", Port: 2222, Key: "/keys/id"},
	}}
	out, err := Inventory(cfg, []string{"web1"}, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ansible_host: 10.0.0.1",
		"ansible_user: deploy",
		"ansible_port: 2222",
		"ansible_ssh_private_key_file: /keys/id",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inventory missing %q\n%s", want, out)
		}
	}
}

func TestInventoryDefaultPortOmitted(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"web1": {Host: "10.0.0.1", Port: 22},
	}}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	if strings.Contains(out, "ansible_port") {
		t.Errorf("port 22 should not be emitted:\n%s", out)
	}
}

func TestInventoryYAMLStructure(t *testing.T) {
	cfg := &config.Config{
		Groups: map[string]config.GroupDefaults{"web": {}},
		Hosts: map[string]config.HostConfig{
			"web1": {Host: "10.0.0.1", Groups: []string{"web"}},
		},
	}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	for _, want := range []string{"all:", "hosts:", "children:", "web:", "web1:"} {
		if !strings.Contains(out, want) {
			t.Errorf("YAML inventory missing %q\n%s", want, out)
		}
	}
}

func TestInventoryINIStructure(t *testing.T) {
	cfg := &config.Config{
		Groups: map[string]config.GroupDefaults{"web": {}},
		Hosts: map[string]config.HostConfig{
			"web1":  {Host: "10.0.0.1", Groups: []string{"web"}},
			"loner": {Host: "10.0.0.9"},
		},
	}
	out, _ := Inventory(cfg, []string{"web1", "loner"}, "ini")
	for _, want := range []string{"[web]", "web1 ansible_host=10.0.0.1", "[ungrouped]", "loner ansible_host=10.0.0.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("INI inventory missing %q\n%s", want, out)
		}
	}
}

func TestInventoryProxyJumpResolved(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"bastion": {Host: "bastion.example.com", User: "jump", Port: 2200},
		"web1":    {Host: "10.0.0.1", User: "deploy", ProxyJump: "bastion"},
	}}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	if !strings.Contains(out, "ProxyJump=jump@bastion.example.com:2200") {
		t.Errorf("proxy_jump alias should resolve to user@host:port\n%s", out)
	}
}

func TestInventoryProxyJumpChain(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"edge":    {Host: "edge.net", User: "e"},
		"bastion": {Host: "b.net", User: "j", ProxyJump: "edge"},
		"web1":    {Host: "10.0.0.1", ProxyJump: "bastion"},
	}}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	if !strings.Contains(out, "ProxyJump=e@edge.net,j@b.net") {
		t.Errorf("multi-hop chain should render outermost-first\n%s", out)
	}
}

func TestInventoryProxyJumpUnknownAlias(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"web1": {Host: "10.0.0.1", ProxyJump: "ssh-config-only"},
	}}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	if !strings.Contains(out, "ProxyJump=ssh-config-only") {
		t.Errorf("an unknown jump alias should pass through verbatim\n%s", out)
	}
}

func TestInventoryProxyCommand(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"web1": {Host: "10.0.0.1", ProxyCommand: "ssh -W %h:%p bastion", ProxyJump: "ignored"},
	}}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	if !strings.Contains(out, `ProxyCommand="ssh -W %h:%p bastion"`) {
		t.Errorf("proxy_command should be emitted quoted\n%s", out)
	}
	if strings.Contains(out, "ProxyJump") {
		t.Errorf("proxy_command must win over proxy_jump\n%s", out)
	}
}

func TestInventoryExternalHost(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"bastion": {Host: "b.net", User: "j"},
		"ext1":    {Host: "ext-alias", User: "u", External: true, Key: "/k", ProxyJump: "bastion"},
	}}
	out, _ := Inventory(cfg, []string{"ext1"}, "yaml")
	if strings.Contains(out, "ansible_ssh_common_args") {
		t.Errorf("external host must not get synthesized ssh args\n%s", out)
	}
	if strings.Contains(out, "ansible_ssh_private_key_file") {
		t.Errorf("external host must not get a key file (ssh-config owns it)\n%s", out)
	}
	if !strings.Contains(out, "ansible_host: ext-alias") || !strings.Contains(out, "ansible_user: u") {
		t.Errorf("external host should still get plain host/user vars\n%s", out)
	}
	if !strings.Contains(out, "external hosts:") {
		t.Errorf("an external host in the set should add the explanatory comment\n%s", out)
	}
}

func TestInventoryTagGroups(t *testing.T) {
	cfg := &config.Config{
		Groups: map[string]config.GroupDefaults{"web": {}},
		Hosts: map[string]config.HostConfig{
			"web1": {Host: "10.0.0.1", Groups: []string{"web"}, Tags: []string{"prod"}},
		},
	}
	out, _ := Inventory(cfg, []string{"web1"}, "yaml")
	if !strings.Contains(out, "tag_prod:") {
		t.Errorf("a tag should become a synthetic tag_ group\n%s", out)
	}
	// The group name itself is an implicit tag — it must not double as tag_web.
	if strings.Contains(out, "tag_web:") {
		t.Errorf("a group name should not be re-emitted as a tag group\n%s", out)
	}
}

func TestPlaybookArgv(t *testing.T) {
	got := PlaybookArgv("deploy.yml", "/tmp/inv.yaml", PlaybookOptions{
		Check: true, Diff: true, Limit: "web", ExtraVars: []string{"a=1", "b=2"},
	})
	want := []string{
		"-i", "/tmp/inv.yaml", "--check", "--diff", "--limit", "web",
		"--extra-vars", "a=1", "--extra-vars", "b=2", "deploy.yml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("playbook argv:\n got  %v\n want %v", got, want)
	}
}

func TestPlaybookArgvMinimal(t *testing.T) {
	got := PlaybookArgv("site.yml", "/i", PlaybookOptions{})
	want := []string{"-i", "/i", "site.yml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("minimal playbook argv: got %v, want %v", got, want)
	}
}

func TestResolvePlaybook(t *testing.T) {
	dir := t.TempDir()
	named := filepath.Join(dir, "deploy.yml")
	if err := os.WriteFile(named, []byte("---"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Bare name resolved under playbooksDir.
	if got, err := ResolvePlaybook("deploy.yml", dir); err != nil || got != named {
		t.Errorf("bare name: got (%q, %v), want (%q, nil)", got, err, named)
	}
	// An existing path is used as-is.
	if got, err := ResolvePlaybook(named, "/nonexistent"); err != nil || got != named {
		t.Errorf("explicit path: got (%q, %v)", got, err)
	}
	// Missing playbook is an error.
	if _, err := ResolvePlaybook("missing.yml", dir); err == nil {
		t.Error("a missing playbook should return an error")
	}
}

func TestDiscoverPlaybooks(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"site.yml", "deploy.yaml", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := DiscoverPlaybooks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"deploy.yaml", "site.yml"}) {
		t.Fatalf("discover: got %v, want [deploy.yaml site.yml]", got)
	}
}

func TestDiscoverPlaybooksMissingDir(t *testing.T) {
	got, err := DiscoverPlaybooks(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("a missing directory should not be an error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a missing directory should yield no playbooks, got %v", got)
	}
}

func TestInventoryExternalJumpHost(t *testing.T) {
	// A proxy_jump that points at an external bastion must be kept as the
	// bastion's ssh-config alias, not flattened to user@host:port — the
	// whole point of `external` is that ssh-config owns its connection.
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"bastion": {Host: "bastion-alias", User: "j", Port: 2200, External: true},
		"web1":    {Host: "10.0.0.1", ProxyJump: "bastion"},
	}}
	out, err := Inventory(cfg, []string{"web1"}, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ProxyJump=bastion-alias") {
		t.Errorf("external bastion should stay as its ssh-config alias\n%s", out)
	}
	if strings.Contains(out, "j@bastion-alias") {
		t.Errorf("external bastion must not be flattened to user@host:port\n%s", out)
	}
}

func TestInventoryExternalJumpInChain(t *testing.T) {
	// chain: web1 -> mid (native) -> bastion (external). The external hop
	// stays an alias; the native hop is still expanded.
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"bastion": {Host: "b-alias", External: true},
		"mid":     {Host: "mid.net", User: "m", ProxyJump: "bastion"},
		"web1":    {Host: "10.0.0.1", ProxyJump: "mid"},
	}}
	out, err := Inventory(cfg, []string{"web1"}, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ProxyJump=b-alias,m@mid.net") {
		t.Errorf("chain should keep the external hop as an alias, expand the native one\n%s", out)
	}
}

func TestInventoryProxyJumpCycle(t *testing.T) {
	// A proxy_jump cycle must be a hard error, not a silently jump-less
	// inventory that points Ansible straight at the target.
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"a": {Host: "a.net", ProxyJump: "b"},
		"b": {Host: "b.net", ProxyJump: "a"},
	}}
	if _, err := Inventory(cfg, []string{"a"}, "yaml"); err == nil {
		t.Fatal("expected an error for a proxy_jump cycle")
	}
}
