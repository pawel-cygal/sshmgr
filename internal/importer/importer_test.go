package importer

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"sshmgr/internal/config"
)

func newCfg() *config.Config {
	return &config.Config{Hosts: map[string]config.HostConfig{}}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp %s: %v", name, err)
	}
	return p
}

func TestSSHConfigImport(t *testing.T) {
	body := `Host web1
    HostName 10.0.0.1
    User deploy
    Port 2200
    IdentityFile ~/.ssh/id_web

Host *
    User nobody

Host bastion
    HostName bastion.example.com
    ProxyJump web1

Match host nas
    User leaked

Host plain
`
	cfg := newCfg()
	r, err := SSHConfig(cfg, writeTemp(t, "ssh_config", body), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bastion", "plain", "web1"} // wildcard "*" excluded
	if !reflect.DeepEqual(r.Added, want) {
		t.Fatalf("added: got %v, want %v", r.Added, want)
	}
	if h := cfg.Hosts["web1"]; h.Host != "10.0.0.1" || h.User != "deploy" || h.Port != 2200 || h.Key != "~/.ssh/id_web" {
		t.Errorf("web1 fields wrong: %+v", h)
	}
	if h := cfg.Hosts["bastion"]; h.ProxyJump != "web1" {
		t.Errorf("bastion ProxyJump: got %q, want web1", h.ProxyJump)
	}
	// No HostName → connect to the alias itself.
	if h := cfg.Hosts["plain"]; h.Host != "plain" {
		t.Errorf("plain Host: got %q, want plain", h.Host)
	}
	// The Match block must close the preceding Host block: its `User leaked`
	// directive must not bleed into `plain`.
	if h := cfg.Hosts["plain"]; h.User == "leaked" {
		t.Error("Match-block directive leaked into a later host")
	}
}

func TestSSHConfigOnlyFilter(t *testing.T) {
	body := "Host web1\n  HostName a\nHost web2\n  HostName b\nHost db1\n  HostName c\n"
	cfg := newCfg()
	r, err := SSHConfig(cfg, writeTemp(t, "ssh_config", body), "", []string{"web*"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"web1", "web2"}
	if !reflect.DeepEqual(r.Added, want) {
		t.Fatalf("only filter: got %v, want %v", r.Added, want)
	}
}

func TestSSHConfigGroupAssigned(t *testing.T) {
	body := "Host h1\n  HostName a\n"
	cfg := newCfg()
	r, err := SSHConfig(cfg, writeTemp(t, "ssh_config", body), "lab", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Hosts["h1"].Groups; !reflect.DeepEqual(got, []string{"lab"}) {
		t.Errorf("group: got %v, want [lab]", got)
	}
	if _, ok := cfg.Groups["lab"]; !ok {
		t.Error("group lab should be created in cfg.Groups")
	}
	if !reflect.DeepEqual(r.Groups, []string{"lab"}) {
		t.Errorf("result groups: got %v", r.Groups)
	}
}

func TestSSHConfigSkipsExisting(t *testing.T) {
	body := "Host dup\n  HostName a\n"
	cfg := newCfg()
	cfg.Hosts["dup"] = config.HostConfig{Host: "preexisting"}
	r, err := SSHConfig(cfg, writeTemp(t, "ssh_config", body), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Added) != 0 || !reflect.DeepEqual(r.Skipped, []string{"dup"}) {
		t.Fatalf("existing alias: added=%v skipped=%v", r.Added, r.Skipped)
	}
	if cfg.Hosts["dup"].Host != "preexisting" {
		t.Error("import must not overwrite an existing alias")
	}
}

func TestAnsibleImport(t *testing.T) {
	body := `[web]
node1 ansible_host=10.0.0.10 ansible_user=ubuntu ansible_port=2022
node2 ansible_host=10.0.0.11

[web:vars]
ansible_user=deploy
ansible_port=2200
`
	cfg := newCfg()
	r, err := Ansible(cfg, writeTemp(t, "inventory.ini", body))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Added, []string{"node1", "node2"}) {
		t.Fatalf("added: got %v", r.Added)
	}
	if h := cfg.Hosts["node1"]; h.Host != "10.0.0.10" || h.User != "ubuntu" || h.Port != 2022 {
		t.Errorf("node1 fields wrong: %+v", h)
	}
	if g := cfg.Hosts["node1"].Groups; !reflect.DeepEqual(g, []string{"web"}) {
		t.Errorf("node1 group: got %v", g)
	}
	if g := cfg.Groups["web"]; g.User != "deploy" || g.Port != 2200 {
		t.Errorf("group vars not folded: %+v", g)
	}
}

func TestHostsImport(t *testing.T) {
	body := `127.0.0.1 localhost
10.0.0.5 server1 server1.local
::1 ip6-localhost ip6-loopback
10.0.0.6 db
`
	cfg := newCfg()
	r, err := Hosts(cfg, writeTemp(t, "hosts", body), "")
	if err != nil {
		t.Fatal(err)
	}
	got := append([]string{}, r.Added...)
	sort.Strings(got)
	want := []string{"db", "server1", "server1.local"} // localhost + ip6-* skipped
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("added: got %v, want %v", got, want)
	}
	if cfg.Hosts["server1"].Host != "10.0.0.5" {
		t.Errorf("server1 Host: got %q", cfg.Hosts["server1"].Host)
	}
}

func TestSplitConfigLine(t *testing.T) {
	cases := []struct{ in, wantK, wantV string }{
		{"User deploy", "User", "deploy"},
		{"User=deploy", "User", "deploy"},
		{"Port  2200", "Port", "2200"},
		{`HostName "my host"`, "HostName", "my host"},
		{"Compression", "Compression", ""},
	}
	for _, c := range cases {
		k, v := splitConfigLine(c.in)
		if k != c.wantK || v != c.wantV {
			t.Errorf("splitConfigLine(%q): got (%q,%q), want (%q,%q)", c.in, k, v, c.wantK, c.wantV)
		}
	}
}

func TestAnsibleKV(t *testing.T) {
	cases := []struct{ in, wantK, wantV string }{
		{"ansible_host=10.0.0.1", "ansible_host", "10.0.0.1"},
		{`ansible_user="bob"`, "ansible_user", "bob"},
		{"ansible_user='bob'", "ansible_user", "bob"},
		{"novalue", "novalue", ""},
	}
	for _, c := range cases {
		k, v := ansibleKV(c.in)
		if k != c.wantK || v != c.wantV {
			t.Errorf("ansibleKV(%q): got (%q,%q), want (%q,%q)", c.in, k, v, c.wantK, c.wantV)
		}
	}
}

func TestMatchesOnly(t *testing.T) {
	cases := []struct {
		only  []string
		alias string
		want  bool
	}{
		{nil, "anything", true},
		{[]string{}, "anything", true},
		{[]string{"web*"}, "web1", true},
		{[]string{"web*"}, "db1", false},
		{[]string{"a", "b*"}, "bx", true},
		{[]string{"a", "b*"}, "cx", false},
	}
	for _, c := range cases {
		if got := matchesOnly(c.only, c.alias); got != c.want {
			t.Errorf("matchesOnly(%v, %q): got %v, want %v", c.only, c.alias, got, c.want)
		}
	}
}
