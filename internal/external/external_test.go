package external

import (
	"reflect"
	"strings"
	"testing"

	"sshmgr/internal/config"
)

func TestTarget(t *testing.T) {
	if got := Target(config.HostConfig{Host: "h"}); got != "h" {
		t.Errorf("no user: got %q, want h", got)
	}
	if got := Target(config.HostConfig{Host: "h", User: "u"}); got != "u@h" {
		t.Errorf("with user: got %q, want u@h", got)
	}
}

func TestSSHArgvMinimal(t *testing.T) {
	got := SSHArgv(config.HostConfig{Host: "h.example.com"})
	if !reflect.DeepEqual(got, []string{"h.example.com"}) {
		t.Fatalf("minimal: got %v, want [h.example.com]", got)
	}
}

func TestSSHArgvFull(t *testing.T) {
	h := config.HostConfig{
		Host:       "h.example.com",
		User:       "deploy",
		Port:       2222,
		Key:        "/keys/id",
		ProxyJump:  "bastion",
		SSHOptions: []string{"StrictHostKeyChecking=no", "-o BatchMode=yes"},
	}
	want := []string{
		"-i", "/keys/id",
		"-p", "2222",
		"-J", "bastion",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"deploy@h.example.com",
	}
	if got := SSHArgv(h); !reflect.DeepEqual(got, want) {
		t.Fatalf("full ssh argv:\n got  %v\n want %v", got, want)
	}
}

func TestSSHArgvDefaultPortOmitted(t *testing.T) {
	for _, a := range SSHArgv(config.HostConfig{Host: "h", Port: 22, User: "u"}) {
		if a == "-p" {
			t.Fatal("port 22 should not emit -p")
		}
	}
}

func TestProxyCommandWinsOverJump(t *testing.T) {
	h := config.HostConfig{
		Host:         "h",
		ProxyJump:    "bastion",
		ProxyCommand: "nc -X connect %h %p",
	}
	joined := strings.Join(SSHArgv(h), " ")
	if strings.Contains(joined, "-J") {
		t.Errorf("-J must not appear when proxy_command is set: %s", joined)
	}
	if !strings.Contains(joined, "ProxyCommand=nc -X connect %h %p") {
		t.Errorf("proxy_command not passed through: %s", joined)
	}
}

func TestSSHCommandArgvRemoteCommand(t *testing.T) {
	got := SSHCommandArgv(config.HostConfig{Host: "h", User: "u", Port: 2222}, "uptime", false)
	want := []string{"-p", "2222", "u@h", "uptime"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remote command argv:\n got  %v\n want %v", got, want)
	}
}

func TestSSHCommandArgvForceTTY(t *testing.T) {
	got := SSHCommandArgv(config.HostConfig{Host: "h"}, "top", true)
	if len(got) == 0 || got[0] != "-t" {
		t.Fatalf("forceTTY should prepend -t: %v", got)
	}
	if got[len(got)-1] != "top" {
		t.Errorf("remote command should be the last arg: %v", got)
	}
}

func TestSSHCommandArgvInteractiveEqualsSSHArgv(t *testing.T) {
	h := config.HostConfig{Host: "h", User: "u", Key: "/k"}
	if got := SSHCommandArgv(h, "", false); !reflect.DeepEqual(got, SSHArgv(h)) {
		t.Fatalf("empty command should equal SSHArgv: %v vs %v", got, SSHArgv(h))
	}
}

func TestSFTPArgvUsesCapitalPortFlag(t *testing.T) {
	got := SFTPArgv(config.HostConfig{Host: "h", User: "u", Port: 2222})
	want := []string{"-P", "2222", "u@h"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sftp argv:\n got  %v\n want %v", got, want)
	}
}

func TestFwdArgv(t *testing.T) {
	got := FwdArgv(config.HostConfig{Host: "h", User: "u"}, "-L", "8080:localhost:80")
	want := []string{"-N", "-L", "8080:localhost:80", "u@h"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fwd argv:\n got  %v\n want %v", got, want)
	}
}

func TestFwdArgvDynamicWithOptions(t *testing.T) {
	got := FwdArgv(config.HostConfig{Host: "h", Port: 2222}, "-D", "1080")
	want := []string{"-N", "-D", "1080", "-p", "2222", "h"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dynamic fwd argv:\n got  %v\n want %v", got, want)
	}
}

func TestSCPArgvRewritesAliasSide(t *testing.T) {
	h := config.HostConfig{Host: "10.0.0.1", User: "deploy", Port: 2222}
	got := SCPArgv(h, "web1", "web1:/etc/nginx.conf", "/tmp/nginx.conf", false)
	want := []string{"-P", "2222", "deploy@10.0.0.1:/etc/nginx.conf", "/tmp/nginx.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scp argv:\n got  %v\n want %v", got, want)
	}
}

func TestSCPArgvRecursiveUpload(t *testing.T) {
	h := config.HostConfig{Host: "h", User: "u"}
	got := SCPArgv(h, "box", "/local/dir", "box:/srv/app", true)
	want := []string{"-r", "/local/dir", "u@h:/srv/app"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recursive scp argv:\n got  %v\n want %v", got, want)
	}
}

func TestRewriteRemoteSpec(t *testing.T) {
	cases := []struct{ spec, alias, target, want string }{
		{"web1:/etc/foo", "web1", "u@h", "u@h:/etc/foo"},
		{"web1:", "web1", "u@h", "u@h:"},
		{"/local/path", "web1", "u@h", "/local/path"},
		{"other:/x", "web1", "u@h", "other:/x"},
	}
	for _, c := range cases {
		if got := RewriteRemoteSpec(c.spec, c.alias, c.target); got != c.want {
			t.Errorf("RewriteRemoteSpec(%q,%q,%q): got %q, want %q",
				c.spec, c.alias, c.target, got, c.want)
		}
	}
}

func TestWithoutOption(t *testing.T) {
	h := config.HostConfig{SSHOptions: []string{"BatchMode=no", "-o batchmode=yes", "Foo=bar"}}
	got := withoutOption(h, "BatchMode").SSHOptions
	if !reflect.DeepEqual(got, []string{"Foo=bar"}) {
		t.Errorf("withoutOption: got %v, want [Foo=bar]", got)
	}
	// the caller's slice must not be mutated
	if len(h.SSHOptions) != 3 {
		t.Errorf("withoutOption mutated the caller's slice: %v", h.SSHOptions)
	}
}

func TestCapturedArgvPinsBatchMode(t *testing.T) {
	h := config.HostConfig{
		Host:       "h",
		SSHOptions: []string{"BatchMode=no", "StrictHostKeyChecking=no"},
	}
	argv := capturedArgv(h, "uptime")
	// The pinned BatchMode=yes must lead the argv so ssh resolves it first...
	if len(argv) < 2 || argv[0] != "-o" || argv[1] != "BatchMode=yes" {
		t.Fatalf("BatchMode=yes should lead the argv: %v", argv)
	}
	joined := strings.Join(argv, " ")
	// ...and the user's BatchMode=no must be gone entirely.
	if strings.Contains(joined, "BatchMode=no") {
		t.Errorf("user BatchMode=no should be stripped: %v", argv)
	}
	// other ssh_options survive, and the command is last.
	if !strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Errorf("non-BatchMode ssh_options should be preserved: %v", argv)
	}
	if argv[len(argv)-1] != "uptime" {
		t.Errorf("command should be the last arg: %v", argv)
	}
}

func TestAliases(t *testing.T) {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{
		"native1": {Host: "1"},
		"ext1":    {Host: "2", External: true},
		"native2": {Host: "3"},
		"ext2":    {Host: "4", External: true},
	}}
	got := Aliases(cfg, []string{"native1", "ext1", "native2", "ext2", "missing"})
	want := []string{"ext1", "ext2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Aliases: got %v, want %v", got, want)
	}
	if ext := Aliases(cfg, []string{"native1", "native2"}); len(ext) != 0 {
		t.Errorf("no external hosts should yield empty, got %v", ext)
	}
}
