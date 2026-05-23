package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sshmgr/internal/config"

	"github.com/zalando/go-keyring"
)

func TestExpand(t *testing.T) {
	vars := map[string]string{"alias": "web01", "host": "10.0.0.1"}
	cases := map[string]string{
		"op://Private/{{alias}}/password": "op://Private/web01/password",
		"{{alias}}@{{host}}":              "web01@10.0.0.1",
		"no placeholders here":            "no placeholders here",
		"{{unknown}} stays":               "{{unknown}} stays",
	}
	for in, want := range cases {
		if got := expand(in, vars); got != want {
			t.Errorf("expand(%q): got %q, want %q", in, got, want)
		}
	}
	if got := expand("{{alias}}", nil); got != "{{alias}}" {
		t.Errorf("nil vars must be a no-op, got %q", got)
	}
}

func TestResolveSpecCmdSubstitutes(t *testing.T) {
	got, err := ResolveSpec(Spec{
		Cmd:  "echo pw-{{alias}}-{{host}}",
		Vars: map[string]string{"alias": "web01", "host": "10.0.0.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "pw-web01-10.0.0.9" {
		t.Errorf("password_cmd placeholders not expanded: got %q", got)
	}
}

func TestResolveSpecKeyringSubstitutes(t *testing.T) {
	keyring.MockInit()
	if err := keyring.Set(KeyringService, "db-master", "kr-secret"); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSpec(Spec{Keyring: "{{alias}}", Vars: map[string]string{"alias": "db-master"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "kr-secret" {
		t.Errorf("password_keyring placeholder not expanded: got %q", got)
	}
}

func TestResolveHostPasswordSubstitutesAlias(t *testing.T) {
	got, err := ResolveHostPassword(config.HostConfig{
		Alias: "db-replica", Host: "10.0.0.5", PasswordCmd: "echo secret-for-{{alias}}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret-for-db-replica" {
		t.Errorf("ResolveHostPassword must expand {{alias}}: got %q", got)
	}
}

func TestResolveStepSubstitutesAlias(t *testing.T) {
	got, err := Resolve(
		config.LoginStep{Command: "su - deployer", PasswordCmd: "echo step-{{alias}}"},
		config.HostConfig{Alias: "web03", Host: "10.0.0.3"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != "step-web03" {
		t.Errorf("login-step password_cmd must expand {{alias}}: got %q", got)
	}
}

func TestPasswordCmdRunsOncePerProcess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	// Each run appends a line to marker, then prints the password.
	cmd := fmt.Sprintf("echo x >> %s; echo cached-secret", marker)
	for i := 0; i < 3; i++ {
		got, err := ResolveSpec(Spec{Cmd: cmd})
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if got != "cached-secret" {
			t.Fatalf("resolve %d: got %q", i, got)
		}
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Errorf("password_cmd must run once then cache; ran %d times", n)
	}
}

func TestPasswordCmdSingleflightDedupesConcurrent(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	// The sleep widens the window so a naive cache would let several
	// concurrent callers all run the command.
	cmd := fmt.Sprintf("sleep 0.1; echo x >> %s; echo sf-secret", marker)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := ResolveSpec(Spec{Cmd: cmd})
			if err != nil || got != "sf-secret" {
				t.Errorf("concurrent resolve: got %q err %v", got, err)
			}
		}()
	}
	wg.Wait()
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Errorf("singleflight must collapse concurrent calls to one run; ran %d times", n)
	}
}
