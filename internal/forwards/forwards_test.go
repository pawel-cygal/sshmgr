package forwards

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"sshmgr/internal/config"
)

func TestValidateProfileOK(t *testing.T) {
	cases := []config.ForwardProfile{
		{Alias: "h", Type: "L", Spec: "3000:internal:3000"},
		{Alias: "h", Type: "L", Spec: "127.0.0.1:3000:internal:3000"},
		{Alias: "h", Type: "R", Spec: "8080:localhost:8080"},
		{Alias: "h", Type: "D", Spec: "1080"},
		{Alias: "h", Type: "D", Spec: "127.0.0.1:1080"},
	}
	for _, p := range cases {
		if err := ValidateProfile(p); err != nil {
			t.Errorf("expected %+v to validate; got %v", p, err)
		}
	}
}

func TestValidateProfileErrors(t *testing.T) {
	cases := []struct {
		p    config.ForwardProfile
		want string
	}{
		{config.ForwardProfile{Type: "L", Spec: "3000:h:3000"}, "alias is required"},
		{config.ForwardProfile{Alias: "h", Spec: "3000:h:3000"}, "type is required"},
		{config.ForwardProfile{Alias: "h", Type: "L"}, "spec is required"},
		{config.ForwardProfile{Alias: "h", Type: "X", Spec: "1"}, "is invalid"},
		{config.ForwardProfile{Alias: "h", Type: "L", Spec: "3000:internal"}, "requires spec"},
		{config.ForwardProfile{Alias: "h", Type: "L", Spec: "abc:internal:3000"}, "not a valid port"},
		{config.ForwardProfile{Alias: "h", Type: "D", Spec: "abc"}, "not a valid port"},
	}
	for _, c := range cases {
		err := ValidateProfile(c.p)
		if err == nil {
			t.Errorf("expected %+v to fail validation", c.p)
			continue
		}
		if !contains(err.Error(), c.want) {
			t.Errorf("validate %+v: got %q, want substring %q", c.p, err.Error(), c.want)
		}
	}
}

func TestFileForwardsParseAndError(t *testing.T) {
	dir := t.TempDir()
	good := "forwards:\n  grafana:\n    alias: bastion\n    type: L\n    spec: 3000:grafana.internal:3000\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := "forwards: [bad: yaml: ["
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ForwardsDir: dir}
	out, errs := FileForwards(cfg)
	if len(out) != 1 || out[0].Name != "grafana" || out[0].Source != "file:a.yaml" {
		t.Errorf("expected 1 grafana profile from a.yaml, got %+v", out)
	}
	if len(errs) == 0 {
		t.Error("broken.yaml should surface a parse error")
	}
}

func TestAllInlineWinsOverFile(t *testing.T) {
	dir := t.TempDir()
	body := "forwards:\n  shared:\n    alias: file-host\n    type: L\n    spec: 1:h:1\n"
	if err := os.WriteFile(filepath.Join(dir, "lib.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ForwardsDir: dir,
		Forwards: map[string]config.ForwardProfile{
			"shared": {Alias: "inline-host", Type: "L", Spec: "2:h:2"},
		},
	}
	all := All(cfg)
	if len(all) != 1 {
		t.Fatalf("expected 1 merged profile, got %d", len(all))
	}
	if all[0].Alias != "inline-host" || all[0].Source != "inline" {
		t.Errorf("inline must override file on name collision: got %+v", all[0])
	}
}

func TestForAliasFiltersByHost(t *testing.T) {
	cfg := &config.Config{
		Forwards: map[string]config.ForwardProfile{
			"grafana": {Alias: "bastion", Type: "L", Spec: "3000:g:3000"},
			"pg":      {Alias: "db-bastion", Type: "L", Spec: "15432:db:5432"},
			"socks":   {Alias: "bastion", Type: "D", Spec: "1080"},
		},
	}
	got := ForAlias(cfg, "bastion")
	names := make([]string, 0, len(got))
	for _, r := range got {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"grafana", "socks"}) {
		t.Errorf("ForAlias(bastion): got %v, want [grafana socks]", names)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
