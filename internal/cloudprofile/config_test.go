package cloudprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useProfilePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloud.json")
	t.Setenv("SSHMGR_CLOUD_CONFIG", path)
	return path
}

func TestProfileLifecycleIsPrivateStrictAndTokenFree(t *testing.T) {
	path := useProfilePath(t)
	profile := Profile{Endpoint: "https://cloud.example.test", Workspace: "client-a", TokenKeyring: TokenKey("prod")}
	written, err := Update(func(config *Config) error { return Upsert(config, "prod", profile, true) })
	if err != nil || written != path {
		t.Fatalf("update path=%q err=%v", written, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile mode=%v err=%v", info, err)
	}
	lockInfo, err := os.Stat(path + ".lock")
	if err != nil || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("profile lock mode=%v err=%v", lockInfo, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "bearer") || strings.Contains(string(data), "secret-token") {
		t.Fatal("profile config contains token material")
	}
	config, loadedPath, err := Load()
	name, loaded, resolveErr := Resolve(config, "")
	if err != nil || resolveErr != nil || loadedPath != path || name != "prod" || loaded != profile {
		t.Fatalf("load=%+v path=%q name=%q profile=%+v err=%v/%v", config, loadedPath, name, loaded, err, resolveErr)
	}
	if _, err := Update(func(config *Config) error { return SetWorkspace(config, "prod", "client-b") }); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(func(config *Config) error {
		if err := Upsert(config, "staging", Profile{Endpoint: "https://staging.example.test", Workspace: "staging", TokenKeyring: TokenKey("staging")}, false); err != nil {
			return err
		}
		return SetActive(config, "staging")
	}); err != nil {
		t.Fatal(err)
	}
	config, _, _ = Load()
	if config.ActiveProfile != "staging" || config.Profiles["prod"].Workspace != "client-b" || len(config.Profiles) != 2 {
		t.Fatalf("updated config=%+v", config)
	}
}

func TestProfilesRejectUnsafeOrAmbiguousConfiguration(t *testing.T) {
	path := useProfilePath(t)
	invalid := []Profile{
		{Endpoint: "http://example.test", Workspace: "client-a", TokenKeyring: "key"},
		{Endpoint: "http://localhost:8787", Workspace: "client-a", TokenKeyring: "key", AllowInsecureLoopback: true},
		{Endpoint: "https://example.test/path", Workspace: "client-a", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Workspace: "Client A", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Workspace: "client-a", TokenKeyring: " bad "},
	}
	for _, profile := range invalid {
		config := NewConfig()
		config.Profiles["prod"] = profile
		config.ActiveProfile = "prod"
		if err := Validate(config); err == nil {
			t.Fatalf("invalid profile accepted: %+v", profile)
		}
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"1","profiles":{},"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field accepted: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("public config accepted: %v", err)
	}
	realPath := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(realPath, []byte(`{"schema_version":"1","profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(t.TempDir(), "cloud-link.json")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHMGR_CLOUD_CONFIG", linkPath)
	if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink config accepted: %v", err)
	}
}

func TestProjectProfilesStoreExplicitOrganizationAndProject(t *testing.T) {
	useProfilePath(t)
	profile := Profile{Endpoint: "https://cloud.example.test", Organization: "systeam-demo", Project: "golden-workspace", TokenKeyring: TokenKey("proj")}
	if _, err := Update(func(config *Config) error { return Upsert(config, "proj", profile, true) }); err != nil {
		t.Fatal(err)
	}
	config, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	name, loaded, resolveErr := Resolve(config, "")
	if resolveErr != nil || name != "proj" || loaded != profile {
		t.Fatalf("name=%q profile=%+v err=%v", name, loaded, resolveErr)
	}
	if !loaded.UsesProjectContext() {
		t.Fatal("organization/project profile must report project context")
	}
	legacy := Profile{Endpoint: "https://cloud.example.test", Workspace: "client-a", TokenKeyring: TokenKey("legacy")}
	if legacy.UsesProjectContext() {
		t.Fatal("legacy workspace profile must not report project context")
	}
}

func TestProfilesRejectAmbiguousOrPartialProjectContext(t *testing.T) {
	invalid := []Profile{
		{Endpoint: "https://example.test", Organization: "org-a", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Project: "fleet", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Workspace: "client-a", Organization: "org-a", Project: "fleet", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Workspace: "client-a", Organization: "org-a", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Organization: "Org A", Project: "fleet", TokenKeyring: "key"},
		{Endpoint: "https://example.test", Organization: "org-a", Project: "Fleet A", TokenKeyring: "key"},
		{Endpoint: "https://example.test", TokenKeyring: "key"},
	}
	for _, profile := range invalid {
		config := NewConfig()
		config.Profiles["prod"] = profile
		config.ActiveProfile = "prod"
		if err := Validate(config); err == nil {
			t.Fatalf("invalid project-context profile accepted: %+v", profile)
		}
	}
}

func TestSetProjectMigratesLegacyProfileAndSetWorkspaceRefusesProjectProfile(t *testing.T) {
	useProfilePath(t)
	legacy := Profile{Endpoint: "https://cloud.example.test", Workspace: "client-a", TokenKeyring: TokenKey("prod")}
	if _, err := Update(func(config *Config) error { return Upsert(config, "prod", legacy, true) }); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(func(config *Config) error { return SetProject(config, "prod", "org-a", "fleet") }); err != nil {
		t.Fatal(err)
	}
	config, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	migrated := config.Profiles["prod"]
	if migrated.Organization != "org-a" || migrated.Project != "fleet" || migrated.Workspace != "" {
		t.Fatalf("migrated profile=%+v", migrated)
	}
	if _, err := Update(func(config *Config) error { return SetWorkspace(config, "prod", "client-b") }); err == nil || !strings.Contains(err.Error(), "organization/project") {
		t.Fatalf("SetWorkspace on a project profile must fail with a project-context hint, got %v", err)
	}
	if _, err := Update(func(config *Config) error { return SetProject(config, "prod", "org-a", "") }); err == nil {
		t.Fatal("SetProject must reject an empty project slug")
	}
}

func TestLoopbackProfileRequiresExplicitLiteralOptIn(t *testing.T) {
	config := NewConfig()
	profile := Profile{Endpoint: "http://127.0.0.1:8787", Workspace: "local", TokenKeyring: "local-token", AllowInsecureLoopback: true}
	if err := Upsert(config, "local", profile, true); err != nil {
		t.Fatal(err)
	}
	if _, got, err := Resolve(config, ""); err != nil || got != profile {
		t.Fatalf("resolve=%+v err=%v", got, err)
	}
}
