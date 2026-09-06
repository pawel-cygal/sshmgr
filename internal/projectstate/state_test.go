package projectstate

import (
	"path/filepath"
	"testing"
)

func TestResolveKeepsRuntimeStateFileSeparate(t *testing.T) {
	temp := t.TempDir()
	runtimeState := filepath.Join(temp, "runtime", "state.yaml")
	cloudState := filepath.Join(temp, "cloud-state")
	t.Setenv("SSHMGR_STATE", runtimeState)
	t.Setenv("SSHMGR_CLOUD_STATE", cloudState)
	t.Setenv("XDG_STATE_HOME", filepath.Join(temp, "xdg-state"))

	paths, err := Resolve(Context{Organization: "acme", Project: "production"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cloudState, "projects", "acme", "production")
	if paths.Root != want {
		t.Fatalf("project root = %q, want %q", paths.Root, want)
	}
	if paths.Root == runtimeState || filepath.Dir(paths.Root) == runtimeState {
		t.Fatalf("runtime state file leaked into project root: %q", paths.Root)
	}
}

func TestResolveUsesPlatformStateWhenCloudOverrideIsEmpty(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("SSHMGR_STATE", filepath.Join(temp, "state.yaml"))
	t.Setenv("SSHMGR_CLOUD_STATE", "")
	t.Setenv("XDG_STATE_HOME", temp)

	paths, err := Resolve(Context{Organization: "acme", Project: "production"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(temp, "sshmgr", "projects", "acme", "production")
	if paths.Root != want {
		t.Fatalf("project root = %q, want %q", paths.Root, want)
	}
}
