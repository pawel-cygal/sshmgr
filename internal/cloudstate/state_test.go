package cloudstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/access"
)

func TestResolveSeparatesProfileProjectAndManualEndpointState(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state")
	t.Setenv("SSHMGR_CLOUD_STATE", base)
	project, err := Resolve(Context{Scope: "production", Organization: "systeam", Project: "fleet"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "production", "systeam", "fleet")
	if project.Root != want || project.History != filepath.Join(want, "history.json") {
		t.Fatalf("project paths=%+v want root=%s", project, want)
	}
	legacy, err := Resolve(Context{Scope: ManualScope("https://cloud.example.test"), Workspace: "fleet"})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Root == project.Root || !strings.Contains(legacy.Root, filepath.Join("legacy", "fleet")) || !strings.Contains(legacy.Root, "manual-") {
		t.Fatalf("legacy paths=%+v", legacy)
	}
}

func TestCommitAndLoadPrivateProjectHistory(t *testing.T) {
	t.Setenv("SSHMGR_CLOUD_STATE", filepath.Join(t.TempDir(), "state"))
	paths, err := Resolve(Context{Scope: "production", Organization: "systeam", Project: "golden-workspace"})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	history, err := access.ReadWorkspaceHistory(filepath.Join("..", "access", "testdata", "workspace-history-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := &history.Plans[len(history.Plans)-1]
	bundle, err := access.BuildWorkspaceBundle(history, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := Commit(paths, plan, history, bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{artifacts.Plan, artifacts.History, artifacts.Bundle} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s mode=%v err=%v", path, info, statErr)
		}
	}
	loaded, err := LoadHistory(paths)
	if err != nil || loaded.HistoryID != history.HistoryID {
		t.Fatalf("loaded history=%+v err=%v", loaded, err)
	}
}

func TestLoadHistoryRejectsUnsafeStateFile(t *testing.T) {
	t.Setenv("SSHMGR_CLOUD_STATE", filepath.Join(t.TempDir(), "state"))
	paths, err := Resolve(Context{Scope: "production", Organization: "systeam", Project: "fleet"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.History, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHistory(paths); err == nil || !strings.Contains(err.Error(), "private regular") {
		t.Fatalf("unsafe history error=%v", err)
	}
}

func TestResolveRejectsAmbiguousOrUnsafeContext(t *testing.T) {
	t.Setenv("SSHMGR_CLOUD_STATE", t.TempDir())
	for _, context := range []Context{
		{Scope: "prod", Organization: "systeam"},
		{Scope: "prod", Organization: "systeam", Project: "fleet", Workspace: "legacy"},
		{Scope: "../prod", Organization: "systeam", Project: "fleet"},
	} {
		if _, err := Resolve(context); err == nil {
			t.Fatalf("unsafe context accepted: %+v", context)
		}
	}
}
