package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/cloudstate"
	"github.com/systeampl/sshmgr/internal/cloudtest"
	"github.com/systeampl/sshmgr/internal/secret"
	"github.com/zalando/go-keyring"
)

func TestConfirmCloudPushRequiresExactUpload(t *testing.T) {
	destination := cloudPushDestination{Endpoint: "https://cloud.example.test", Organization: "systeam", Project: "fleet"}
	for _, test := range []struct {
		input string
		want  bool
	}{
		{input: "upload\n", want: true},
		{input: " upload \r\n", want: true},
		{input: "yes\n", want: false},
		{input: "UPLOAD\n", want: false},
	} {
		var prompt bytes.Buffer
		got, err := confirmCloudPush(strings.NewReader(test.input), &prompt, destination)
		if err != nil || got != test.want {
			t.Fatalf("input=%q confirmed=%t want=%t err=%v", test.input, got, test.want, err)
		}
		if !strings.Contains(prompt.String(), "systeam/fleet") || !strings.Contains(prompt.String(), destination.Endpoint) {
			t.Fatalf("confirmation prompt=%q", prompt.String())
		}
	}
	if _, err := confirmCloudPush(strings.NewReader(strings.Repeat("x", 65)), &bytes.Buffer{}, destination); err == nil {
		t.Fatal("oversized Cloud push confirmation was accepted")
	}
}

func TestCloudPushProfileUploadsIdempotentlyAndAccumulatesProjectHistory(t *testing.T) {
	keyring.MockInit()
	token := "cloud-push-test-token-0123456789abcdef0123456789abcdef"
	service := cloudtest.New(token, "push-uploader")
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	profilePath := filepath.Join(t.TempDir(), "cloud.json")
	stateRoot := filepath.Join(t.TempDir(), "cloud-state")
	t.Setenv("SSHMGR_CLOUD_CONFIG", profilePath)
	t.Setenv("SSHMGR_CLOUD_STATE", stateRoot)
	keyringName := "cloud-push-test"
	if err := secret.KeyringSet(keyringName, token); err != nil {
		t.Fatal(err)
	}
	if _, err := cloudprofile.Update(func(config *cloudprofile.Config) error {
		return cloudprofile.Upsert(config, "production", cloudprofile.Profile{
			Endpoint: server.URL, Organization: "local", Project: "golden-workspace",
			TokenKeyring: keyringName, AllowInsecureLoopback: true,
		}, true)
	}); err != nil {
		t.Fatal(err)
	}

	fixture := filepath.Join("internal", "access", "testdata", "snapshot-v1.json")
	cmdCloudPush([]string{fixture, "--profile", "production", "--timeout", "5s", "--yes"})
	cmdCloudPush([]string{fixture, "--profile", "production", "--timeout", "5s", "--yes"})
	bundles := service.Bundles()
	if len(bundles) != 1 || bundles[0].PrincipalID != "push-uploader" {
		t.Fatalf("idempotent stored bundles=%+v", bundles)
	}

	second, err := access.ReadSnapshot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	second.ScanID = "scan_push_second"
	second.StartedAt = "2026-08-12T12:00:00Z"
	second.Finalize(time.Date(2026, 8, 12, 12, 0, 1, 0, time.UTC))
	secondPath := filepath.Join(t.TempDir(), "second-scan.json")
	if err := access.WriteSnapshot(secondPath, second); err != nil {
		t.Fatal(err)
	}
	cmdCloudPush([]string{secondPath, "--profile", "production", "--timeout", "5s", "--yes"})
	bundles = service.Bundles()
	if len(bundles) != 2 {
		t.Fatalf("accumulated stored bundles=%+v", bundles)
	}

	paths, err := cloudstate.Resolve(cloudstate.Context{Scope: "production", Organization: "local", Project: "golden-workspace"})
	if err != nil {
		t.Fatal(err)
	}
	history, err := cloudstate.LoadHistory(paths)
	if err != nil || len(history.Plans) != 2 || history.LatestScanID != second.ScanID {
		t.Fatalf("local push history=%+v err=%v", history, err)
	}
	for _, path := range []string{paths.History, paths.Lock} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private state file %s info=%v err=%v", path, info, statErr)
		}
	}
	if entries, err := os.ReadDir(paths.Plans); err != nil || len(entries) != 2 {
		t.Fatalf("upload plan artifacts=%v err=%v", entries, err)
	}
	if entries, err := os.ReadDir(paths.Bundles); err != nil || len(entries) != 2 {
		t.Fatalf("bundle artifacts=%v err=%v", entries, err)
	}
	if err := filepath.Walk(stateRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), token) {
			t.Fatalf("plaintext Cloud token leaked into local push state %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
