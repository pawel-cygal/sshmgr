package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/cloudtest"
	"github.com/systeampl/sshmgr/internal/secret"
	"github.com/zalando/go-keyring"
)

func TestCloudProfileLoginStatusWorkspaceAndUpload(t *testing.T) {
	keyring.MockInit()
	token := "cloud-profile-test-token-0123456789abcdef0123456789abcdef"
	service := cloudtest.New(token, "profile-uploader")
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	profilePath := filepath.Join(t.TempDir(), "cloud.json")
	t.Setenv("SSHMGR_CLOUD_CONFIG", profilePath)
	t.Setenv("SSHMGR_PROFILE_TEST_TOKEN", token)
	cmdCloudLogin([]string{"local", "--endpoint", server.URL, "--workspace", "golden-workspace", "--token-env", "SSHMGR_PROFILE_TEST_TOKEN", "--allow-http-loopback", "--timeout", "5s"})

	config, loadedPath, err := cloudprofile.Load()
	if err != nil || loadedPath != profilePath || config.ActiveProfile != "local" {
		t.Fatalf("profile config=%+v path=%q err=%v", config, loadedPath, err)
	}
	profile := config.Profiles["local"]
	if profile.Workspace != "golden-workspace" || profile.Endpoint != server.URL || !profile.AllowInsecureLoopback {
		t.Fatalf("profile=%+v", profile)
	}
	storedToken, err := secret.KeyringGet(profile.TokenKeyring)
	if err != nil || storedToken != token {
		t.Fatalf("stored token mismatch err=%v", err)
	}
	data, _ := os.ReadFile(profilePath)
	if strings.Contains(string(data), token) {
		t.Fatal("plaintext token leaked into Cloud profile config")
	}
	cmdCloudStatus([]string{"--profile", "local", "--timeout", "5s", "--json"})
	cmdCloudWorkspace([]string{"show", "--profile", "local", "--json"})
	cmdCloudWorkspace([]string{"list", "--json"})
	cmdCloudWorkspace([]string{"use", "local"})
	cmdCloudWorkspace([]string{"set", "golden-workspace", "--profile", "local"})

	history, err := access.ReadWorkspaceHistory(filepath.Join("internal", "access", "testdata", "workspace-history-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := access.BuildWorkspaceBundle(history, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	if err := access.WriteWorkspaceBundle(bundlePath, bundle); err != nil {
		t.Fatal(err)
	}
	cmdCloudUpload([]string{bundlePath, "--profile", "local", "--timeout", "5s"})
	bundles := service.Bundles()
	if len(bundles) != 1 || bundles[0].PrincipalID != "profile-uploader" {
		t.Fatalf("stored bundles=%+v", bundles)
	}
}

func TestCloudProfileProjectLoginStatusAndUpload(t *testing.T) {
	keyring.MockInit()
	token := "cloud-project-test-token-0123456789abcdef0123456789abcdef"
	service := cloudtest.New(token, "project-uploader")
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	profilePath := filepath.Join(t.TempDir(), "cloud.json")
	t.Setenv("SSHMGR_CLOUD_CONFIG", profilePath)
	t.Setenv("SSHMGR_PROJECT_TEST_TOKEN", token)
	cmdCloudLogin([]string{"proj", "--endpoint", server.URL, "--organization", "local", "--project", "golden-workspace", "--token-env", "SSHMGR_PROJECT_TEST_TOKEN", "--allow-http-loopback", "--timeout", "5s"})

	config, _, err := cloudprofile.Load()
	if err != nil || config.ActiveProfile != "proj" {
		t.Fatalf("profile config=%+v err=%v", config, err)
	}
	profile := config.Profiles["proj"]
	if profile.Organization != "local" || profile.Project != "golden-workspace" || profile.Workspace != "" {
		t.Fatalf("profile=%+v", profile)
	}
	cmdCloudStatus([]string{"--profile", "proj", "--timeout", "5s", "--json"})
	cmdCloudProject([]string{"show", "--profile", "proj", "--json"})
	cmdCloudProject([]string{"list", "--json"})
	cmdCloudProject([]string{"use", "proj"})
	cmdCloudProject([]string{"set", "golden-workspace", "--organization", "local", "--profile", "proj"})

	history, err := access.ReadWorkspaceHistory(filepath.Join("internal", "access", "testdata", "workspace-history-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := access.BuildWorkspaceBundle(history, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	if err := access.WriteWorkspaceBundle(bundlePath, bundle); err != nil {
		t.Fatal(err)
	}
	cmdCloudUpload([]string{bundlePath, "--profile", "proj", "--timeout", "5s"})
	bundles := service.Bundles()
	if len(bundles) != 1 || bundles[0].PrincipalID != "project-uploader" {
		t.Fatalf("stored bundles=%+v", bundles)
	}
}

func TestReadCloudTokenIsBounded(t *testing.T) {
	valid := "cloud-token-0123456789abcdef0123456789abcdef\r\n"
	if got, err := readCloudToken(strings.NewReader(valid)); err != nil || got != strings.TrimSuffix(strings.TrimSuffix(valid, "\n"), "\r") {
		t.Fatalf("token=%q err=%v", got, err)
	}
	if _, err := readCloudToken(strings.NewReader(strings.Repeat("x", 513))); err == nil {
		t.Fatal("oversized token accepted")
	}
}
