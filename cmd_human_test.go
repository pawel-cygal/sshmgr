package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/secret"
	"github.com/zalando/go-keyring"
)

func TestHumanLoginFirstRunEndToEndPreservesHosts(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	hostPath, cloudPath := filepath.Join(dir, "hosts.yaml"), filepath.Join(dir, "cloud.json")
	t.Setenv("SSHMGR_CONFIG", hostPath)
	t.Setenv("SSHMGR_CLOUD_CONFIG", cloudPath)
	original := []byte("# keep my hosts\nhosts:\n  personal:\n    host: 192.0.2.10\n    user: operator\n")
	if err := os.WriteFile(hostPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("s", 43)
	var base string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			t.Error("login sent credentials before approval")
		}
		switch r.URL.Path {
		case "/v2/device/authorize":
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "1", "device_code": "test-device-code", "user_code": "TEST-CODE", "verification_uri": base + "/device", "verification_uri_complete": base + "/device?code=TEST-CODE", "expires_in": 60, "interval": 1})
		case "/v2/device/token":
			var request cloudcontract.DeviceTokenRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.DeviceCode != "test-device-code" {
				t.Error("incorrect device code")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "1", "token_type": "Bearer", "access_token": token, "expires_in": 3600, "session": cloudcontract.BrowserSession{User: cloudcontract.BrowserUser{ID: "owner", Email: "owner@example.test"}, Organizations: []cloudcontract.BrowserOrganization{{Slug: "company", Projects: []cloudcontract.BrowserProject{{Slug: "prod"}}}}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	cmdHumanLogin([]string{"--profile", "personal", "--endpoint", base, "--no-browser", "--timeout", "5s"})
	cfg, _, err := cloudprofile.Load()
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["personal"]
	if cfg.ActiveProfile != "personal" || p.Endpoint != base || p.Organization != "company" || p.Project != "prod" {
		t.Fatal("incorrect saved Cloud context")
	}
	stored, err := secret.KeyringGet("sshmgr-human:personal")
	if err != nil || stored != token {
		t.Fatal("human session was not saved to keyring")
	}
	if _, err := secret.KeyringGet(p.TokenKeyring); err == nil {
		t.Fatal("human login created a runner credential")
	}
	cloudData, _ := os.ReadFile(cloudPath)
	if bytes.Contains(cloudData, []byte(token)) {
		t.Fatal("session token leaked into profile")
	}
	after, _ := os.ReadFile(hostPath)
	if !bytes.Equal(original, after) {
		t.Fatal("login altered SSH inventory")
	}
}

func TestHumanOnboardingPreservesHostInventory(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "config.yaml")
	cloudPath := filepath.Join(dir, "cloud.json")
	t.Setenv("SSHMGR_CONFIG", hostPath)
	t.Setenv("SSHMGR_CLOUD_CONFIG", cloudPath)
	// Comments, anchors and ordering must survive byte-for-byte, not just YAML decoding.
	original := []byte("# My inventory\nhosts:\n  first:\n    user: &user deploy\n    host: 192.0.2.1\n  second:\n    host: 192.0.2.2\n    user: *user\n")
	if err := os.WriteFile(hostPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := cloudprofile.NewConfig()
	human, _, err := prepareHumanLogin(cfg, "personal", "")
	if err != nil {
		t.Fatal(err)
	}
	human.Profile.Organization, human.Profile.Project = "company", "prod"
	if err := persistHumanLogin(human, true, "first-session"); err != nil {
		t.Fatal(err)
	}
	cloudBefore, err := os.ReadFile(cloudPath)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent login must not overwrite an existing profile.
	human.Profile.Project = "different"
	if err := persistHumanLogin(human, true, "conflicting-session"); err == nil {
		t.Fatal("existing profile overwritten")
	}
	if stored, err := secret.KeyringGet(human.TokenKey); err != nil || stored != "first-session" {
		t.Fatal("conflicting login changed the existing session")
	}
	cloudAfter, _ := os.ReadFile(cloudPath)
	if !bytes.Equal(cloudBefore, cloudAfter) {
		t.Fatal("failed login changed Cloud profile")
	}
	hosts, _, err := config.Load()
	if err != nil || len(hosts.Hosts) != 2 {
		t.Fatalf("inventory cannot be loaded: %v", err)
	}
	after, _ := os.ReadFile(hostPath)
	if !bytes.Equal(original, after) {
		t.Fatal("host inventory changed during Cloud onboarding")
	}
	info, _ := os.Stat(hostPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("host file permissions changed")
	}
	// Even a mistaken Cloud config override must fail without replacing YAML.
	t.Setenv("SSHMGR_CLOUD_CONFIG", hostPath)
	if err := persistHumanLogin(human, true, "misconfigured-session"); err == nil {
		t.Fatal("host inventory accepted as Cloud configuration")
	}
	after, _ = os.ReadFile(hostPath)
	if !bytes.Equal(original, after) {
		t.Fatal("misconfigured Cloud path overwrote host inventory")
	}
}

func TestHumanProjectStatus(t *testing.T) {
	for _, tc := range []struct {
		name, organization, project, workspace string
		organizations                          []cloudcontract.BrowserOrganization
		want, absent                           string
	}{
		{name: "accessible", organization: "company", project: "prod", organizations: []cloudcontract.BrowserOrganization{{Slug: "company", Projects: []cloudcontract.BrowserProject{{Slug: "prod"}}}}, want: "Project access: available", absent: "Warning:"},
		{name: "no memberships", organization: "company", project: "prod", want: "saved project is not listed", absent: "Project access: available"},
		{name: "same slug different organization", organization: "company", project: "prod", organizations: []cloudcontract.BrowserOrganization{{Slug: "other", Projects: []cloudcontract.BrowserProject{{Slug: "prod"}}}}, want: "saved project is not listed", absent: "Project access: available"},
		{name: "different project", organization: "company", project: "prod", organizations: []cloudcontract.BrowserOrganization{{Slug: "company", Projects: []cloudcontract.BrowserProject{{Slug: "dev"}}}}, want: "saved project is not listed", absent: "Project access: available"},
		{name: "legacy workspace", workspace: "legacy", want: "Workspace: legacy (legacy runner context)", absent: "Project: /"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			human := humanContext{ProfileName: "personal", Profile: cloudprofile.Profile{Endpoint: "https://cloud.example.test", Organization: tc.organization, Project: tc.project, Workspace: tc.workspace}}
			before := human
			var output bytes.Buffer
			printHumanProjectStatus(&output, human, cloudcontract.BrowserSession{Organizations: tc.organizations})
			if !strings.Contains(output.String(), tc.want) || strings.Contains(output.String(), tc.absent) {
				t.Fatalf("unexpected status: %s", output.String())
			}
			if human != before {
				t.Fatal("status changed the profile")
			}
			if tc.name != "accessible" && !strings.Contains(output.String(), "--endpoint https://cloud.example.test") {
				t.Fatal("recovery hint lost the custom endpoint")
			}
		})
	}
}

func TestHumanReloginPreservesProfileAndRunner(t *testing.T) {
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "cloud.json")
	t.Setenv("SSHMGR_CLOUD_CONFIG", path)
	profile := cloudprofile.Profile{Endpoint: "https://cloud.example.test", Organization: "company", Project: "prod", TokenKeyring: "sshmgr-cloud:personal"}
	if _, err := cloudprofile.Update(func(cfg *cloudprofile.Config) error {
		return cloudprofile.Upsert(cfg, "personal", profile, true)
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := secret.KeyringSet(profile.TokenKeyring, "runner-token"); err != nil {
		t.Fatal(err)
	}
	human := humanContext{ProfileName: "personal", Profile: profile, TokenKey: "sshmgr-human:personal"}
	if err := persistHumanLogin(human, false, "new-human-session"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("relogin changed profile metadata")
	}
	if token, err := secret.KeyringGet(profile.TokenKeyring); err != nil || token != "runner-token" {
		t.Fatal("relogin changed runner token")
	}
	if token, err := secret.KeyringGet(human.TokenKey); err != nil || token != "new-human-session" {
		t.Fatal("human session was not saved")
	}
}

func TestHumanLoginKeyringFailureDoesNotCreateProfile(t *testing.T) {
	keyring.MockInitWithError(errors.New("keyring locked"))
	t.Cleanup(keyring.MockInit)
	path := filepath.Join(t.TempDir(), "cloud.json")
	t.Setenv("SSHMGR_CLOUD_CONFIG", path)
	human, _, err := prepareHumanLogin(cloudprofile.NewConfig(), "personal", "")
	if err != nil {
		t.Fatal(err)
	}
	human.Profile.Organization, human.Profile.Project = "company", "prod"
	if err := persistHumanLogin(human, true, "session"); err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("expected keyring failure, got %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed login published a profile: %v", err)
	}
}

func TestHumanSessionRollbackOnProfileWriteFailure(t *testing.T) {
	for _, previous := range []string{"", "previous-session"} {
		t.Run("previous="+previous, func(t *testing.T) {
			keyring.MockInit()
			path := filepath.Join(t.TempDir(), "cloud.json")
			t.Setenv("SSHMGR_CLOUD_CONFIG", path)
			const key = "sshmgr-human:personal"
			if previous != "" {
				if err := secret.KeyringSet(key, previous); err != nil {
					t.Fatal(err)
				}
			}
			if err := secret.KeyringSet("sshmgr-cloud:personal", "runner-credential"); err != nil {
				t.Fatal(err)
			}
			_, err := cloudprofile.UpdateWithRollback(func(cfg *cloudprofile.Config) error {
				return cloudprofile.Upsert(cfg, "personal", cloudprofile.Profile{Endpoint: "https://cloud.example.test", Organization: "company", Project: "prod", TokenKeyring: cloudprofile.TokenKey("personal")}, true)
			}, func() (func() error, error) {
				rollback, err := stageHumanSession(key, "new-session")
				if err != nil {
					return nil, err
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				return rollback, nil
			})
			if err == nil {
				t.Fatal("expected profile publication failure")
			}
			stored, err := secret.KeyringGet(key)
			if previous == "" {
				if !secret.IsKeyringNotFound(err) {
					t.Fatal("new session survived rollback")
				}
			} else if err != nil || stored != previous {
				t.Fatal("previous session was not restored")
			}
			if runner, err := secret.KeyringGet("sshmgr-cloud:personal"); err != nil || runner != "runner-credential" {
				t.Fatal("rollback changed runner credentials")
			}
		})
	}
}

// Opt-in compatibility check. Load only an isolated copy because legacy Load
// may migrate runtime history to a sidecar even when the YAML is unchanged.
func TestExistingInventoryCompatibility(t *testing.T) {
	source := os.Getenv("SSHMGR_COMPAT_INVENTORY")
	if source == "" {
		t.Skip("set SSHMGR_COMPAT_INVENTORY for a private read-only compatibility check")
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal("cannot read compatibility inventory")
	}
	copyPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(copyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHMGR_CONFIG", copyPath)
	cfg, _, err := config.Load()
	if err != nil {
		t.Fatal("inventory compatibility check failed; contents suppressed")
	}
	t.Logf("inventory decoded successfully: %d hosts", len(cfg.Hosts))
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("source inventory changed")
	}
}

func TestHumanFirstLoginNeedsNoRunnerProfile(t *testing.T) {
	cfg := cloudprofile.NewConfig()
	human, fresh, err := prepareHumanLogin(cfg, "", "")
	if err != nil || !fresh || human.Profile.Endpoint != "https://sshmgr.systeam.pl" || human.TokenKey != "sshmgr-human:systeam" {
		t.Fatalf("login=%+v fresh=%v err=%v", human, fresh, err)
	}
	if len(cfg.Profiles) != 0 {
		t.Fatal("preparing login mutated config before approval")
	}
	for _, endpoint := range []string{"http://example.com", "https://user:password@example.com"} {
		if _, _, err := prepareHumanLogin(cfg, "new", endpoint); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}

func TestHumanLoginPreservesExistingRunnerProfile(t *testing.T) {
	cfg := cloudprofile.NewConfig()
	p := cloudprofile.Profile{Endpoint: "https://private.example.com", Organization: "company", Project: "prod", TokenKeyring: "sshmgr-cloud:existing"}
	if err := cloudprofile.Upsert(cfg, "existing", p, true); err != nil {
		t.Fatal(err)
	}
	human, fresh, err := prepareHumanLogin(cfg, "", "")
	if err != nil || fresh || human.Profile != p {
		t.Fatalf("existing profile changed: %+v %v", human, err)
	}
	if _, _, err := prepareHumanLogin(cfg, "existing", "https://other.example.com"); err == nil {
		t.Fatal("endpoint replacement accepted")
	}
	if cfg.Profiles["existing"] != p {
		t.Fatal("runner profile mutated")
	}
}

func TestHumanLoginSelectsOnlyAccessibleUnambiguousProject(t *testing.T) {
	session := cloudcontract.BrowserSession{Organizations: []cloudcontract.BrowserOrganization{{Slug: "company", Projects: []cloudcontract.BrowserProject{{Slug: "prod"}}}}}
	selected, err := selectHumanLoginProject(session, "", "")
	if err != nil || selected != [2]string{"company", "prod"} {
		t.Fatalf("selection=%v err=%v", selected, err)
	}
	session.Organizations[0].Projects = append(session.Organizations[0].Projects, cloudcontract.BrowserProject{Slug: "dev"})
	if _, err := selectHumanLoginProject(session, "", ""); err == nil {
		t.Fatal("ambiguous project silently selected")
	}
	if _, err := selectHumanLoginProject(session, "company", "missing"); err == nil {
		t.Fatal("inaccessible project accepted")
	}
	if selected, err := selectHumanLoginProject(session, "company", "dev"); err != nil || selected[1] != "dev" {
		t.Fatalf("explicit selection=%v err=%v", selected, err)
	}
	if _, err := selectHumanLoginProject(cloudcontract.BrowserSession{}, "", ""); err == nil {
		t.Fatal("empty account accepted")
	}
}

func TestHumanLoginInteractiveProjectSelection(t *testing.T) {
	session := cloudcontract.BrowserSession{Organizations: []cloudcontract.BrowserOrganization{
		{Slug: "company", Projects: []cloudcontract.BrowserProject{{Slug: "prod"}}},
		{Slug: "sandbox", Projects: []cloudcontract.BrowserProject{{Slug: "dev"}}},
	}}
	for _, tc := range []struct {
		name, input, org, project          string
		interactive, wantError, wantPrompt bool
		want                               [2]string
	}{
		{name: "choose", input: "2\n", interactive: true, wantPrompt: true, want: [2]string{"sandbox", "dev"}},
		{name: "retry invalid", input: "\n0\n3\nword\n1\n", interactive: true, wantPrompt: true, want: [2]string{"company", "prod"}},
		{name: "cancel", input: "q\n", interactive: true, wantPrompt: true, wantError: true},
		{name: "eof", interactive: true, wantPrompt: true, wantError: true},
		{name: "script must not prompt", input: "1\n", wantError: true},
		{name: "explicit", org: "sandbox", project: "dev", want: [2]string{"sandbox", "dev"}},
		{name: "invalid explicit must not prompt", org: "company", project: "missing", interactive: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			got, err := chooseHumanLoginProject(session, tc.org, tc.project, tc.interactive, strings.NewReader(tc.input), &output)
			if (err != nil) != tc.wantError || got != tc.want {
				t.Fatalf("selection=%v err=%v", got, err)
			}
			if strings.Contains(output.String(), "Project [1-2]") != tc.wantPrompt {
				t.Fatalf("unexpected prompt: %q", output.String())
			}
		})
	}
}

func TestHumanVerificationCommandDerivesSafeProductionTarget(t *testing.T) {
	t.Setenv("SSHMGR_VERIFY_HOST", "")
	t.Setenv("SSHMGR_VERIFY_PORT", "")
	token := strings.Repeat("a", 43)
	command, err := humanVerificationCommand(cloudprofile.Profile{Endpoint: "https://api.example.test"}, token)
	if err != nil || command != "ssh "+token+"@verify.example.test" {
		t.Fatalf("verification command=%q err=%v", command, err)
	}
}

func TestHumanVerificationCommandSupportsExplicitDevelopmentPort(t *testing.T) {
	t.Setenv("SSHMGR_VERIFY_HOST", "127.0.0.1:2222")
	t.Setenv("SSHMGR_VERIFY_PORT", "")
	token := strings.Repeat("b", 43)
	command, err := humanVerificationCommand(cloudprofile.Profile{}, token)
	if err != nil || command != "ssh -p 2222 "+token+"@127.0.0.1" {
		t.Fatalf("verification command=%q err=%v", command, err)
	}
}

func TestHumanVerificationCommandRejectsShellSyntaxAndInvalidPorts(t *testing.T) {
	t.Setenv("SSHMGR_VERIFY_HOST", "verify.example.test;touch-bad")
	if _, err := humanVerificationCommand(cloudprofile.Profile{}, strings.Repeat("c", 43)); err == nil {
		t.Fatal("unsafe verification host was accepted")
	}
	t.Setenv("SSHMGR_VERIFY_HOST", "verify.example.test")
	t.Setenv("SSHMGR_VERIFY_PORT", "70000")
	if _, err := humanVerificationCommand(cloudprofile.Profile{}, strings.Repeat("c", 43)); err == nil {
		t.Fatal("invalid verification port was accepted")
	}
	t.Setenv("SSHMGR_VERIFY_PORT", "22")
	if _, err := humanVerificationCommand(cloudprofile.Profile{}, "bad token; echo owned"); err == nil {
		t.Fatal("unsafe verification token was accepted")
	}
}
