package cloudclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/cloudclient"
	"github.com/systeampl/sshmgr/internal/cloudtest"
)

const testToken = "cloud-client-test-token-0123456789abcdef0123456789abcdef"

func testBundle(t *testing.T) *access.WorkspaceBundle {
	t.Helper()
	history, err := access.ReadWorkspaceHistory(filepath.Join("..", "access", "testdata", "workspace-history-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := access.BuildWorkspaceBundle(history, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestClientUploadsValidatedBundleAndHandlesIdempotentRetry(t *testing.T) {
	service := cloudtest.New(testToken, "client-a-uploader")
	handler := service.Handler()
	var seenUserAgent bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUserAgent = r.UserAgent() == "sshmgr/test"
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	client, err := cloudclient.New(cloudclient.Options{
		Endpoint: server.URL, Token: testToken, Timeout: 5 * time.Second,
		UserAgent: "sshmgr/test", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(context.Background(), "golden-workspace")
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "ready" || status.Workspace != "golden-workspace" || status.PrincipalID != "client-a-uploader" || status.APIVersion != "v1" {
		t.Fatalf("status = %+v", status)
	}
	bundle := testBundle(t)
	created, err := client.UploadBundle(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != "created" || created.Bundle.BundleID != bundle.BundleID || created.Bundle.PrincipalID != "client-a-uploader" || !seenUserAgent {
		t.Fatalf("created result = %+v user-agent=%t", created, seenUserAgent)
	}
	retry, err := client.UploadBundle(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Status != "already_exists" || retry.Bundle != created.Bundle {
		t.Fatalf("retry = %+v", retry)
	}
}

func TestClientProjectStatusAndUploadUseV2OrganizationRoutes(t *testing.T) {
	service := cloudtest.New(testToken, "client-a-uploader")
	server := httptest.NewTLSServer(service.Handler())
	defer server.Close()
	client, err := cloudclient.New(cloudclient.Options{
		Endpoint: server.URL, Token: testToken, Timeout: 5 * time.Second,
		UserAgent: "sshmgr/test", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.ProjectStatus(context.Background(), "local", "golden-workspace")
	if err != nil {
		t.Fatal(err)
	}
	if status.APIVersion != "v2" || status.Organization != "local" || status.Project != "golden-workspace" ||
		status.Workspace != "golden-workspace" || status.PrincipalID != "client-a-uploader" {
		t.Fatalf("project status = %+v", status)
	}
	bundle := testBundle(t)
	created, err := client.UploadProjectBundle(context.Background(), "local", "golden-workspace", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != "created" || created.Bundle.BundleID != bundle.BundleID || created.Bundle.Workspace != "golden-workspace" {
		t.Fatalf("created result = %+v", created)
	}
	retry, err := client.UploadProjectBundle(context.Background(), "local", "golden-workspace", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Status != "already_exists" || retry.Bundle != created.Bundle {
		t.Fatalf("retry = %+v", retry)
	}
	if _, err := client.ProjectStatus(context.Background(), "other-org", "golden-workspace"); err == nil {
		t.Fatal("status for a foreign organization was accepted")
	}
	if _, err := client.UploadProjectBundle(context.Background(), "other-org", "golden-workspace", bundle); err == nil {
		t.Fatal("upload to a foreign organization was accepted")
	}
	if _, err := client.UploadProjectBundle(context.Background(), "local", "other-project", bundle); err == nil {
		t.Fatal("upload with a project differing from the bundle workspace was accepted")
	}
}

func TestClientProjectStatusRejectsMismatchedEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1","service":"sshmgr-cloud-api","status":"ready","api_version":"v2","storage":"append_only_file","workspace":"fleet","organization":"other-org","project":"fleet","principal_id":"test","version":"dev","commit":"abc","build_date":"today","server_time":"2026-08-13T20:00:00Z","capabilities":["workspace_status","bundle_ingest"]}`))
	}))
	defer server.Close()
	client, err := cloudclient.New(cloudclient.Options{Endpoint: server.URL, Token: testToken, AllowInsecureLoopback: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ProjectStatus(context.Background(), "org-a", "fleet"); err == nil || !strings.Contains(err.Error(), "does not reconcile") {
		t.Fatalf("mismatched organization echo accepted: %v", err)
	}
	if _, err := client.ProjectStatus(context.Background(), "org a", "fleet"); err == nil {
		t.Fatal("invalid organization slug accepted")
	}
	if _, err := client.ProjectStatus(context.Background(), "org-a", "fleet a"); err == nil {
		t.Fatal("invalid project slug accepted")
	}
}

func TestClientStatusRejectsWorkspaceAndMismatchedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1","service":"sshmgr-cloud-api","status":"ready","api_version":"v1","storage":"append_only_file","workspace":"wrong","principal_id":"test","version":"dev","commit":"abc","build_date":"today","server_time":"2026-08-13T20:00:00Z","capabilities":["workspace_status"]}`))
	}))
	defer server.Close()
	client, err := cloudclient.New(cloudclient.Options{Endpoint: server.URL, Token: testToken, AllowInsecureLoopback: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(context.Background(), "bad workspace"); err == nil {
		t.Fatal("invalid workspace accepted")
	}
	if _, err := client.Status(context.Background(), "golden-workspace"); err == nil || !strings.Contains(err.Error(), "does not reconcile") {
		t.Fatalf("mismatched status accepted: %v", err)
	}
}

func TestClientEnforcesTransportAndResponseBoundaries(t *testing.T) {
	for _, options := range []cloudclient.Options{
		{Endpoint: "http://example.com", Token: testToken, AllowInsecureLoopback: true, Timeout: time.Second},
		{Endpoint: "http://localhost:8787", Token: testToken, AllowInsecureLoopback: true, Timeout: time.Second},
		{Endpoint: "http://127.0.0.1:8787", Token: testToken, Timeout: time.Second},
		{Endpoint: "ftp://127.0.0.1", Token: testToken, Timeout: time.Second},
		{Endpoint: "https://user@example.com", Token: testToken, Timeout: time.Second},
		{Endpoint: "https://example.com/api", Token: testToken, Timeout: time.Second},
		{Endpoint: "https://example.com", Token: "bad token", Timeout: time.Second},
		{Endpoint: "https://example.com", Token: testToken, Timeout: 0},
	} {
		if _, err := cloudclient.New(options); err == nil {
			t.Fatalf("unsafe client options accepted: %+v", options)
		}
	}

	redirectTargetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		if r.Header.Get("Authorization") != "" {
			t.Error("redirect target received bearer token")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := cloudclient.New(cloudclient.Options{Endpoint: redirect.URL, Token: testToken, AllowInsecureLoopback: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UploadBundle(context.Background(), testBundle(t)); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect was accepted: %v", err)
	}
	if redirectTargetHit {
		t.Fatal("redirect target was contacted")
	}
}

func TestClientRejectsAPIErrorAndMismatchedSuccess(t *testing.T) {
	tests := []struct {
		name, body string
		status     int
		want       string
	}{
		{name: "structured API error", status: http.StatusUnauthorized, body: `{"error":{"code":"unauthorized","message":"valid bearer token required"}}`, want: "unauthorized"},
		{name: "mismatched success", status: http.StatusCreated, body: `{"schema_version":"1","status":"created","bundle":{"workspace":"wrong","bundle_id":"wrong","history_id":"wrong","latest_scan_id":"wrong","payload_sha256":"wrong","payload_bytes":1,"received_at":"2026-08-13T20:00:00Z","principal_id":"test"}}`, want: "does not reconcile"},
		{name: "unknown success field", status: http.StatusCreated, body: `{"schema_version":"1","status":"created","bundle":{"workspace":"wrong"},"unknown":true}`, want: "unknown field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := cloudclient.New(cloudclient.Options{Endpoint: server.URL, Token: testToken, AllowInsecureLoopback: true, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.UploadBundle(context.Background(), testBundle(t)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}
