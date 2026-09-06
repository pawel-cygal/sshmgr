package humanclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
)

func TestClientKeepsDeviceAndHumanBearerPlanesSeparate(t *testing.T) {
	token := strings.Repeat("h", 43)
	deviceCode := strings.Repeat("d", 43)
	user := cloudcontract.BrowserUser{ID: "usr_" + strings.Repeat("a", 32), Email: "owner@example.test", DisplayName: "Owner", EmailVerified: true}
	session := cloudcontract.BrowserSession{SchemaVersion: "1", SessionID: "cli_" + strings.Repeat("b", 32), User: user}
	seen := []string{}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/device/authorize":
			if r.Header.Get("Authorization") != "" || r.UserAgent() != "sshmgr/test" {
				t.Errorf("device authorization leaked bearer or user agent missing: headers=%v", r.Header)
			}
			_ = json.NewEncoder(w).Encode(cloudcontract.DeviceAuthorization{SchemaVersion: "1", DeviceCode: deviceCode, UserCode: "ABCD-EFGH", VerificationURI: server.URL + "/device", VerificationURIComplete: server.URL + "/device?code=ABCD-EFGH", ExpiresIn: 600, Interval: 3})
		case "/v2/device/token":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("device exchange carried a human bearer token")
			}
			_ = json.NewEncoder(w).Encode(cloudcontract.CLISessionIssue{SchemaVersion: "1", AccessToken: token, TokenType: "Bearer", ExpiresIn: 43200, Session: session})
		case "/v2/cli/session":
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Errorf("human bearer header=%q", r.Header.Get("Authorization"))
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "1", "session": session})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(Options{Endpoint: server.URL, Token: token, Timeout: 5 * time.Second, UserAgent: "sshmgr/test", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.StartDeviceAuthorization(context.Background())
	if err != nil || authorization.UserCode != "ABCD-EFGH" {
		t.Fatalf("device authorization=%+v err=%v", authorization, err)
	}
	issue, err := client.ExchangeDeviceAuthorization(context.Background(), deviceCode)
	if err != nil || issue.AccessToken != token || issue.Session.User.ID != user.ID {
		t.Fatalf("device exchange=%+v err=%v", issue, err)
	}
	resolved, err := client.Session(context.Background())
	if err != nil || resolved.User.Email != user.Email {
		t.Fatalf("human session=%+v err=%v", resolved, err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /v2/device/authorize", "POST /v2/device/token", "GET /v2/cli/session", "DELETE /v2/cli/session"}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("routes=%v want=%v", seen, want)
	}
}

func TestClientMapsDevicePendingError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"authorization_pending","message":"device authorization is pending"}}`))
	}))
	defer server.Close()
	client, err := New(Options{Endpoint: server.URL, Timeout: time.Second, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ExchangeDeviceAuthorization(context.Background(), strings.Repeat("d", 43))
	if !IsCode(err, "authorization_pending") {
		t.Fatalf("pending error=%v", err)
	}
}
