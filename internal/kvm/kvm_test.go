package kvm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/systeampl/sshmgr/internal/config"
)

type stubProvider struct{ web string }

func (s stubProvider) Reset(context.Context) error            { return nil }
func (s stubProvider) Power(context.Context) error            { return nil }
func (s stubProvider) Off(context.Context) error              { return nil }
func (s stubProvider) Status(context.Context) (string, error) { return "on", nil }
func (s stubProvider) WebURL() string                         { return s.web }

func noPass() (string, error) { return "", nil }

func TestNewUnknownTypeErrors(t *testing.T) {
	if _, err := New(config.KVMConfig{Type: "nope"}, "h", noPass); err == nil {
		t.Fatal("unknown kvm type should error")
	}
}

func TestNewDispatchesToRegisteredDriver(t *testing.T) {
	Register("stub", func(k config.KVMConfig, host string, pass PasswordFunc) (Provider, error) {
		return stubProvider{web: "x://" + host}, nil
	})
	p, err := New(config.KVMConfig{Type: "stub"}, "h1", noPass)
	if err != nil {
		t.Fatal(err)
	}
	if p.WebURL() != "x://h1" {
		t.Fatalf("driver not dispatched, got %q", p.WebURL())
	}
}

func TestBaseURLDefaultsAndOverrides(t *testing.T) {
	if got := BaseURL(config.KVMConfig{}, "alg-kvm"); got != "https://alg-kvm" {
		t.Fatalf("default scheme https: got %q", got)
	}
	if got := BaseURL(config.KVMConfig{Scheme: "http", Port: 8080}, "alg-kvm"); got != "http://alg-kvm:8080" {
		t.Fatalf("scheme+port override: got %q", got)
	}
	if got := BaseURL(config.KVMConfig{}, "2001:db8::5"); got != "https://[2001:db8::5]" {
		t.Fatalf("IPv6 without explicit port: got %q", got)
	}
	if got := BaseURL(config.KVMConfig{Port: 8443}, "[2001:db8::5]"); got != "https://[2001:db8::5]:8443" {
		t.Fatalf("bracketed IPv6 with explicit port: got %q", got)
	}
}

func TestValidateConfigRejectsMalformedNetworkSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.KVMConfig
		host string
	}{
		{"empty host", config.KVMConfig{}, ""},
		{"scheme", config.KVMConfig{Scheme: "ftp"}, "kvm.local"},
		{"port", config.KVMConfig{Port: 70000}, "kvm.local"},
		{"host path", config.KVMConfig{}, "https://kvm.local/path"},
		{"bad embedded port", config.KVMConfig{}, "kvm.local:nope"},
		{"two port sources", config.KVMConfig{Port: 8443}, "kvm.local:443"},
		{"ambiguous ipv6", config.KVMConfig{}, "2001:db8::1:zzzz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateConfig(tc.cfg, tc.host); err == nil {
				t.Fatal("invalid KVM config accepted")
			}
		})
	}
}

func TestValidateConfigAcceptsHostPortAndIPv6(t *testing.T) {
	for _, host := range []string{"kvm.local:8443", "2001:db8::5", "[2001:db8::5]", "[2001:db8::5]:8443"} {
		if err := ValidateConfig(config.KVMConfig{}, host); err != nil {
			t.Errorf("ValidateConfig(%q): %v", host, err)
		}
	}
}

func TestNanoKVMStatusSurfacesAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":42,"msg":"sensor unavailable","data":{}}`))
	}))
	defer srv.Close()

	n := &nanoKVM{client: srv.Client(), base: srv.URL, token: "already-authenticated", pass: noPass}
	_, err := n.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "code 42") {
		t.Fatalf("expected API error, got %v", err)
	}
}
