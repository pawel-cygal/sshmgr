package kvm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sshmgr/internal/config"
)

// mustNano builds a nanokvm Provider pointed at a test server URL.
func mustNano(t *testing.T, srvURL string) Provider {
	t.Helper()
	host := strings.TrimPrefix(srvURL, "http://")
	p, err := New(config.KVMConfig{Type: "nanokvm", Scheme: "http"}, host, func() (string, error) { return "pw", nil })
	if err != nil {
		t.Fatalf("New nanokvm: %v", err)
	}
	return p
}

func nanoServer(t *testing.T, loginCode, gpioCode string, capture *string, loginHits *int, cookie *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		*loginHits++
		http.SetCookie(w, &http.Cookie{Name: "nano-kvm-token", Value: "tok123", Path: "/"})
		w.Write([]byte(`{"code":` + loginCode + `}`))
	})
	mux.HandleFunc("/api/vm/gpio", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*capture = string(b)
		if c, err := r.Cookie("nano-kvm-token"); err == nil {
			*cookie = c.Value
		}
		w.Write([]byte(`{"code":` + gpioCode + `}`))
	})
	return httptest.NewServer(mux)
}

func TestNanoKVMResetLazyLoginThenGpio(t *testing.T) {
	var body, cookie string
	var loginHits int
	srv := nanoServer(t, "0", "0", &body, &loginHits, &cookie)
	defer srv.Close()

	if err := mustNano(t, srv.URL).Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if loginHits != 1 {
		t.Fatalf("expected exactly one lazy login, got %d", loginHits)
	}
	if cookie != "tok123" {
		t.Fatalf("login cookie not carried into gpio, got %q", cookie)
	}
	if !strings.Contains(body, `"type":"reset"`) || !strings.Contains(body, `"duration":800`) {
		t.Fatalf("reset gpio body wrong: %s", body)
	}
}

func TestNanoKVMOffIsLongPress(t *testing.T) {
	var body, cookie string
	var loginHits int
	srv := nanoServer(t, "0", "0", &body, &loginHits, &cookie)
	defer srv.Close()

	if err := mustNano(t, srv.URL).Off(context.Background()); err != nil {
		t.Fatalf("Off: %v", err)
	}
	if !strings.Contains(body, `"type":"power"`) || !strings.Contains(body, `"duration":6000`) {
		t.Fatalf("off should be a long power press, got: %s", body)
	}
}

func TestNanoKVMPowerShortPress(t *testing.T) {
	var body, cookie string
	var loginHits int
	srv := nanoServer(t, "0", "0", &body, &loginHits, &cookie)
	defer srv.Close()

	if err := mustNano(t, srv.URL).Power(context.Background()); err != nil {
		t.Fatalf("Power: %v", err)
	}
	if !strings.Contains(body, `"type":"power"`) || !strings.Contains(body, `"duration":800`) {
		t.Fatalf("power should be a short press, got: %s", body)
	}
}

func TestNanoKVMLoginFailureSkipsGpio(t *testing.T) {
	var body, cookie string
	var loginHits int
	srv := nanoServer(t, "1001", "0", &body, &loginHits, &cookie) // login code != 0
	defer srv.Close()

	if err := mustNano(t, srv.URL).Reset(context.Background()); err == nil {
		t.Fatal("expected login failure to error")
	}
	if body != "" {
		t.Fatalf("gpio must not be called after a failed login, got body %q", body)
	}
}

func TestNewDefaultsToNanokvm(t *testing.T) {
	p, err := New(config.KVMConfig{Host: "x"}, "x", func() (string, error) { return "pw", nil })
	if err != nil {
		t.Fatalf("empty type should default to nanokvm: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}

func TestNanoKVMWebURL(t *testing.T) {
	p, _ := New(config.KVMConfig{Type: "nanokvm", Scheme: "https"}, "alg00001-kvm", func() (string, error) { return "", nil })
	if got := p.WebURL(); got != "https://alg00001-kvm" {
		t.Fatalf("WebURL: got %q", got)
	}
}
