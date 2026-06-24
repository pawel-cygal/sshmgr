package kvm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sshmgr/internal/config"
)

func mustNano(t *testing.T, srvURL string) Provider {
	t.Helper()
	host := strings.TrimPrefix(srvURL, "http://")
	p, err := New(config.KVMConfig{Type: "nanokvm", Scheme: "http"}, host, func() (string, error) { return "pw", nil })
	if err != nil {
		t.Fatalf("New nanokvm: %v", err)
	}
	return p
}

// nanoServer mimics a NanoKVM: login returns a JWT in data.token (no Set-Cookie,
// like the real device), and gpio requires that token back as the cookie.
func nanoServer(t *testing.T, loginCode, gpioCode string, gotBody, gotCookie *string, loginHits *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		*loginHits++
		w.Write([]byte(`{"code":` + loginCode + `,"data":{"token":"tok123"}}`))
	})
	mux.HandleFunc("/api/vm/gpio", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*gotBody = string(b)
		if c, err := r.Cookie("nano-kvm-token"); err == nil {
			*gotCookie = c.Value
		}
		w.Write([]byte(`{"code":` + gpioCode + `}`))
	})
	return httptest.NewServer(mux)
}

func TestNanoKVMResetLazyLoginThenGpio(t *testing.T) {
	var body, cookie string
	var loginHits int
	srv := nanoServer(t, "0", "0", &body, &cookie, &loginHits)
	defer srv.Close()

	if err := mustNano(t, srv.URL).Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if loginHits != 1 {
		t.Fatalf("expected exactly one lazy login, got %d", loginHits)
	}
	if cookie != "tok123" {
		t.Fatalf("token from data.token must be sent as the nano-kvm-token cookie, got %q", cookie)
	}
	if !strings.Contains(body, `"type":"reset"`) || !strings.Contains(body, `"duration":800`) {
		t.Fatalf("reset gpio body wrong: %s", body)
	}
}

func TestNanoKVMOffIsLongPress(t *testing.T) {
	var body, cookie string
	var loginHits int
	srv := nanoServer(t, "0", "0", &body, &cookie, &loginHits)
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
	srv := nanoServer(t, "0", "0", &body, &cookie, &loginHits)
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
	srv := nanoServer(t, "-4", "0", &body, &cookie, &loginHits) // login code != 0
	defer srv.Close()

	if err := mustNano(t, srv.URL).Reset(context.Background()); err == nil {
		t.Fatal("expected login failure to error")
	}
	if body != "" {
		t.Fatalf("gpio must not be called after a failed login, got body %q", body)
	}
}

func TestNanoKVMLoginSendsEncryptedPassword(t *testing.T) {
	var loginBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		loginBody = string(b)
		w.Write([]byte(`{"code":0,"data":{"token":"t"}}`))
	})
	mux.HandleFunc("/api/vm/gpio", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"code":0}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	p, _ := New(config.KVMConfig{Type: "nanokvm", Scheme: "http"}, host, func() (string, error) { return "s3cret", nil })
	if err := p.Power(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The plaintext password must never appear on the wire; the value must be a
	// CryptoJS/OpenSSL "Salted__" blob that decrypts back to the plaintext.
	if strings.Contains(loginBody, "s3cret") {
		t.Fatalf("plaintext password leaked in login body: %s", loginBody)
	}
	var lb struct{ Password string }
	if err := jsonUnmarshalField(loginBody, "password", &lb.Password); err != nil {
		t.Fatalf("no password field: %v", err)
	}
	if got := decryptCryptoJS(t, lb.Password, "nanokvm-sipeed-2024"); got != "s3cret" {
		t.Fatalf("encrypted password did not round-trip, decrypted=%q", got)
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
	p, _ := New(config.KVMConfig{Type: "nanokvm", Scheme: "http"}, "alg00001-kvm", func() (string, error) { return "", nil })
	if got := p.WebURL(); got != "http://alg00001-kvm" {
		t.Fatalf("WebURL: got %q", got)
	}
}

// --- test helpers: decrypt the CryptoJS/OpenSSL blob to prove the round-trip ---

func jsonUnmarshalField(body, field string, dst *string) error {
	// tiny extractor to avoid importing encoding/json twice; body is small JSON
	i := strings.Index(body, `"`+field+`":"`)
	if i < 0 {
		return io.EOF
	}
	rest := body[i+len(field)+4:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return io.EOF
	}
	*dst = rest[:j]
	return nil
}

func decryptCryptoJS(t *testing.T, urlEncoded, passphrase string) string {
	t.Helper()
	b64, err := url.QueryUnescape(urlEncoded)
	if err != nil {
		t.Fatalf("unescape: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if len(raw) < 16 || string(raw[:8]) != "Salted__" {
		t.Fatalf("missing Salted__ prefix")
	}
	salt := raw[8:16]
	ct := raw[16:]
	// EVP_BytesToKey (MD5) — same KDF the driver must use.
	var d, prev []byte
	for len(d) < 48 {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(passphrase))
		h.Write(salt)
		prev = h.Sum(nil)
		d = append(d, prev...)
	}
	block, _ := aes.NewCipher(d[:32])
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, d[32:48]).CryptBlocks(pt, ct)
	n := int(pt[len(pt)-1]) // strip PKCS7
	return string(pt[:len(pt)-n])
}
