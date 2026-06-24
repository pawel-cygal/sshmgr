package kvm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // EVP_BytesToKey KDF mandated by NanoKVM's CryptoJS login, not used for security
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"sshmgr/internal/config"
)

func init() { Register("nanokvm", newNanoKVM) }

// Press durations (ms): short taps for power/reset, a long hold to force off.
const (
	pressShort = 800
	pressForce = 6000
	// loginKey is the CryptoJS passphrase the NanoKVM web frontend uses to
	// obfuscate the password on HTTP devices.
	loginKey = "nanokvm-sipeed-2024"
	// authCookie is where the device expects the JWT back (it does NOT Set-Cookie;
	// the web client copies data.token into this cookie itself).
	authCookie = "nano-kvm-token"
)

// nanoKVM drives a Sipeed NanoKVM over its HTTP API. Login returns a JWT in
// data.token (no Set-Cookie); the driver sends it back as the nano-kvm-token
// cookie on every subsequent call. The password is encrypted client-side with
// CryptoJS's OpenSSL-compatible AES-256-CBC. Login is lazy.
type nanoKVM struct {
	client *http.Client
	base   string
	user   string
	pass   PasswordFunc

	mu    sync.Mutex
	token string
}

func newNanoKVM(k config.KVMConfig, resolvedHost string, pass PasswordFunc) (Provider, error) {
	if resolvedHost == "" {
		return nil, errors.New("kvm host is empty")
	}
	user := k.User
	if user == "" {
		user = "admin"
	}
	return &nanoKVM{client: httpClient(k), base: BaseURL(k, resolvedHost), user: user, pass: pass}, nil
}

type apiResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (n *nanoKVM) ensureAuth(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.token != "" {
		return nil
	}
	pw, err := n.pass()
	if err != nil {
		return fmt.Errorf("resolve kvm password: %w", err)
	}
	enc, err := encryptPassword(pw, loginKey)
	if err != nil {
		return fmt.Errorf("encrypt kvm password: %w", err)
	}
	var resp apiResp
	if err := n.post(ctx, "/api/auth/login", map[string]string{"username": n.user, "password": enc}, &resp); err != nil {
		return fmt.Errorf("kvm login: %w", err)
	}
	if resp.Code != 0 {
		return fmt.Errorf("kvm login rejected (code %d) %s", resp.Code, resp.Msg)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(resp.Data, &tok)
	if tok.Token == "" {
		return errors.New("kvm login returned no token")
	}
	n.token = tok.Token
	return nil
}

func (n *nanoKVM) gpio(ctx context.Context, kind string, durationMS int) error {
	if err := n.ensureAuth(ctx); err != nil {
		return err
	}
	var resp apiResp
	if err := n.post(ctx, "/api/vm/gpio", map[string]any{"type": kind, "duration": durationMS}, &resp); err != nil {
		return fmt.Errorf("kvm %s: %w", kind, err)
	}
	if resp.Code != 0 {
		return fmt.Errorf("kvm %s rejected (code %d) %s", kind, resp.Code, resp.Msg)
	}
	return nil
}

func (n *nanoKVM) Reset(ctx context.Context) error { return n.gpio(ctx, "reset", pressShort) }
func (n *nanoKVM) Power(ctx context.Context) error { return n.gpio(ctx, "power", pressShort) }
func (n *nanoKVM) Off(ctx context.Context) error   { return n.gpio(ctx, "power", pressForce) }

// Status authenticates and reads /api/vm/info, returning a short summary.
func (n *nanoKVM) Status(ctx context.Context) (string, error) {
	if err := n.ensureAuth(ctx); err != nil {
		return "", err
	}
	var resp apiResp
	if err := n.get(ctx, "/api/vm/info", &resp); err != nil {
		return "reachable (auth ok; /api/vm/info unavailable)", nil
	}
	var info struct {
		Application string `json:"application"`
		IP          string `json:"ip"`
		Mdns        string `json:"mdns"`
	}
	_ = json.Unmarshal(resp.Data, &info)
	parts := []string{"online"}
	if info.Application != "" {
		parts = append(parts, "fw "+info.Application)
	}
	if info.IP != "" {
		parts = append(parts, "ip "+info.IP)
	}
	if info.Mdns != "" {
		parts = append(parts, info.Mdns)
	}
	return strings.Join(parts, " · "), nil
}

func (n *nanoKVM) WebURL() string { return n.base }

func (n *nanoKVM) post(ctx context.Context, path string, body any, out *apiResp) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return n.do(req, out)
}

func (n *nanoKVM) get(ctx context.Context, path string, out *apiResp) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.base+path, nil)
	if err != nil {
		return err
	}
	return n.do(req, out)
}

func (n *nanoKVM) do(req *http.Request, out *apiResp) error {
	if n.token != "" {
		req.AddCookie(&http.Cookie{Name: authCookie, Value: n.token})
	}
	r, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", r.StatusCode, snippet(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// encryptPassword reproduces CryptoJS.AES.encrypt(password, passphrase).toString()
// then encodeURIComponent: an OpenSSL "Salted__"+salt+ciphertext blob (AES-256-CBC,
// key/iv derived from the passphrase via EVP_BytesToKey/MD5), base64-encoded and
// URL-escaped. This is what the NanoKVM web UI sends on HTTP devices.
func encryptPassword(plain, passphrase string) (string, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, iv := evpBytesToKey([]byte(passphrase), salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plain), aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	blob := append([]byte("Salted__"), salt...)
	blob = append(blob, ct...)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(blob)), nil
}

// evpBytesToKey is OpenSSL's MD5-based key derivation, as used by CryptoJS.
func evpBytesToKey(passphrase, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var d, prev []byte
	for len(d) < keyLen+ivLen {
		h := md5.New() //nolint:gosec // protocol-mandated KDF
		h.Write(prev)
		h.Write(passphrase)
		h.Write(salt)
		prev = h.Sum(nil)
		d = append(d, prev...)
	}
	return d[:keyLen], d[keyLen : keyLen+ivLen]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
