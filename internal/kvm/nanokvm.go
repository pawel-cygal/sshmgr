package kvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"

	"sshmgr/internal/config"
)

func init() { Register("nanokvm", newNanoKVM) }

// Press durations (ms): short taps for power/reset, a long hold to force off.
const (
	pressShort = 800
	pressForce = 6000
)

// nanoKVM drives a Sipeed NanoKVM over its HTTP API. Auth is a JWT returned by
// /api/auth/login as a cookie; the client's cookie jar carries it into
// subsequent /api/vm/gpio calls. Login is lazy (first action that needs it).
type nanoKVM struct {
	client *http.Client
	base   string
	user   string
	pass   PasswordFunc

	mu     sync.Mutex
	authed bool
}

func newNanoKVM(k config.KVMConfig, resolvedHost string, pass PasswordFunc) (Provider, error) {
	if resolvedHost == "" {
		return nil, errors.New("kvm host is empty")
	}
	c := httpClient(k)
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c.Jar = jar
	user := k.User
	if user == "" {
		user = "admin"
	}
	return &nanoKVM{client: c, base: BaseURL(k, resolvedHost), user: user, pass: pass}, nil
}

// apiResp is the common NanoKVM envelope: code 0 means success.
type apiResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (n *nanoKVM) ensureAuth(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.authed {
		return nil
	}
	pw, err := n.pass()
	if err != nil {
		return fmt.Errorf("resolve kvm password: %w", err)
	}
	var resp apiResp
	if err := n.post(ctx, "/api/auth/login", map[string]string{"username": n.user, "password": pw}, &resp); err != nil {
		return fmt.Errorf("kvm login: %w", err)
	}
	if resp.Code != 0 {
		return fmt.Errorf("kvm login rejected (code %d) %s", resp.Code, resp.Msg)
	}
	n.authed = true
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

// Status authenticates and reports what the device exposes. The exact
// power-state endpoint varies by firmware; this is best-effort and verified on a
// real device. Auth success alone confirms the KVM is reachable and credentials
// are valid.
func (n *nanoKVM) Status(ctx context.Context) (string, error) {
	if err := n.ensureAuth(ctx); err != nil {
		return "", err
	}
	var resp apiResp
	if err := n.get(ctx, "/api/vm/info", &resp); err != nil {
		return "reachable (auth ok; state endpoint unavailable)", nil
	}
	if len(resp.Data) > 0 {
		return strings.TrimSpace(string(resp.Data)), nil
	}
	return "reachable (auth ok)", nil
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

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
