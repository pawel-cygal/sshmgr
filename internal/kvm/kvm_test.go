package kvm

import (
	"context"
	"testing"

	"sshmgr/internal/config"
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
}
