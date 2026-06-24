// Package kvm controls out-of-band KVM power controllers (reset/power/off),
// behind a backend-agnostic Provider interface. NanoKVM is the first driver;
// other types (PiKVM, IPMI, Redfish, a generic command/webhook) can register
// themselves without touching the CLI or TUI.
package kvm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"sshmgr/internal/config"
)

// Provider is the seam every KVM backend implements. Power/reset/off act on the
// target machine's ATX lines; Status reports power state; WebURL is the device's
// browser UI.
type Provider interface {
	Reset(context.Context) error
	Power(context.Context) error // short power-button press
	Off(context.Context) error   // long press / force off
	Status(context.Context) (string, error)
	WebURL() string
}

// PasswordFunc lazily resolves the KVM password (resolved on first auth so a
// dry action like WebURL needs no secret access).
type PasswordFunc func() (string, error)

// Driver builds a Provider from a resolved KVM config, the already
// placeholder-expanded host, and a password resolver.
type Driver func(k config.KVMConfig, resolvedHost string, pass PasswordFunc) (Provider, error)

var (
	mu      sync.RWMutex
	drivers = map[string]Driver{}
)

// Register makes a driver available under a kvm `type`. Drivers call this from
// their init().
func Register(typ string, d Driver) {
	mu.Lock()
	defer mu.Unlock()
	drivers[typ] = d
}

// New builds the Provider for k.Type (default "nanokvm").
func New(k config.KVMConfig, resolvedHost string, pass PasswordFunc) (Provider, error) {
	typ := k.Type
	if typ == "" {
		typ = "nanokvm"
	}
	mu.RLock()
	d := drivers[typ]
	mu.RUnlock()
	if d == nil {
		return nil, fmt.Errorf("unknown kvm type %q", typ)
	}
	return d(k, resolvedHost, pass)
}

// BaseURL builds scheme://host[:port] for a resolved KVM host.
func BaseURL(k config.KVMConfig, resolvedHost string) string {
	scheme := k.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := resolvedHost
	if k.Port != 0 {
		host = net.JoinHostPort(resolvedHost, strconv.Itoa(k.Port))
	}
	return scheme + "://" + host
}

// httpClient returns an HTTP client for talking to a KVM. TLS verification is
// skipped by default (NanoKVM ships a self-signed cert); set kvm.insecure: false
// to require a valid certificate. The skip is scoped to this client only.
func httpClient(k config.KVMConfig) *http.Client {
	insecure := k.Insecure == nil || *k.Insecure
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed KVM cert, opt-out via config
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}
