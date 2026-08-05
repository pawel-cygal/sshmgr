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
	"strings"
	"sync"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
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

// KnownType reports whether a provider driver is registered under typ.
func KnownType(typ string) bool {
	if typ == "" {
		typ = "nanokvm"
	}
	mu.RLock()
	defer mu.RUnlock()
	return drivers[typ] != nil
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
	if typ == "nanokvm" {
		if err := ValidateConfig(k, resolvedHost); err != nil {
			return nil, err
		}
	}
	return d(k, resolvedHost, pass)
}

// ValidateConfig checks the network portion shared by NanoKVM actions before
// an HTTP request is attempted. Keeping it exported lets `sshmgr lint` report
// the same errors without contacting the device.
func ValidateConfig(k config.KVMConfig, resolvedHost string) error {
	host := strings.TrimSpace(resolvedHost)
	if host == "" {
		return fmt.Errorf("kvm host is empty")
	}
	if strings.ContainsAny(host, "/\\?#@ \t\r\n") {
		return fmt.Errorf("invalid kvm host %q (configure scheme and port separately)", resolvedHost)
	}
	if strings.Contains(host, ":") {
		plainIP := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if net.ParseIP(plainIP) == nil {
			name, portText, err := net.SplitHostPort(host)
			if err != nil || strings.TrimSpace(name) == "" {
				return fmt.Errorf("invalid kvm host or host:port %q", resolvedHost)
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port in kvm host %q", resolvedHost)
			}
			if k.Port != 0 {
				return fmt.Errorf("kvm port is configured both in host %q and port: %d", resolvedHost, k.Port)
			}
		}
	}
	if k.Port < 0 || k.Port > 65535 {
		return fmt.Errorf("invalid kvm port %d (want 1..65535)", k.Port)
	}
	scheme := strings.ToLower(strings.TrimSpace(k.Scheme))
	if scheme != "" && scheme != "http" && scheme != "https" {
		return fmt.Errorf("invalid kvm scheme %q (want http or https)", k.Scheme)
	}
	return nil
}

// BaseURL builds scheme://host[:port] for a resolved KVM host.
func BaseURL(k config.KVMConfig, resolvedHost string) string {
	scheme := strings.ToLower(strings.TrimSpace(k.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	host := strings.TrimSpace(resolvedHost)
	if _, _, err := net.SplitHostPort(host); err == nil && k.Port == 0 {
		return scheme + "://" + host
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if k.Port != 0 {
		host = net.JoinHostPort(host, strconv.Itoa(k.Port))
	} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
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
