package fwd

import (
	"net"
	"strings"
	"testing"
)

func TestPreflightListenRejectsBusyAddr(t *testing.T) {
	// Take an ephemeral port; PreflightListen on the same address must
	// fail — that is the entire point of the helper (fail fast instead of
	// racing through the SSH handshake to bind:address-already-in-use).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	err = PreflightListen(addr)
	if err == nil {
		t.Fatalf("preflight should reject busy %s", addr)
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("error must mention the busy address: %v", err)
	}
}
