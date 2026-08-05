package fwd

import (
	"bytes"
	"encoding/binary"
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

func TestRewriteX11SetupReplacesCookieForBothByteOrders(t *testing.T) {
	fake := []byte("0123456789abcdef")
	real := []byte("real-cookie-value")
	for _, tc := range []struct {
		name  string
		mark  byte
		order binary.ByteOrder
	}{
		{"little", 'l', binary.LittleEndian},
		{"big", 'B', binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := x11SetupPacket(tc.mark, tc.order, "MIT-MAGIC-COOKIE-1", fake)
			var out bytes.Buffer
			if err := rewriteX11Setup(bytes.NewReader(packet), &out, "MIT-MAGIC-COOKIE-1", fake, real); err != nil {
				t.Fatal(err)
			}
			got := out.Bytes()
			if n := int(tc.order.Uint16(got[8:10])); n != len(real) {
				t.Fatalf("rewritten cookie length = %d, want %d", n, len(real))
			}
			nameLen := int(tc.order.Uint16(got[6:8]))
			start := 12 + padded4(nameLen)
			if !bytes.Equal(got[start:start+len(real)], real) {
				t.Fatalf("real cookie not written: %x", got[start:start+len(real)])
			}
		})
	}
}

func TestRewriteX11SetupRejectsUnissuedCookie(t *testing.T) {
	fake := []byte("0123456789abcdef")
	packet := x11SetupPacket('l', binary.LittleEndian, "MIT-MAGIC-COOKIE-1", []byte("attacker-cookie!"))
	var out bytes.Buffer
	err := rewriteX11Setup(bytes.NewReader(packet), &out, "MIT-MAGIC-COOKIE-1", fake, []byte("real-cookie-value"))
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected cookie mismatch, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("rejected setup leaked %d bytes to local X server", out.Len())
	}
}

func x11SetupPacket(mark byte, order binary.ByteOrder, protocol string, cookie []byte) []byte {
	header := make([]byte, 12)
	header[0] = mark
	order.PutUint16(header[2:4], 11)
	order.PutUint16(header[6:8], uint16(len(protocol)))
	order.PutUint16(header[8:10], uint16(len(cookie)))
	packet := append([]byte{}, header...)
	packet = append(packet, protocol...)
	packet = append(packet, make([]byte, padded4(len(protocol))-len(protocol))...)
	packet = append(packet, cookie...)
	packet = append(packet, make([]byte, padded4(len(cookie))-len(cookie))...)
	return packet
}

func TestParseForwardSpecsValidatePortsAndIPv6(t *testing.T) {
	listen, target, err := ParseLocalSpec("[::1]:8080:[2001:db8::5]:22")
	if err != nil {
		t.Fatal(err)
	}
	if listen != "[::1]:8080" || target != "[2001:db8::5]:22" {
		t.Fatalf("unexpected IPv6 parse: %q -> %q", listen, target)
	}
	for _, spec := range []string{"0:host:22", "65536:host:22", "22:host:-1", "abc:host:22"} {
		if _, _, err := ParseLocalSpec(spec); err == nil {
			t.Errorf("invalid spec %q accepted", spec)
		}
	}
	if got, err := ParseDynamicSpec("[::1]:1080"); err != nil || got != "[::1]:1080" {
		t.Fatalf("dynamic IPv6: got %q err=%v", got, err)
	}
}
