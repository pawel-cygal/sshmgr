package fwd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SetupX11 requests X11 forwarding on session and starts a goroutine that
// accepts incoming x11 channels from the SSH server, routing each one to the
// local X server (resolved from $DISPLAY).
//
// Call this AFTER session.RequestPty (or before, doesn't matter) but BEFORE
// session.Shell/Run.
func SetupX11(client *ssh.Client, session *ssh.Session) error {
	display := os.Getenv("DISPLAY")
	if display == "" {
		return fmt.Errorf("DISPLAY is not set — start a local X server first")
	}
	localX, err := resolveX11Socket(display)
	if err != nil {
		return err
	}
	authProtocol, realCookie, err := loadXAuthority(display)
	if err != nil {
		return err
	}

	// The remote side receives a one-time fake cookie. On every incoming X11
	// channel we verify and replace it with the real local Xauthority cookie
	// before forwarding the setup packet to the local X server. This is the
	// same cookie-spoofing boundary used by OpenSSH: the real credential never
	// leaves the local machine.
	cookieBytes := make([]byte, 16)
	if _, err := rand.Read(cookieBytes); err != nil {
		return err
	}

	payload := ssh.Marshal(&x11Req{
		SingleConnection: false,
		AuthProtocol:     authProtocol,
		AuthCookie:       hex.EncodeToString(cookieBytes),
		ScreenNumber:     0,
	})
	if ok, err := session.SendRequest("x11-req", true, payload); err != nil {
		return fmt.Errorf("x11-req: %w", err)
	} else if !ok {
		return fmt.Errorf("x11-req rejected by server (X11Forwarding disabled?)")
	}

	// Accept x11 channels opened by the remote and pipe them to the local X
	// server. Runs until the session ends.
	x11 := client.HandleChannelOpen("x11")
	if x11 == nil {
		return fmt.Errorf("ssh client already handles x11 channels")
	}
	go func() {
		for newCh := range x11 {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go forwardX11Channel(ch, localX, authProtocol, cookieBytes, realCookie)
		}
	}()
	return nil
}

type x11Req struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

func resolveX11Socket(display string) (string, error) {
	// DISPLAY is typically ":N" (Unix socket) or "host:N" / "host:N.M".
	// XQuartz uses a launchd-managed absolute Unix socket display.
	if strings.HasPrefix(display, "/") {
		return display, nil
	}
	host, num := splitDisplay(display)
	if host == "" || host == "unix" {
		return fmt.Sprintf("/tmp/.X11-unix/X%d", num), nil
	}
	return fmt.Sprintf("%s:%d", host, 6000+num), nil
}

func splitDisplay(d string) (host string, num int) {
	d = strings.TrimSpace(d)
	idx := strings.LastIndex(d, ":")
	if idx < 0 {
		return d, 0
	}
	host = d[:idx]
	disp := d[idx+1:]
	if dot := strings.Index(disp, "."); dot >= 0 {
		disp = disp[:dot]
	}
	n, _ := strconv.Atoi(disp)
	return host, n
}

func loadXAuthority(display string) (string, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "xauth", "list", display).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return "", nil, fmt.Errorf("read Xauthority for DISPLAY=%s: %w", display, ctx.Err())
		}
		return "", nil, fmt.Errorf("read Xauthority for DISPLAY=%s with xauth: %w (%s)",
			display, err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[len(fields)-2] != "MIT-MAGIC-COOKIE-1" {
			continue
		}
		cookie, err := hex.DecodeString(fields[len(fields)-1])
		if err != nil || len(cookie) == 0 {
			continue
		}
		return fields[len(fields)-2], cookie, nil
	}
	return "", nil, fmt.Errorf("no MIT-MAGIC-COOKIE-1 entry in Xauthority for DISPLAY=%s", display)
}

func forwardX11Channel(ch ssh.Channel, localX, protocol string, fakeCookie, realCookie []byte) {
	defer ch.Close()
	network := "unix"
	if strings.Contains(localX, ":") && !strings.HasPrefix(localX, "/") {
		network = "tcp"
	}
	conn, err := net.Dial(network, localX)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x11] dial local X (%s): %v\n", localX, err)
		return
	}
	defer conn.Close()
	if err := rewriteX11Setup(ch, conn, protocol, fakeCookie, realCookie); err != nil {
		fmt.Fprintf(os.Stderr, "[x11] reject setup packet: %v\n", err)
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, conn); done <- struct{}{} }()
	<-done
}

// rewriteX11Setup consumes the first X11 connection setup packet, verifies the
// fake credential issued to the remote process, and writes an equivalent setup
// packet containing the real local credential. Subsequent bytes can be copied
// transparently in both directions.
func rewriteX11Setup(src io.Reader, dst io.Writer, protocol string, fakeCookie, realCookie []byte) error {
	header := make([]byte, 12)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	var order binary.ByteOrder
	switch header[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return fmt.Errorf("invalid byte order %#x", header[0])
	}
	nameLen := int(order.Uint16(header[6:8]))
	dataLen := int(order.Uint16(header[8:10]))
	if nameLen > 4096 || dataLen > 4096 {
		return fmt.Errorf("unreasonable auth lengths %d/%d", nameLen, dataLen)
	}
	namePadded := padded4(nameLen)
	dataPadded := padded4(dataLen)
	auth := make([]byte, namePadded+dataPadded)
	if _, err := io.ReadFull(src, auth); err != nil {
		return fmt.Errorf("read auth data: %w", err)
	}
	name := auth[:nameLen]
	data := auth[namePadded : namePadded+dataLen]
	if string(name) != protocol {
		return fmt.Errorf("unexpected auth protocol %q", name)
	}
	if !bytes.Equal(data, fakeCookie) {
		return fmt.Errorf("fake cookie mismatch")
	}
	if len(realCookie) > int(^uint16(0)) {
		return fmt.Errorf("real cookie is too long")
	}

	order.PutUint16(header[8:10], uint16(len(realCookie)))
	packet := make([]byte, 0, len(header)+namePadded+padded4(len(realCookie)))
	packet = append(packet, header...)
	packet = append(packet, name...)
	packet = append(packet, make([]byte, namePadded-nameLen)...)
	packet = append(packet, realCookie...)
	packet = append(packet, make([]byte, padded4(len(realCookie))-len(realCookie))...)
	if _, err := dst.Write(packet); err != nil {
		return fmt.Errorf("write rewritten setup: %w", err)
	}
	return nil
}

func padded4(n int) int { return (n + 3) &^ 3 }
