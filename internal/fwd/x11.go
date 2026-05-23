package fwd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

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

	// Generate a fake xauth cookie. Real OpenSSH reads ~/.Xauthority but most
	// servers accept any 32-hex cookie when X11Forwarding is set non-strict
	// (and we use trusted forwarding so cookie matching is skipped).
	cookieBytes := make([]byte, 16)
	if _, err := rand.Read(cookieBytes); err != nil {
		return err
	}
	cookie := hex.EncodeToString(cookieBytes)

	payload := ssh.Marshal(&x11Req{
		SingleConnection: false,
		AuthProtocol:     "MIT-MAGIC-COOKIE-1",
		AuthCookie:       cookie,
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
			go forwardX11Channel(ch, localX)
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

func forwardX11Channel(ch ssh.Channel, localX string) {
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
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, conn); done <- struct{}{} }()
	<-done
}
