// Package fwd implements SSH port forwarding (-L local, -R remote, -D SOCKS5
// dynamic) over an existing *ssh.Client. All three reuse sshc's connect chain
// (proxy_jump, proxy_command, password backends), so a tunnel through a
// bastion jumphost works exactly the same as a direct LAN connect.
package fwd

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sshmgr/internal/theme"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

// Local opens listenAddr on the local machine; each accepted connection is
// tunneled through client to targetAddr (host:port). Blocks until ctx is
// cancelled or a fatal error occurs.
func Local(ctx context.Context, client *ssh.Client, listenAddr, targetAddr string) error {
	if !strings.Contains(listenAddr, ":") {
		listenAddr = "127.0.0.1:" + listenAddr
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("local listen %s: %w", listenAddr, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "%s[sshmgr]%s -L %s%s%s -> %s%s%s (Ctrl-C to stop)\n",
		ansiPrimary(), reset(), ansiAccent(), ln.Addr(), reset(),
		ansiAccent(), targetAddr, reset())

	go func() { <-ctx.Done(); ln.Close() }()
	for {
		local, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if isTransientAcceptErr(err) {
				fmt.Fprintf(os.Stderr, "[fwd] transient accept error: %v (continuing)\n", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go func(local net.Conn) {
			defer local.Close()
			remote, err := client.Dial("tcp", targetAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fwd] dial %s: %v\n", targetAddr, err)
				return
			}
			defer remote.Close()
			bidirCopy(local, remote)
		}(local)
	}
}

// Remote requests listenAddr on the remote (server) side; each accepted
// connection is forwarded through the client to localTarget on the local
// machine. Mirrors `ssh -R listenAddr:localTarget`.
func Remote(ctx context.Context, client *ssh.Client, listenAddr, localTarget string) error {
	if !strings.Contains(listenAddr, ":") {
		listenAddr = "0.0.0.0:" + listenAddr
	}
	ln, err := client.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("remote listen %s: %w", listenAddr, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "%s[sshmgr]%s -R remote:%s%s%s -> local:%s%s%s (Ctrl-C to stop)\n",
		ansiPrimary(), reset(), ansiAccent(), listenAddr, reset(),
		ansiAccent(), localTarget, reset())

	go func() { <-ctx.Done(); ln.Close() }()
	for {
		remote, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if isTransientAcceptErr(err) {
				fmt.Fprintf(os.Stderr, "[fwd] transient accept error: %v (continuing)\n", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go func(remote net.Conn) {
			defer remote.Close()
			local, err := net.Dial("tcp", localTarget)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fwd] dial local %s: %v\n", localTarget, err)
				return
			}
			defer local.Close()
			bidirCopy(remote, local)
		}(remote)
	}
}

// isTransientAcceptErr matches errors that don't mean the listener is dead —
// EMFILE/ENFILE (out of fds), brief network blips, etc.
func isTransientAcceptErr(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "too many open files") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "no buffer space")
}

// Dynamic starts a SOCKS5 proxy on listenAddr. Each SOCKS request is dialed
// through client, so the local machine effectively browses the remote network
// (use as a browser SOCKS proxy to reach internal services).
func Dynamic(ctx context.Context, client *ssh.Client, listenAddr string) error {
	if !strings.Contains(listenAddr, ":") {
		listenAddr = "127.0.0.1:" + listenAddr
	}
	conf := &socks5.Config{
		Dial: func(_ context.Context, network, addr string) (net.Conn, error) {
			return client.Dial(network, addr)
		},
		Logger: stdlog.New(io.Discard, "", 0),
	}
	server, err := socks5.New(conf)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("socks listen %s: %w", listenAddr, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "%s[sshmgr]%s -D SOCKS5 proxy on %s%s%s — set browser socks5://%s%s%s (Ctrl-C to stop)\n",
		ansiPrimary(), reset(), ansiAccent(), ln.Addr(), reset(),
		ansiAccent(), ln.Addr(), reset())
	go func() { <-ctx.Done(); ln.Close() }()
	if err := server.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// ParseLocalSpec parses "[bind:]port[:host:port]" or "port:host:port" into
// (listenAddr, targetAddr). Forms accepted:
//
//	8080:remote:3306                          -> 127.0.0.1:8080 -> remote:3306
//	127.0.0.1:8080:remote:3306                -> 127.0.0.1:8080 -> remote:3306
func ParseLocalSpec(spec string) (listen, target string, err error) {
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 3: // port:host:port
		if _, e := strconv.Atoi(parts[0]); e != nil {
			return "", "", fmt.Errorf("bad local port %q", parts[0])
		}
		if _, e := strconv.Atoi(parts[2]); e != nil {
			return "", "", fmt.Errorf("bad remote port %q", parts[2])
		}
		return "127.0.0.1:" + parts[0], parts[1] + ":" + parts[2], nil
	case 4: // bind:port:host:port
		if _, e := strconv.Atoi(parts[1]); e != nil {
			return "", "", fmt.Errorf("bad local port %q", parts[1])
		}
		if _, e := strconv.Atoi(parts[3]); e != nil {
			return "", "", fmt.Errorf("bad remote port %q", parts[3])
		}
		return parts[0] + ":" + parts[1], parts[2] + ":" + parts[3], nil
	}
	return "", "", fmt.Errorf("expected [bind:]port:host:port, got %q", spec)
}

// ParseRemoteSpec parses an -R spec into (remoteListen, localTarget). The
// wire format is identical to -L's "[bind:]port:host:port" — only the
// semantics differ (the first listen is opened on the remote side and
// connections from it are dialed to the local host:port).
//
// We deliberately reuse ParseLocalSpec since the validation rules are the
// same; nothing here re-checks that the second host is reachable locally
// (defer that to net.Dial in the forward goroutine).
func ParseRemoteSpec(spec string) (remoteListen, localTarget string, err error) {
	return ParseLocalSpec(spec)
}

// ParseDynamicSpec parses "[bind:]port" for SOCKS5 dynamic forward.
func ParseDynamicSpec(spec string) (listen string, err error) {
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 1:
		if _, e := strconv.Atoi(parts[0]); e != nil {
			return "", fmt.Errorf("bad port %q", parts[0])
		}
		return "127.0.0.1:" + parts[0], nil
	case 2:
		if _, e := strconv.Atoi(parts[1]); e != nil {
			return "", fmt.Errorf("bad port %q", parts[1])
		}
		return parts[0] + ":" + parts[1], nil
	}
	return "", fmt.Errorf("expected [bind:]port, got %q", spec)
}

// CtxOnSignal returns a context cancelled on SIGINT/SIGTERM so forwards exit
// cleanly when the user hits Ctrl-C.
func CtxOnSignal() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		signal.Stop(sigs)
		cancel()
	}()
	return ctx, cancel
}

// closeWriter is implemented by *net.TCPConn and ssh channels; lets us
// half-close in the direction whose source has hit EOF, keeping the other
// direction open so in-flight bytes still flow.
type closeWriter interface{ CloseWrite() error }

func bidirCopy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		if cw, ok := a.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		if cw, ok := b.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func ansiPrimary() string { return theme.ANSI(theme.Current.Primary) }
func ansiAccent() string  { return theme.ANSI(theme.Current.AccentB) }
func reset() string       { return theme.Reset() }

// PreflightListen reports whether addr is already occupied by another local
// listener. Used by `sshmgr fwd` to fail fast on -L / -D when the user's
// intended local port is taken — much clearer than racing through the SSH
// handshake only to see ssh print "bind: address already in use" later.
func PreflightListen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("local bind %s is busy: %w", addr, err)
	}
	return l.Close()
}
