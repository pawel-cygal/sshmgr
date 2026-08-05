package sshc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/fwd"
	"github.com/systeampl/sshmgr/internal/secret"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// ConnectAlias resolves the alias from cfg and connects, following proxy_jump
// chains if present. The returned client owns the full chain — closing it
// closes all upstream jump clients too.
func ConnectAlias(cfg *config.Config, alias string) (*ssh.Client, error) {
	chain, err := connectChain(cfg, alias, map[string]bool{})
	if err != nil {
		return nil, err
	}
	target := chain[0]

	// Keepalive: server_alive_interval > 0 spins a goroutine that sends an
	// SSH global request every N seconds. After server_alive_count_max
	// (default 3) consecutive failures, close the client — same model as
	// OpenSSH's ClientAliveCountMax.
	if h, ok := cfg.ResolveHost(alias); ok && h.ServerAliveInterval > 0 {
		max := h.ServerAliveCountMax
		if max == 0 {
			max = 3
		}
		startKeepalive(target, time.Duration(h.ServerAliveInterval)*time.Second, max)
	}

	if len(chain) > 1 {
		return wrapWithChain(target, chain[1:]), nil
	}
	return target, nil
}

func startKeepalive(client *ssh.Client, interval time.Duration, maxFail int) {
	go func() {
		miss := 0
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				miss++
				if miss >= maxFail {
					_ = client.Close()
					return
				}
				continue
			}
			miss = 0
		}
	}()
}

func connectChain(cfg *config.Config, alias string, visited map[string]bool) ([]*ssh.Client, error) {
	if visited[alias] {
		return nil, fmt.Errorf("proxy_jump cycle detected at %q", alias)
	}
	visited[alias] = true

	h, ok := cfg.ResolveHost(alias)
	if !ok {
		return nil, fmt.Errorf("alias not found: %s", alias)
	}

	// proxy_command takes precedence over proxy_jump (matches OpenSSH semantics
	// and lets users delegate to system ssh when they need ProxyCommand-style
	// tricks like port knocking).
	if h.ProxyCommand != "" {
		c, err := dialViaProxyCommand(h)
		if err != nil {
			return nil, fmt.Errorf("connect %s via proxy_command: %w", alias, err)
		}
		return []*ssh.Client{c}, nil
	}

	if h.ProxyJump == "" {
		c, err := dialDirect(h)
		if err != nil {
			return nil, fmt.Errorf("connect %s: %w", alias, err)
		}
		return []*ssh.Client{c}, nil
	}

	upstream, err := connectChain(cfg, h.ProxyJump, visited)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", h.ProxyJump, err)
	}
	jump := upstream[0]

	c, err := dialThroughJump(jump, h)
	if err != nil {
		for _, u := range upstream {
			u.Close()
		}
		return nil, fmt.Errorf("connect %s via %s: %w", alias, h.ProxyJump, err)
	}
	return append([]*ssh.Client{c}, upstream...), nil
}

func dialDirect(h config.HostConfig) (*ssh.Client, error) {
	sshConfig, cleanupAuth, err := clientConfigFor(h)
	if err != nil {
		return nil, err
	}
	defer cleanupAuth()
	addr := net.JoinHostPort(h.Host, fmt.Sprintf("%d", h.Port))
	timeout := connectTimeout(h)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := newClientConnTimeout(conn, addr, sshConfig, timeout)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// dialViaProxyCommand executes the proxy_command (with %h/%p substituted)
// and uses its stdio as the SSH transport. Lets users delegate to OpenSSH
// for ProxyCommand-style tricks like port knocking (`ssh jump -W %h:%p`).
func dialViaProxyCommand(h config.HostConfig) (*ssh.Client, error) {
	pcmd := h.ProxyCommand
	if debugEnabled() && strings.HasPrefix(pcmd, "ssh ") {
		pcmd = "ssh -v " + strings.TrimPrefix(pcmd, "ssh ")
	}
	expanded := strings.ReplaceAll(pcmd, "%h", h.Host)
	expanded = strings.ReplaceAll(expanded, "%p", fmt.Sprintf("%d", h.Port))
	statusf("[sshmgr] proxy_command: %s\n", expanded)

	cmd, err := buildProxyCommand(pcmd, h.Host, h.Port)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Host, fmt.Sprintf("%d", h.Port))
	conn, err := newCmdConn(cmd, addr)
	if err != nil {
		return nil, err
	}
	sshConfig, cleanupAuth, err := clientConfigFor(h)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer cleanupAuth()
	statusf("[sshmgr] SSH handshake on tunnel -> %s (user=%s)\n", addr, h.User)
	sshConn, chans, reqs, err := newClientConnTimeout(conn, addr, sshConfig, connectTimeout(h))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake via proxy_command: %w", err)
	}
	statusf("[sshmgr] connected.\n")
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func debugEnabled() bool {
	v := os.Getenv("SSHMGR_DEBUG")
	return v != "" && v != "0" && !strings.EqualFold(v, "false") && !strings.EqualFold(v, "no")
}

// statusf writes a [sshmgr] status line unless SSHMGR_FROM_UI=1 (then the
// user is mid-TUI handoff and the chatter is just noise). Always shown when
// SSHMGR_DEBUG is on, regardless of FROM_UI.
func statusf(format string, args ...any) {
	if debugEnabled() || os.Getenv("SSHMGR_FROM_UI") != "1" {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func dialThroughJump(jump *ssh.Client, h config.HostConfig) (*ssh.Client, error) {
	addr := net.JoinHostPort(h.Host, fmt.Sprintf("%d", h.Port))
	timeout := connectTimeout(h)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := jump.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial via jump: %w", err)
	}
	sshConfig, cleanupAuth, err := clientConfigFor(h)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer cleanupAuth()
	sshConn, chans, reqs, err := newClientConnTimeout(conn, addr, sshConfig, timeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake via jump: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func clientConfigFor(h config.HostConfig) (*ssh.ClientConfig, func(), error) {
	auths, cleanupAuth, err := authMethods(h)
	if err != nil {
		return nil, func() {}, err
	}
	hk, err := hostKeyCallback(h.AutoAcceptHostKey)
	if err != nil {
		cleanupAuth()
		return nil, func() {}, err
	}
	timeout := connectTimeout(h)
	return &ssh.ClientConfig{
		User:            h.User,
		Auth:            auths,
		HostKeyCallback: hk,
		Timeout:         timeout,
	}, cleanupAuth, nil
}

func connectTimeout(h config.HostConfig) time.Duration {
	if h.ConnectTimeout > 0 {
		return time.Duration(h.ConnectTimeout) * time.Second
	}
	return 30 * time.Second
}

type clientConnResult struct {
	conn  ssh.Conn
	chans <-chan ssh.NewChannel
	reqs  <-chan *ssh.Request
	err   error
}

// newClientConnTimeout bounds the SSH handshake for transports where
// ssh.ClientConfig.Timeout is otherwise ignored (jump channels and
// proxy_command pipes). Closing raw on timeout unblocks the handshake goroutine.
func newClientConnTimeout(raw net.Conn, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	done := make(chan clientConnResult, 1)
	go func() {
		conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
		done <- clientConnResult{conn: conn, chans: chans, reqs: reqs, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		if result.err != nil {
			_ = raw.Close()
		}
		return result.conn, result.chans, result.reqs, result.err
	case <-timer.C:
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("SSH handshake with %s timed out after %s", addr, timeout)
	}
}

var (
	upstreamMu       sync.Mutex
	upstreamRegistry = map[*ssh.Client][]*ssh.Client{}
)

func wrapWithChain(target *ssh.Client, upstream []*ssh.Client) *ssh.Client {
	upstreamMu.Lock()
	upstreamRegistry[target] = upstream
	upstreamMu.Unlock()
	return target
}

// CloseChain closes target plus any registered upstream jump clients.
// Use this instead of client.Close() when proxy_jump may be in play.
func CloseChain(target *ssh.Client) {
	if target == nil {
		return
	}
	upstreamMu.Lock()
	upstream := upstreamRegistry[target]
	delete(upstreamRegistry, target)
	upstreamMu.Unlock()
	target.Close()
	for _, u := range upstream {
		_ = u.Close()
	}
}

// authMethods builds the authentication order and returns a cleanup function
// for any local ssh-agent connection it opens. The agent socket must remain
// open until the SSH handshake has completed because agent-backed signers call
// back through it while signing the authentication request.
func authMethods(h config.HostConfig) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	noCleanup := func() {}

	// KeyOnly: exactly the configured key, no fallback. Used by key-rotation
	// verification — the new key must succeed entirely on its own.
	if h.KeyOnly {
		if h.Key == "" {
			return nil, noCleanup, errors.New("key_only verification requires a key")
		}
		keyPath := config.ExpandPath(h.Key)
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, noCleanup, fmt.Errorf("cannot read SSH key %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err == nil {
			return []ssh.AuthMethod{ssh.PublicKeys(signer)}, noCleanup, nil
		}
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, noCleanup, fmt.Errorf("cannot parse SSH key %s: %w", keyPath, err)
		}
		// Encrypted rotation keys remain key-only by selecting the matching
		// signer from ssh-agent using the public .pub sidecar. Other agent keys
		// are never offered, preserving the rotation verification contract.
		pub, err := readPublicKeySidecar(keyPath)
		if err != nil {
			return nil, noCleanup, fmt.Errorf("encrypted key-only identity %s: %w", keyPath, err)
		}
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, noCleanup, fmt.Errorf("SSH key %s is encrypted; start ssh-agent and run ssh-add %s", keyPath, keyPath)
		}
		conn, err := net.DialTimeout("unix", sock, 2*time.Second)
		if err != nil {
			return nil, noCleanup, fmt.Errorf("dial ssh-agent for encrypted key %s: %w", keyPath, err)
		}
		agentSigners, err := agent.NewClient(conn).Signers()
		if err != nil {
			_ = conn.Close()
			return nil, noCleanup, fmt.Errorf("list ssh-agent identities: %w", err)
		}
		for _, candidate := range agentSigners {
			if bytes.Equal(candidate.PublicKey().Marshal(), pub.Marshal()) {
				var once sync.Once
				cleanup := func() { once.Do(func() { _ = conn.Close() }) }
				return []ssh.AuthMethod{ssh.PublicKeys(candidate)}, cleanup, nil
			}
		}
		_ = conn.Close()
		return nil, noCleanup, fmt.Errorf("encrypted key %s is not loaded in ssh-agent (run ssh-add %s)", keyPath, keyPath)
	}

	var encryptedKeyPath string
	if h.Key != "" {
		keyPath := config.ExpandPath(h.Key)
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, noCleanup, fmt.Errorf("cannot read SSH key %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		} else {
			var missing *ssh.PassphraseMissingError
			if !errors.As(err, &missing) {
				return nil, noCleanup, fmt.Errorf("cannot parse SSH key %s: %w", keyPath, err)
			}
			// Encrypted private keys are normally unlocked by ssh-add. Keep the
			// configured identity in the error context, then try the local agent.
			encryptedKeyPath = keyPath
		}
	}

	hasPassword := h.Password != "" || h.PasswordEnv != "" ||
		h.PasswordKeyring != "" || h.PasswordCmd != "" || h.PasswordPrompt

	var agentConn net.Conn
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.DialTimeout("unix", sock, 2*time.Second)
		if err == nil {
			agentConn = conn
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		} else if encryptedKeyPath != "" && !hasPassword {
			return nil, noCleanup, fmt.Errorf("SSH key %s is encrypted and ssh-agent at %s is unavailable: %w (run ssh-add %s)",
				encryptedKeyPath, sock, err, encryptedKeyPath)
		}
	} else if encryptedKeyPath != "" && !hasPassword {
		return nil, noCleanup, fmt.Errorf("SSH key %s is encrypted; start ssh-agent and run ssh-add %s, or configure a password backend",
			encryptedKeyPath, encryptedKeyPath)
	}
	cleanup := noCleanup
	if agentConn != nil {
		var once sync.Once
		cleanup = func() { once.Do(func() { _ = agentConn.Close() }) }
	}

	if hasPassword {
		methods = append(methods, ssh.PasswordCallback(func() (string, error) {
			return secret.ResolveHostPassword(h)
		}))
	}

	// Keyboard-interactive: only include when Duo auto-push is configured (we
	// need it for the Duo flow) or when there's no password backend (fallback
	// for hosts that purely use keyboard-interactive). Skipping it for plain
	// password hosts avoids Dropbear-style servers replying FAILURE to a
	// keyboard-interactive probe (`ssh: unexpected message type 51`).
	if h.AutoDuoPush || !hasPassword {
		methods = append(methods, ssh.KeyboardInteractive(keyboardInteractiveFn(h)))
	}
	return methods, cleanup, nil
}

func readPublicKeySidecar(privatePath string) (ssh.PublicKey, error) {
	path := privatePath + ".pub"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key sidecar %s: %w", path, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse public key sidecar %s: %w", path, err)
	}
	return pub, nil
}

func keyboardInteractiveFn(h config.HostConfig) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		reader := bufio.NewReader(os.Stdin)

		if instruction != "" {
			fmt.Fprintln(os.Stderr, instruction)
		}

		for i, q := range questions {
			lower := strings.ToLower(q)
			if h.AutoDuoPush && looksLikeDuoPrompt(lower) {
				fmt.Fprintln(os.Stderr, q+"1")
				fmt.Fprintln(os.Stderr, "[sshmgr] Duo prompt detected — selecting option 1 (Duo Push)")
				answers[i] = "1"
				continue
			}

			if !echos[i] {
				fmt.Fprint(os.Stderr, q)
				bytePw, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return nil, err
				}
				answers[i] = string(bytePw)
				continue
			}

			fmt.Fprint(os.Stderr, q)
			answer, _ := reader.ReadString('\n')
			answers[i] = strings.TrimSpace(answer)
		}
		return answers, nil
	}
}

func looksLikeDuoPrompt(prompt string) bool {
	return strings.Contains(prompt, "passcode or option") ||
		strings.Contains(prompt, "enter a passcode") ||
		strings.Contains(prompt, "duo push") ||
		strings.Contains(prompt, "sms passcodes") ||
		strings.Contains(prompt, "option (1-2)")
}

// hostKeyCallback returns a callback that:
//   - rejects keys that differ from a stored entry (MITM-style mismatch)
//   - on first contact, prints the fingerprint and asks the user to confirm,
//     then appends the key to ~/.ssh/known_hosts.
func hostKeyCallback(autoAccept bool) (ssh.HostKeyCallback, error) {
	khPath, err := knownHostsPath()
	if err != nil {
		return nil, err
	}
	if err := ensureFile(khPath); err != nil {
		return nil, err
	}

	hk, err := knownhosts.New(khPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load known_hosts (%s): %w", khPath, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if debugEnabled() {
			fmt.Fprintf(os.Stderr, "[hostkey] callback hostname=%q remote=%v keytype=%s\n", hostname, remote, key.Type())
		}
		err := hk(hostname, remote, key)
		if debugEnabled() {
			fmt.Fprintf(os.Stderr, "[hostkey] known_hosts lookup err=%v\n", err)
		}
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) > 0 {
				bareHost := hostname
				port := ""
				if h, p, splitErr := net.SplitHostPort(hostname); splitErr == nil {
					bareHost = h
					port = p
				}
				return fmt.Errorf("host key mismatch for %s\n  fingerprint: %s\n  This could be a man-in-the-middle attack — verify out-of-band.\n  If you trust the new key, drop the stale entry — easiest way:\n      sshmgr trust <alias>\n  Or manually (note the bracketed form for non-standard ports):\n      ssh-keygen -R %s\n      ssh-keygen -R '[%s]:%s'\n  (entries are also in %s)",
					hostname, ssh.FingerprintSHA256(key), bareHost, bareHost, port, khPath)
			}
			// Unknown host — TOFU.
			if autoAccept {
				statusf("[sshmgr] auto-accepting host key for %q (auto_accept_host_key)\n  fingerprint: %s\n",
					hostname, ssh.FingerprintSHA256(key))
				appendErr := appendKnownHost(khPath, hostname, remote, key)
				if debugEnabled() {
					fmt.Fprintf(os.Stderr, "[hostkey] appendKnownHost err=%v\n", appendErr)
				}
				return appendErr
			}
			fmt.Fprintf(os.Stderr, "[sshmgr] The authenticity of host %q can't be established.\n", hostname)
			fmt.Fprintf(os.Stderr, "  key type:    %s\n", key.Type())
			fmt.Fprintf(os.Stderr, "  fingerprint: %s\n", ssh.FingerprintSHA256(key))
			fmt.Fprint(os.Stderr, "Add to known_hosts? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.ToLower(strings.TrimSpace(answer))
			if answer != "y" && answer != "yes" {
				return errors.New("host key not accepted by user")
			}
			return appendKnownHost(khPath, hostname, remote, key)
		}
		return err
	}, nil
}

func knownHostsPath() (string, error) {
	if path := os.Getenv("SSHMGR_KNOWN_HOSTS"); path != "" {
		return config.ExpandPath(path), nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".ssh", "known_hosts"), nil
}

func ensureFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Deduplicate hostname and remote.String() — for non-standard ports they
	// normalise to the same `[host]:port` form and we'd otherwise write twice.
	names := uniqueNorm(hostname, remote.String())
	line := knownhosts.Line(names, key)
	if _, err := fmt.Fprintln(f, line); err != nil {
		return err
	}
	return nil
}

func uniqueNorm(in ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		n := knownhosts.Normalize(s)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// RunCommands executes h.Commands (optionally wrapped via become) on the client.
func RunCommands(client *ssh.Client, h config.HostConfig) error {
	commands := h.Commands
	if len(commands) == 0 {
		commands = []string{"whoami"}
	}

	for _, cmd := range commands {
		finalCmd := cmd
		if h.Become.User != "" {
			switch h.Become.Method {
			case "", "sudo":
				finalCmd = fmt.Sprintf("sudo -iu %s -- sh -lc %s",
					shellQuote(h.Become.User), shellQuote(cmd))
			case "su":
				finalCmd = fmt.Sprintf("su - %s -c %s",
					shellQuote(h.Become.User), shellQuote(cmd))
			default:
				return fmt.Errorf("unsupported become method: %s", h.Become.Method)
			}
		}

		fmt.Fprintf(os.Stderr, "\n$ %s\n", finalCmd)

		session, err := client.NewSession()
		if err != nil {
			return err
		}
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin
		err = session.Run(finalCmd)
		session.Close()
		if err != nil {
			return fmt.Errorf("command failed: %s: %w", finalCmd, err)
		}
	}
	return nil
}

// RunOneShot executes a single command on the remote and returns its exit
// code, streaming stdout/stderr to the local terminal. If forceTTY is true,
// allocates a PTY (needed for commands that detect a TTY, e.g. `sudo`).
func RunOneShot(client *ssh.Client, command string, forceTTY bool) (int, error) {
	session, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if forceTTY {
		fd := int(os.Stdin.Fd())
		if term.IsTerminal(fd) {
			old, err := term.MakeRaw(fd)
			if err == nil {
				defer term.Restore(fd, old)
			}
			width, height := 120, 40
			if w, h, err := term.GetSize(fd); err == nil {
				width, height = w, h
			}
			modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
			termType := os.Getenv("TERM")
			if termType == "" {
				termType = "xterm-256color"
			}
			_ = session.RequestPty(termType, height, width, modes)
			session.Stdin = os.Stdin
		}
	} else {
		session.Stdin = os.Stdin
	}

	err = session.Run(command)
	if err == nil {
		return 0, nil
	}
	if ee, ok := err.(*ssh.ExitError); ok {
		return ee.ExitStatus(), nil
	}
	return 1, err
}

// InteractiveShell opens a PTY-backed login shell with the local terminal in raw
// mode and forwards SIGWINCH so curses apps (vim/htop) resize correctly.
// If steps is non-empty, runs the expect/response chain after the shell starts
// before handing control to the user. If x11 is true, requests X11 forwarding
// so remote GUI apps render on the local X server. If forwardAgent is true,
// makes the local ssh-agent visible inside the session. If sessionLogPath is
// non-empty everything written to the user's terminal is also tee'd to that
// file (audit trail). If persistent is "tmux"/"screen"/truthy the shell is
// wrapped in a multiplexer named `sshmgr-<sessionTag>` so the remote stays
// alive across disconnects and reattaches on the next connect.
func InteractiveShell(client *ssh.Client, h config.HostConfig, steps []config.LoginStep, x11, forwardAgent bool, sessionLogPath, persistent, sessionTag string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return err
	}
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return err
	}

	// Optional session log: tee whatever lands on the user's terminal into a
	// file. Best-effort — if we can't create the file we warn and continue
	// without logging rather than refuse the shell.
	var logFile *os.File
	if sessionLogPath != "" {
		if err := os.MkdirAll(filepath.Dir(sessionLogPath), 0o700); err == nil {
			logFile, err = os.OpenFile(sessionLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintf(logFile, "\n--- sshmgr session %s ---\n", time.Now().Format(time.RFC3339))
				defer logFile.Close()
			} else {
				fmt.Fprintf(os.Stderr, "[sshmgr] session log disabled: %v\n", err)
			}
		}
	}

	fd := int(os.Stdin.Fd())

	width, height := 120, 40
	if term.IsTerminal(fd) {
		if w, h, err := term.GetSize(fd); err == nil {
			width, height = w, h
		}
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	if err := session.RequestPty(termType, height, width, modes); err != nil {
		return err
	}

	if x11 {
		if err := fwd.SetupX11(client, session); err != nil {
			fmt.Fprintf(os.Stderr, "[sshmgr] X11 forwarding disabled: %v\n", err)
		} else {
			statusf("[sshmgr] X11 forwarding enabled (DISPLAY=%s)\n", os.Getenv("DISPLAY"))
		}
	}

	if forwardAgent {
		if err := setupAgentForward(client, session); err != nil {
			fmt.Fprintf(os.Stderr, "[sshmgr] agent forwarding disabled: %v\n", err)
		} else {
			statusf("[sshmgr] ssh-agent forwarding enabled\n")
		}
	}

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			if !term.IsTerminal(fd) {
				continue
			}
			w, h, err := term.GetSize(fd)
			if err != nil {
				continue
			}
			_ = session.WindowChange(h, w)
		}
	}()

	if cmd := persistentShellCmd(persistent, sessionTag); cmd != "" {
		statusf("[sshmgr] persistent session via %s (attach: %s)\n", persistent, cmd)
		if err := session.Start(cmd); err != nil {
			return err
		}
	} else {
		if err := session.Shell(); err != nil {
			return err
		}
	}

	// Start exactly one stdout reader for the lifetime of the shell. Both the
	// optional automatic chain and later in-session escalation observe prompts
	// through this inspector; no abandoned goroutine can steal shell output.
	var termOut io.Writer = os.Stdout
	var errOut io.Writer = os.Stderr
	if logFile != nil {
		logW := &lockedWriter{w: logFile}
		termOut = io.MultiWriter(os.Stdout, logW)
		errOut = io.MultiWriter(os.Stderr, logW)
	}
	insp := newExpectInspector(termOut)
	go io.Copy(insp, stdoutPipe)
	go io.Copy(errOut, stderrPipe)

	// Run login chain BEFORE switching to raw mode — output still gets mirrored
	// to the user's terminal so they see what's happening. Skipped when
	// login_steps_auto is false: the chain is then available only via the
	// in-session `~r` escalation hotkey, which avoids racing MFA prompts at
	// connect.
	autoRun := h.LoginStepsAuto == nil || *h.LoginStepsAuto
	if len(steps) > 0 && autoRun {
		statusf("[sshmgr] running %d login step(s)...\n", len(steps))
		if err := runLoginChain(steps, h, stdinPipe, insp); err != nil {
			return fmt.Errorf("login chain: %w", err)
		}
		statusf("[sshmgr] login chain complete, dropping to shell.\n")
	}

	// Switch to raw mode for interactive shell.
	var oldState *term.State
	if term.IsTerminal(fd) {
		oldState, err = term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("cannot set raw mode: %w", err)
		}
		defer term.Restore(fd, oldState)
	}

	// Pump local stdin → remote through the escape scanner, which intercepts the
	// `~r` escalation hotkey (recognised at line start) and runs the host's
	// login_steps chain on demand against the live session. Blocks forever on
	// terminal read after Wait returns, but main() exits and the OS reaps it.
	escalateKey := byte('~')
	if h.EscalateKey != "" {
		escalateKey = h.EscalateKey[0]
	}
	escStatus := func(s string) { fmt.Fprintf(os.Stderr, "\r\n[sshmgr] %s\r\n", s) }
	go escalateStdinPump(stdinPipe, os.Stdin, escalateKey, steps, h, insp, escStatus)

	err = session.Wait()
	_ = stdinPipe.Close()
	var em *ssh.ExitMissingError
	if errors.As(err, &em) {
		return nil
	}
	// Persistent-mode failure: tmux/screen missing on the remote is the
	// most common reason for an immediate exit-127, surface a hint.
	if persistent != "" {
		var ee *ssh.ExitError
		if errors.As(err, &ee) && ee.ExitStatus() == 127 {
			return fmt.Errorf("persistent session via %s exited 127 — is %s installed on the remote? (or set 'persistent:' to empty to use a plain shell)", persistent, strings.ToLower(persistent))
		}
	}
	return err
}

// runLoginChain uses the shell's single output inspector. idle=0 disables the
// manual mode's passwordless-sudo heuristic: automatic mode requires the
// configured prompt or a hard timeout and never advances on mere silence.
func runLoginChain(steps []config.LoginStep, h config.HostConfig, stdin io.Writer, insp *expectInspector) error {
	return runEscalation(steps, h, stdin, insp, 0, nil)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ConnectAliasWithKey opens a fresh connection to alias through its normal
// proxy chain, but authenticates the final hop with ONLY keyPath. Jump hosts
// keep their normal credentials. Rotation uses this both for verification and
// for the destructive old-key removal step, so it never falls back to the key
// it is about to remove.
func ConnectAliasWithKey(cfg *config.Config, alias, keyPath string) (*ssh.Client, error) {
	// Shallow-clone the config and swap the target host's auth to key-only.
	// Proxy/jump hosts keep their normal credentials so the tunnel still works.
	clone := *cfg
	clone.Hosts = make(map[string]config.HostConfig, len(cfg.Hosts))
	for k, v := range cfg.Hosts {
		clone.Hosts[k] = v
	}
	h := clone.Hosts[alias]
	h.Key = keyPath
	h.KeyOnly = true
	h.Password, h.PasswordEnv, h.PasswordKeyring, h.PasswordCmd = "", "", "", ""
	h.PasswordPrompt = false
	h.AutoDuoPush = false
	clone.Hosts[alias] = h
	return ConnectAlias(&clone, alias)
}

// VerifyKey opens a fresh key-only connection and runs `true`. This is the
// safety gate for key rotation: never remove an old key unless this succeeds.
func VerifyKey(cfg *config.Config, alias, keyPath string) error {
	client, err := ConnectAliasWithKey(cfg, alias, keyPath)
	if err != nil {
		return err
	}
	defer CloseChain(client)
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Run("true")
}

// persistentShellCmd returns the remote command to start (or reattach to)
// a persistent session, or "" if persistence is disabled.
//
// Supported values:
//   - "tmux" / "true" / "yes" / "1"  -> tmux
//   - "screen"                       -> GNU screen
//   - anything else                  -> disabled
//
// Session name: "sshmgr-<tag>". The tag is usually the alias so each host
// gets its own slot (tmux is per-host on the remote anyway).
func persistentShellCmd(mode, tag string) string {
	if tag == "" {
		tag = "default"
	}
	name := "sshmgr-" + tag
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "tmux", "true", "yes", "1":
		// `new-session -A -s NAME` attaches if NAME exists, else creates.
		// Quote the full name (including the "sshmgr-" prefix) so an alias
		// containing a quote or whitespace doesn't fracture into multiple
		// shell tokens before tmux sees it.
		return "tmux new-session -A -s " + shellQuote(name)
	case "screen":
		// -DR detaches anyone else attached and creates if missing.
		return "screen -DR " + shellQuote(name)
	default:
		return ""
	}
}

// lockedWriter serialises writes so stdout and stderr goroutines tee'd to
// the same audit log don't tear at page boundaries.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// setupAgentForward dials $SSH_AUTH_SOCK and exposes the agent to session so
// commands like `git clone git@github.com:...` work remotely without copying
// keys. Mirrors `ssh -A`.
func setupAgentForward(client *ssh.Client, session *ssh.Session) error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return errors.New("SSH_AUTH_SOCK is empty — start ssh-agent first")
	}
	// ForwardToRemote opens a fresh local socket for each remote agent
	// channel. Keeping one agent.Client around for the whole SSH session would
	// leak its Unix connection after the session closes.
	if err := agent.ForwardToRemote(client, sock); err != nil {
		return err
	}
	if err := agent.RequestAgentForwarding(session); err != nil {
		return err
	}
	return nil
}

// buildProxyCommand runs the proxy_command through `sh -c` so the user can
// write shell-quoted commands ("ssh jump -W %h:%p", with pipes, env, etc.).
// %h and %p are substituted with target host and port, like OpenSSH.
func buildProxyCommand(template, host string, port int) (*exec.Cmd, error) {
	if template == "" {
		return nil, errors.New("empty proxy_command")
	}
	expanded := strings.ReplaceAll(template, "%h", host)
	expanded = strings.ReplaceAll(expanded, "%p", fmt.Sprintf("%d", port))
	return exec.Command("sh", "-c", expanded), nil
}

// cmdConn is a net.Conn backed by a subprocess's stdin/stdout. Used for
// proxy_command: the SSH library reads/writes through the spawned process.
type cmdConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	done   chan error
	debug  bool
	remote string // host:port of the SSH target we're tunneling to
}

func newCmdConn(cmd *exec.Cmd, remoteAddr string) (*cmdConn, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("start proxy_command: %w", err)
	}
	c := &cmdConn{cmd: cmd, stdin: stdin, stdout: stdout, done: make(chan error, 1), debug: debugEnabled(), remote: remoteAddr}
	if c.debug {
		fmt.Fprintf(os.Stderr, "[cmdconn] subprocess started (pid=%d)\n", cmd.Process.Pid)
	}
	go func() {
		err := cmd.Wait()
		c.done <- err
		if c.debug {
			fmt.Fprintf(os.Stderr, "[cmdconn] subprocess exited: %v\n", err)
		}
	}()
	return c, nil
}

func (c *cmdConn) Read(b []byte) (int, error) {
	if c.debug {
		fmt.Fprintf(os.Stderr, "[cmdconn] read(%d) waiting...\n", len(b))
	}
	n, err := c.stdout.Read(b)
	if c.debug {
		m := n
		if m > 80 {
			m = 80
		}
		fmt.Fprintf(os.Stderr, "[cmdconn] read -> %d bytes err=%v data=%q\n", n, err, b[:m])
	}
	return n, err
}
func (c *cmdConn) Write(b []byte) (int, error) {
	if c.debug {
		m := len(b)
		if m > 80 {
			m = 80
		}
		fmt.Fprintf(os.Stderr, "[cmdconn] write(%d) data=%q\n", len(b), b[:m])
	}
	return c.stdin.Write(b)
}
func (c *cmdConn) Close() error {
	c.stdin.Close()
	c.stdout.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	// Wait for the Wait() goroutine to return, but don't block forever — a
	// stuck PID (zombie, weird namespace, etc.) shouldn't hang sshmgr.
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
	}
	return nil
}

func (c *cmdConn) LocalAddr() net.Addr                { return cmdAddr{addr: "127.0.0.1:0"} }
func (c *cmdConn) RemoteAddr() net.Addr               { return cmdAddr{addr: c.remote} }
func (c *cmdConn) SetDeadline(t time.Time) error      { return nil }
func (c *cmdConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *cmdConn) SetWriteDeadline(t time.Time) error { return nil }

// cmdAddr satisfies net.Addr with a valid host:port string so libraries that
// parse the address via net.SplitHostPort (e.g. x/crypto/ssh/knownhosts) work.
type cmdAddr struct{ addr string }

func (a cmdAddr) Network() string { return "tcp" }
func (a cmdAddr) String() string  { return a.addr }
