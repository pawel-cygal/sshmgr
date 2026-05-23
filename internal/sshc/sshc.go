package sshc

import (
	"bufio"
	"bytes"
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

	"sshmgr/internal/config"
	"sshmgr/internal/fwd"
	"sshmgr/internal/secret"

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
	sshConfig, err := clientConfigFor(h)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Host, fmt.Sprintf("%d", h.Port))
	return ssh.Dial("tcp", addr, sshConfig)
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
	sshConfig, err := clientConfigFor(h)
	if err != nil {
		conn.Close()
		return nil, err
	}
	statusf("[sshmgr] SSH handshake on tunnel -> %s (user=%s)\n", addr, h.User)
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
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
	conn, err := jump.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial via jump: %w", err)
	}
	sshConfig, err := clientConfigFor(h)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake via jump: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func clientConfigFor(h config.HostConfig) (*ssh.ClientConfig, error) {
	auths, err := authMethods(h)
	if err != nil {
		return nil, err
	}
	hk, err := hostKeyCallback(h.AutoAcceptHostKey)
	if err != nil {
		return nil, err
	}
	timeout := 30 * time.Second
	if h.ConnectTimeout > 0 {
		timeout = time.Duration(h.ConnectTimeout) * time.Second
	}
	return &ssh.ClientConfig{
		User:            h.User,
		Auth:            auths,
		HostKeyCallback: hk,
		Timeout:         timeout,
	}, nil
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

func authMethods(h config.HostConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	// KeyOnly: exactly the configured key, no fallback. Used by key-rotation
	// verification — the new key must succeed entirely on its own.
	if h.KeyOnly {
		if h.Key == "" {
			return nil, errors.New("key_only verification requires a key")
		}
		keyPath := config.ExpandPath(h.Key)
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read SSH key %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse SSH key %s: %w", keyPath, err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}

	if h.Key != "" {
		keyPath := config.ExpandPath(h.Key)
		keyBytes, err := os.ReadFile(keyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("cannot parse SSH key %s: %w", keyPath, err)
			}
			methods = append(methods, ssh.PublicKeys(signer))
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot read SSH key %s: %w", keyPath, err)
		}
	}

	hasPassword := h.Password != "" || h.PasswordEnv != "" ||
		h.PasswordKeyring != "" || h.PasswordCmd != "" || h.PasswordPrompt

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
	return methods, nil
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
// - rejects keys that differ from a stored entry (MITM-style mismatch)
// - on first contact, prints the fingerprint and asks the user to confirm,
//   then appends the key to ~/.ssh/known_hosts.
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

	// Run login chain BEFORE switching to raw mode — output still gets mirrored
	// to the user's terminal so they see what's happening.
	if len(steps) > 0 {
		statusf("[sshmgr] running %d login step(s)...\n", len(steps))
		if err := runLoginChain(steps, h, stdoutPipe, stdinPipe); err != nil {
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

	// Pump server output to our terminal (and the log file if requested).
	// stdout and stderr arrive on separate goroutines; without a lock,
	// their writes to logFile can tear at the page boundary. Wrap once in
	// a mutex-guarded writer so audit logs are clean.
	if logFile != nil {
		logW := &lockedWriter{w: logFile}
		go io.Copy(io.MultiWriter(os.Stdout, logW), stdoutPipe)
		go io.Copy(io.MultiWriter(os.Stderr, logW), stderrPipe)
	} else {
		go io.Copy(os.Stdout, stdoutPipe)
		go io.Copy(os.Stderr, stderrPipe)
	}
	// Pump local stdin → remote. Blocks forever on terminal read after Wait
	// returns, but main() exits and the OS reaps it.
	go func() { _, _ = io.Copy(stdinPipe, os.Stdin) }()

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

// runLoginChain executes step.Command + waits for step.Expect + sends response
// for each step in order. Output is mirrored to os.Stdout so the user can see
// each prompt and answer. Passwords are resolved from $PasswordEnv or literal
// Response.
func runLoginChain(steps []config.LoginStep, h config.HostConfig, stdout io.Reader, stdin io.Writer) error {
	type readResult struct {
		buf []byte
		err error
	}
	// Reads run in a goroutine so the per-step deadline can actually fire —
	// otherwise a naked stdout.Read() blocks forever if the server stops
	// sending bytes, hanging the whole interactive shell.
	reads := make(chan readResult, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case reads <- readResult{chunk, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	acc := make([]byte, 0, 4096)
	for i, step := range steps {
		if step.Command == "" {
			return fmt.Errorf("step %d: empty command", i+1)
		}
		if _, err := fmt.Fprintf(stdin, "%s\n", step.Command); err != nil {
			return fmt.Errorf("step %d (%q): write command: %w", i+1, step.Command, err)
		}
		statusf("[sshmgr] step %d: %s\n", i+1, step.Command)
		acc = acc[:0]

		if step.Expect == "" {
			continue
		}

		timeoutMS := step.TimeoutMS
		if timeoutMS <= 0 {
			timeoutMS = 30000
		}
		timer := time.NewTimer(time.Duration(timeoutMS) * time.Millisecond)
		matched := false
	WaitLoop:
		for !matched {
			select {
			case r := <-reads:
				if len(r.buf) > 0 {
					_, _ = os.Stdout.Write(r.buf)
					acc = append(acc, r.buf...)
					if bytes.Contains(acc, []byte(step.Expect)) {
						matched = true
						break WaitLoop
					}
				}
				if r.err != nil {
					timer.Stop()
					return fmt.Errorf("step %d (%q): read: %w", i+1, step.Command, r.err)
				}
			case <-timer.C:
				return fmt.Errorf("step %d (%q): timeout waiting for %q after %dms", i+1, step.Command, step.Expect, timeoutMS)
			}
		}
		timer.Stop()

		response, err := secret.Resolve(step, h)
		if err != nil {
			return fmt.Errorf("step %d (%q): %w", i+1, step.Command, err)
		}
		if _, err := fmt.Fprintf(stdin, "%s\n", response); err != nil {
			return fmt.Errorf("step %d (%q): write response: %w", i+1, step.Command, err)
		}
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// VerifyKey opens a fresh connection to alias — through its normal proxy
// chain — authenticating the final hop with ONLY keyPath (no password, no
// keyboard-interactive, no fallback to the old key). It runs `true` and
// returns nil only if that succeeds. This is the safety gate for key
// rotation: never remove an old key unless VerifyKey confirms the new one.
func VerifyKey(cfg *config.Config, alias, keyPath string) error {
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

	client, err := ConnectAlias(&clone, alias)
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
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("dial ssh-agent: %w", err)
	}
	if err := agent.ForwardToAgent(client, agent.NewClient(conn)); err != nil {
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
