// Package external runs sshmgr operations through the system OpenSSH tools
// (ssh / scp / sftp) for hosts marked `external: true`. Such hosts need
// OpenSSH-only behaviour the native Go SSH client can't reproduce —
// knock-proxy ProxyCommand, ControlMaster, Match blocks, and so on.
//
// The *Argv builders are pure functions, unit-tested directly. Run and
// RunCaptured spawn the actual processes.
package external

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
)

// Target is the `user@host` (or bare `host`) destination argument.
func Target(h config.HostConfig) string {
	if h.User != "" {
		return h.User + "@" + h.Host
	}
	return h.Host
}

// connArgs returns the connection options shared by ssh, scp and sftp: -i
// (key), the port, proxy options and pass-through ssh_options. portFlag
// differs between the clients — "-p" for ssh, "-P" for scp/sftp.
// proxy_command takes precedence over proxy_jump, matching the native path.
func connArgs(h config.HostConfig, portFlag string) []string {
	var argv []string
	if h.Key != "" {
		argv = append(argv, "-i", config.ExpandPath(h.Key))
	}
	if h.Port != 0 && h.Port != 22 {
		argv = append(argv, portFlag, strconv.Itoa(h.Port))
	}
	// -J and ProxyCommand are mutually exclusive in OpenSSH; ProxyCommand
	// wins when both are configured.
	if h.ProxyCommand != "" {
		argv = append(argv, "-o", "ProxyCommand="+h.ProxyCommand)
	} else if h.ProxyJump != "" {
		argv = append(argv, "-J", h.ProxyJump)
	}
	for _, opt := range h.SSHOptions {
		// Accept "KEY=VAL" or "-o KEY=VAL"; always emit "-o KEY=VAL".
		opt = strings.TrimSpace(opt)
		opt = strings.TrimPrefix(opt, "-o ")
		opt = strings.TrimPrefix(opt, "-o")
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		argv = append(argv, "-o", opt)
	}
	return argv
}

// SSHArgv builds the argv (after the ssh binary) for an interactive shell.
func SSHArgv(h config.HostConfig) []string {
	return append(connArgs(h, "-p"), Target(h))
}

// SSHCommandArgv builds the ssh argv for a one-shot remote command. An empty
// command yields an interactive shell (matching SSHArgv); forceTTY adds -t to
// request a PTY.
func SSHCommandArgv(h config.HostConfig, command string, forceTTY bool) []string {
	var argv []string
	if forceTTY {
		argv = append(argv, "-t")
	}
	argv = append(argv, connArgs(h, "-p")...)
	argv = append(argv, Target(h))
	if command != "" {
		argv = append(argv, command)
	}
	return argv
}

// SFTPArgv builds the argv (after the sftp binary) for an interactive SFTP
// session.
func SFTPArgv(h config.HostConfig) []string {
	return append(connArgs(h, "-P"), Target(h))
}

// FwdArgv builds the ssh argv for port forwarding. flag is "-L", "-R" or
// "-D"; -N keeps the connection open without a remote shell.
func FwdArgv(h config.HostConfig, flag, spec string) []string {
	// Pin ExitOnForwardFailure before user options. OpenSSH uses the first
	// value it obtains, so a detached parent cannot report success while a
	// requested local/remote listener was rejected.
	argv := []string{"-N", "-o", "ExitOnForwardFailure=yes", flag, spec}
	argv = append(argv, connArgs(h, "-p")...)
	return append(argv, Target(h))
}

// SCPArgv builds the argv (after the scp binary) for a file copy. src and dst
// keep sshmgr's `alias:/path` UX; the side referencing alias is rewritten to
// `user@host:/path` for scp.
func SCPArgv(h config.HostConfig, alias, src, dst string, recursive bool) []string {
	var argv []string
	if recursive {
		argv = append(argv, "-r")
	}
	argv = append(argv, connArgs(h, "-P")...)
	target := Target(h)
	argv = append(argv, RewriteRemoteSpec(src, alias, target))
	argv = append(argv, RewriteRemoteSpec(dst, alias, target))
	return argv
}

// RewriteRemoteSpec rewrites an `alias:/path` argument to `user@host:/path`
// so the system scp client resolves the right destination. Specs that don't
// reference alias (local paths, other hosts) pass through unchanged.
func RewriteRemoteSpec(spec, alias, target string) string {
	if strings.HasPrefix(spec, alias+":") {
		return target + spec[len(alias):]
	}
	return spec
}

// Run execs a system OpenSSH-family binary (ssh / scp / sftp) found in PATH,
// wiring stdio to the current process. Returns the child's exit code (0 on
// clean exit); a non-nil error means the binary could not be started.
func Run(bin string, argv []string) (int, error) {
	return RunWithReady(bin, argv, 0, nil)
}

// RunWithReady starts an external command and invokes ready only after it has
// remained alive for readyDelay. For OpenSSH forwards, pair this with
// ExitOnForwardFailure=yes: bind/request failures exit before the callback,
// while an established -N session remains alive. Native forwards have an
// exact listener callback; this delay is the best portable signal exposed by
// the OpenSSH CLI without forcing it to fork away from sshmgr's PID registry.
func RunWithReady(bin string, argv []string, readyDelay time.Duration, ready func()) (int, error) {
	binPath, err := exec.LookPath(bin)
	if err != nil {
		return 0, fmt.Errorf("cannot find %s in PATH: %w", bin, err)
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] external host — running: %s %s\n", bin, strings.Join(argv, " "))
	cmd := exec.Command(binPath, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if ready != nil {
		timer := time.NewTimer(readyDelay)
		select {
		case err = <-done:
			timer.Stop()
			return externalExit(err)
		case <-timer.C:
			ready()
		}
		err = <-done
	} else {
		err = <-done
	}
	return externalExit(err)
}

func externalExit(err error) (int, error) {
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

// withoutOption returns a copy of h with any ssh_option named optKey removed.
// Keys are matched case-insensitively and the "-o " prefix is tolerated. The
// caller's slice is never mutated.
func withoutOption(h config.HostConfig, optKey string) config.HostConfig {
	var kept []string
	for _, opt := range h.SSHOptions {
		o := strings.TrimSpace(opt)
		o = strings.TrimPrefix(o, "-o ")
		o = strings.TrimPrefix(o, "-o")
		o = strings.TrimSpace(o)
		key := o
		if i := strings.IndexByte(o, '='); i >= 0 {
			key = o[:i]
		}
		if strings.EqualFold(strings.TrimSpace(key), optKey) {
			continue
		}
		kept = append(kept, opt)
	}
	h.SSHOptions = kept
	return h
}

// capturedArgv builds the ssh argv for a non-interactive captured run
// (exec / watch). BatchMode=yes is pinned: any user-set BatchMode in
// ssh_options is dropped first, so the fleet path can't be made to hang on a
// password prompt regardless of how ssh resolves duplicate -o options.
func capturedArgv(h config.HostConfig, command string) []string {
	safe := withoutOption(h, "BatchMode")
	return append([]string{"-o", "BatchMode=yes"}, SSHCommandArgv(safe, command, false)...)
}

// capturedInputArgv builds the stricter OpenSSH invocation used by read-only
// fleet collectors which stream a fixed protocol over stdin. The leading
// options cannot be weakened through host ssh_options: OpenSSH uses the first
// value obtained for these settings, and matching user-provided values are
// removed as defence in depth.
func capturedInputArgv(h config.HostConfig, command string) []string {
	protected := []string{
		"BatchMode",
		"RequestTTY",
		"StdinNull",
		"ClearAllForwardings",
		"PermitLocalCommand",
		"StrictHostKeyChecking",
		"UpdateHostKeys",
		"RemoteCommand",
	}
	safe := h
	for _, option := range protected {
		safe = withoutOption(safe, option)
	}
	argv := []string{
		"-o", "BatchMode=yes",
		"-o", "RequestTTY=no",
		"-o", "StdinNull=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "RemoteCommand=none",
	}
	return append(argv, SSHCommandArgv(safe, command, false)...)
}

// RunCapturedInputContext executes a non-interactive OpenSSH command while
// supplying protocol data on stdin and keeping stdout separate from stderr.
// Both streams are consumed through bounded buffers so a broken or hostile
// endpoint cannot make the scanner retain unbounded output. It never logs the
// remote command, which may contain the fixed collector implementation.
func RunCapturedInputContext(ctx context.Context, h config.HostConfig, command, input string, stdoutLimit int64) ([]byte, string, int, error) {
	if stdoutLimit < 1 || stdoutLimit > int64(int(^uint(0)>>1)) {
		return nil, "", 0, fmt.Errorf("invalid external ssh stdout limit %d", stdoutLimit)
	}
	binPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil, "", 0, fmt.Errorf("cannot find ssh in PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, binPath, capturedInputArgv(h, command)...)
	cmd.Stdin = strings.NewReader(input)
	stdout := newCappedBuffer(int(stdoutLimit))
	stderr := newCappedBuffer(8192)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, stderr.String(), 0, ctxErr
	}
	if stdout.truncated {
		return nil, stderr.String(), 0, fmt.Errorf("external ssh stdout exceeds %d bytes", stdoutLimit)
	}
	data := append([]byte(nil), stdout.buf.Bytes()...)
	if runErr == nil {
		return data, stderr.String(), 0, nil
	}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		return data, stderr.String(), exitErr.ExitCode(), nil
	}
	return data, stderr.String(), 0, runErr
}

// RunCapturedContext runs a one-shot remote command via the system ssh
// client and returns its combined stdout+stderr. Cancelling ctx kills the
// ssh process — used by the fleet exec path to enforce a per-host timeout.
// BatchMode is forced so a host needing a password fails fast instead of
// hanging a parallel run on a prompt. A non-nil error means ssh could not be
// started; a connection failure surfaces as a non-zero code instead.
func RunCapturedContext(ctx context.Context, h config.HostConfig, command string) (string, int, error) {
	binPath, err := exec.LookPath("ssh")
	if err != nil {
		return "", 0, err
	}
	cmd := exec.CommandContext(ctx, binPath, capturedArgv(h, command)...)
	buf := newCappedBuffer(32 << 20)
	cmd.Stdout, cmd.Stderr = &buf, &buf
	runErr := cmd.Run()
	if runErr == nil {
		return buf.String(), 0, nil
	}
	if ee, ok := runErr.(*exec.ExitError); ok {
		return buf.String(), ee.ExitCode(), nil
	}
	return buf.String(), 0, runErr
}

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) cappedBuffer { return cappedBuffer{limit: limit} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return n, nil
}

func (b *cappedBuffer) String() string {
	out := b.buf.String()
	if b.truncated {
		out += fmt.Sprintf("\n[sshmgr: output truncated after %d bytes]\n", b.limit)
	}
	return out
}

// RunCaptured is RunCapturedContext with no timeout. Used by `watch`.
func RunCaptured(h config.HostConfig, command string) (string, int, error) {
	return RunCapturedContext(context.Background(), h, command)
}

// Aliases returns the subset of aliases that resolve to external hosts —
// used to reject external hosts from native-only subcommands.
func Aliases(cfg *config.Config, aliases []string) []string {
	var ext []string
	for _, a := range aliases {
		if h, ok := cfg.ResolveHost(a); ok && h.External {
			ext = append(ext, a)
		}
	}
	return ext
}
