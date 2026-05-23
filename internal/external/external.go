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

	"sshmgr/internal/config"
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
	argv := []string{"-N", flag, spec}
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
	binPath, err := exec.LookPath(bin)
	if err != nil {
		return 0, fmt.Errorf("cannot find %s in PATH: %w", bin, err)
	}
	fmt.Fprintf(os.Stderr, "[sshmgr] external host — running: %s %s\n", bin, strings.Join(argv, " "))
	cmd := exec.Command(binPath, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
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
	var buf bytes.Buffer
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
