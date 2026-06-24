package sshc

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/secret"
)

// escalate.go implements the in-session, on-demand privilege-escalation hotkey.
// The user presses an ssh-style escape (`~` at line start) followed by `r` to run
// the host's login_steps chain against the live shell — landing as root in the same
// session — instead of auto-firing it at connect (which races with MFA prompts).

// escapeScanner recognises an OpenSSH-style escape sequence in the raw stdin byte
// stream: the escape byte is only special as the first byte of a line, `<esc>r`
// triggers escalation, `<esc><esc>` emits a single literal escape byte, and any
// other `<esc>X` passes both bytes through. It is a pure state machine so the
// trigger logic can be unit-tested without a terminal.
type escapeScanner struct {
	escape      byte
	atLineStart bool
	pending     bool // saw the escape byte at line start, awaiting the action byte
}

func newEscapeScanner(escape byte) *escapeScanner {
	return &escapeScanner{escape: escape, atLineStart: true}
}

// feed processes one input byte and returns the bytes to forward to the remote
// plus whether the escalation action (`<escape>r`) was triggered. Forwarded bytes
// are empty when a byte is held (pending escape) or suppressed (the `<esc>r` pair).
func (s *escapeScanner) feed(b byte) (forward []byte, escalate bool) {
	if s.pending {
		s.pending = false
		switch b {
		case 'r':
			// Consumed `<esc>r`; after escalation the remote prints a fresh prompt.
			s.atLineStart = true
			return nil, true
		case s.escape:
			s.atLineStart = false
			return []byte{s.escape}, false
		default:
			s.atLineStart = isLineEnd(b)
			return []byte{s.escape, b}, false
		}
	}
	if s.atLineStart && b == s.escape {
		s.pending = true
		return nil, false
	}
	s.atLineStart = isLineEnd(b)
	return []byte{b}, false
}

func isLineEnd(b byte) bool { return b == '\n' || b == '\r' }

// expectInspector wraps the session's stdout pump: it always forwards bytes to
// the user's terminal (and log), and — while armed — scans the forwarded stream
// for an expected substring so the escalation runner can wait for a prompt
// without taking the stream away from the live session.
type expectInspector struct {
	out io.Writer

	mu           sync.Mutex
	armed        bool
	pattern      []byte
	acc          []byte
	found        chan struct{}
	sawOutput    bool
	lastActivity time.Time
}

func newExpectInspector(out io.Writer) *expectInspector {
	return &expectInspector{out: out}
}

func (e *expectInspector) Write(p []byte) (int, error) {
	n, err := e.out.Write(p)
	e.mu.Lock()
	if e.armed && n > 0 {
		e.sawOutput = true
		e.lastActivity = time.Now()
		e.acc = append(e.acc, p[:n]...)
		if bytes.Contains(e.acc, e.pattern) {
			e.armed = false
			close(e.found)
		}
	}
	e.mu.Unlock()
	return n, err
}

// arm starts watching the forwarded byte stream for pattern. Call it before
// writing the command so a prompt that arrives immediately is not missed.
func (e *expectInspector) arm(pattern string) {
	e.mu.Lock()
	e.armed = true
	e.pattern = []byte(pattern)
	e.acc = e.acc[:0]
	e.found = make(chan struct{})
	e.sawOutput = false
	e.lastActivity = time.Now()
	e.mu.Unlock()
}

func (e *expectInspector) disarm() {
	e.mu.Lock()
	e.armed = false
	e.mu.Unlock()
}

// wait blocks until the armed pattern appears (returns true), the output goes
// idle after the command produced some text without the pattern (returns false —
// the command finished without prompting, e.g. cached sudo or passwordless), or
// the hard timeout elapses with no output at all (returns an error). The idle
// path is what stops a re-escalation from hanging when `sudo` has cached creds
// and never reprints its password prompt.
func (e *expectInspector) wait(timeout, idle time.Duration) (bool, error) {
	e.mu.Lock()
	ch := e.found
	pat := string(e.pattern)
	e.mu.Unlock()

	hard := time.NewTimer(timeout)
	defer hard.Stop()
	tick := time.NewTicker(idle / 2)
	defer tick.Stop()

	for {
		select {
		case <-ch:
			return true, nil
		case <-hard.C:
			e.disarm()
			return false, fmt.Errorf("timeout waiting for %q after %s", pat, timeout)
		case <-tick.C:
			e.mu.Lock()
			stillArmed := e.armed
			idleNow := e.sawOutput && time.Since(e.lastActivity) >= idle
			e.mu.Unlock()
			if stillArmed && idleNow {
				e.disarm()
				return false, nil
			}
		}
	}
}

// escalationIdle is how long the runner waits for a step's password prompt to
// stop producing output before concluding the command finished without asking
// for a password (e.g. sudo with cached credentials). Generous enough that a
// real, fast su/sudo prompt always wins the race first.
const escalationIdle = 2 * time.Second

// escalateStdinPump copies src (the local terminal) to dst (the remote stdin),
// intercepting the `<escape>r` hotkey at line start. On trigger it runs the
// host's login_steps against the live session via insp, synchronously — which
// holds local keystrokes until the chain finishes or aborts — then resumes
// passthrough. A trigger with no chain configured is a no-op with a status note.
func escalateStdinPump(dst io.Writer, src io.Reader, escape byte, steps []config.LoginStep, h config.HostConfig, insp *expectInspector, status func(string)) {
	sc := newEscapeScanner(escape)
	buf := make([]byte, 4096)
	for {
		n, rerr := src.Read(buf)
		for i := 0; i < n; i++ {
			fwd, esc := sc.feed(buf[i])
			if len(fwd) > 0 {
				if _, werr := dst.Write(fwd); werr != nil {
					return
				}
			}
			if !esc {
				continue
			}
			if len(steps) == 0 {
				if status != nil {
					status("no escalation chain configured for this host")
				}
				continue
			}
			if err := runEscalation(steps, h, dst, insp, escalationIdle, status); err != nil && status != nil {
				status("escalation aborted: " + err.Error())
			}
		}
		if rerr != nil {
			return
		}
	}
}

// runEscalation drives steps against an already-open, already-pumping session:
// for each step it arms the inspector, writes the command, then waits for the
// expect substring. If the prompt appears it sends the resolved password; if the
// command instead finishes without prompting (output goes idle for `idle` — e.g.
// `sudo` with cached credentials on a re-escalation), it skips the password and
// moves on. On a hard timeout (no output at all) or a resolution error it returns
// WITHOUT sending that step's password, leaving the user at the live shell.
// status, if non-nil, receives human-readable progress lines.
func runEscalation(steps []config.LoginStep, h config.HostConfig, w io.Writer, insp *expectInspector, idle time.Duration, status func(string)) error {
	for i, step := range steps {
		if step.Command == "" {
			return fmt.Errorf("step %d: empty command", i+1)
		}
		if status != nil {
			status("escalating: " + step.Command)
		}
		if step.Expect != "" {
			insp.arm(step.Expect)
		}
		if _, err := fmt.Fprintf(w, "%s\n", step.Command); err != nil {
			return fmt.Errorf("step %d (%q): write command: %w", i+1, step.Command, err)
		}
		if step.Expect == "" {
			continue
		}
		timeout := 30 * time.Second
		if step.TimeoutMS > 0 {
			timeout = time.Duration(step.TimeoutMS) * time.Millisecond
		}
		matched, err := insp.wait(timeout, idle)
		if err != nil {
			return fmt.Errorf("step %d (%q): %w", i+1, step.Command, err)
		}
		if !matched {
			// No password prompt appeared (cached sudo / passwordless): the
			// command already succeeded, so skip the password and continue.
			if status != nil {
				status("no password prompt for " + step.Command + " — continuing")
			}
			continue
		}
		pw, err := secret.Resolve(step, h)
		if err != nil {
			return fmt.Errorf("step %d (%q): %w", i+1, step.Command, err)
		}
		if _, err := fmt.Fprintf(w, "%s\n", pw); err != nil {
			return fmt.Errorf("step %d (%q): write password: %w", i+1, step.Command, err)
		}
	}
	return nil
}
