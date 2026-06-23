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

	mu      sync.Mutex
	armed   bool
	pattern []byte
	acc     []byte
	found   chan struct{}
}

func newExpectInspector(out io.Writer) *expectInspector {
	return &expectInspector{out: out}
}

func (e *expectInspector) Write(p []byte) (int, error) {
	n, err := e.out.Write(p)
	e.mu.Lock()
	if e.armed && n > 0 {
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
	e.mu.Unlock()
}

// wait blocks until the armed pattern appears or timeout elapses.
func (e *expectInspector) wait(timeout time.Duration) error {
	e.mu.Lock()
	ch := e.found
	pat := string(e.pattern)
	e.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		e.mu.Lock()
		e.armed = false
		e.mu.Unlock()
		return fmt.Errorf("timeout waiting for %q after %s", pat, timeout)
	}
}

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
			if err := runEscalation(steps, h, dst, insp, status); err != nil && status != nil {
				status("escalation aborted: " + err.Error())
			}
		}
		if rerr != nil {
			return
		}
	}
}

// runEscalation drives steps against an already-open, already-pumping session:
// for each step it arms the inspector, writes the command, waits for the expect
// substring, then writes the resolved password. On any timeout or resolution
// error it returns WITHOUT sending that step's password, leaving the user at the
// live shell. status, if non-nil, receives human-readable progress lines.
func runEscalation(steps []config.LoginStep, h config.HostConfig, w io.Writer, insp *expectInspector, status func(string)) error {
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
		if err := insp.wait(timeout); err != nil {
			return fmt.Errorf("step %d (%q): %w", i+1, step.Command, err)
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
