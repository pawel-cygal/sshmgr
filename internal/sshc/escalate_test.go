package sshc

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"sshmgr/internal/config"
)

// syncBuffer is a goroutine-safe bytes.Buffer for asserting on what the runner
// wrote while another goroutine feeds the inspector.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitUntil polls cond up to d, failing the test if it never becomes true.
func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// feedString runs every byte of s through the scanner and returns the
// concatenated forwarded bytes plus the number of escalation triggers.
func feedString(sc *escapeScanner, s string) (forwarded []byte, triggers int) {
	for i := 0; i < len(s); i++ {
		fwd, esc := sc.feed(s[i])
		forwarded = append(forwarded, fwd...)
		if esc {
			triggers++
		}
	}
	return forwarded, triggers
}

func TestEscapeScannerTriggersAtLineStart(t *testing.T) {
	sc := newEscapeScanner('~')
	fwd, triggers := feedString(sc, "~r")
	if triggers != 1 {
		t.Fatalf("`~r` at line start should trigger once, got %d", triggers)
	}
	if len(fwd) != 0 {
		t.Fatalf("`~r` bytes must be suppressed, forwarded %q", fwd)
	}
}

func TestEscapeScannerIgnoresTildeMidLine(t *testing.T) {
	sc := newEscapeScanner('~')
	// `cd ~/x` — the tilde is not at line start, must pass through untouched.
	fwd, triggers := feedString(sc, "cd ~/x")
	if triggers != 0 {
		t.Fatalf("mid-line `~` must not trigger, got %d", triggers)
	}
	if string(fwd) != "cd ~/x" {
		t.Fatalf("mid-line bytes must pass through verbatim, got %q", fwd)
	}
}

func TestEscapeScannerDoubleTildeIsLiteral(t *testing.T) {
	sc := newEscapeScanner('~')
	fwd, triggers := feedString(sc, "~~")
	if triggers != 0 {
		t.Fatalf("`~~` must not trigger, got %d", triggers)
	}
	if string(fwd) != "~" {
		t.Fatalf("`~~` should forward a single literal `~`, got %q", fwd)
	}
}

func TestEscapeScannerUnknownActionPassesThrough(t *testing.T) {
	sc := newEscapeScanner('~')
	fwd, triggers := feedString(sc, "~x")
	if triggers != 0 {
		t.Fatalf("`~x` must not trigger, got %d", triggers)
	}
	if string(fwd) != "~x" {
		t.Fatalf("`~x` should forward `~x` verbatim, got %q", fwd)
	}
}

func TestEscapeScannerLineStartResetsAfterNewline(t *testing.T) {
	sc := newEscapeScanner('~')
	// First a normal command + newline, THEN `~r` which should now trigger.
	fwd, triggers := feedString(sc, "ls\n~r")
	if triggers != 1 {
		t.Fatalf("`~r` after a newline should trigger, got %d", triggers)
	}
	if string(fwd) != "ls\n" {
		t.Fatalf("only `ls\\n` should be forwarded, got %q", fwd)
	}
}

func TestEscapeScannerTriggerThenTypingResumes(t *testing.T) {
	sc := newEscapeScanner('~')
	// After a trigger the scanner returns to line-start; subsequent typing flows.
	_, triggers := feedString(sc, "~r")
	if triggers != 1 {
		t.Fatalf("expected one trigger, got %d", triggers)
	}
	fwd, more := feedString(sc, "whoami\n")
	if more != 0 {
		t.Fatalf("no further triggers expected, got %d", more)
	}
	if string(fwd) != "whoami\n" {
		t.Fatalf("typing after trigger must flow, got %q", fwd)
	}
}

func TestEscapeScannerCustomKey(t *testing.T) {
	sc := newEscapeScanner('`')
	fwd, triggers := feedString(sc, "`r")
	if triggers != 1 || len(fwd) != 0 {
		t.Fatalf("custom escape `+r should trigger and suppress, got triggers=%d fwd=%q", triggers, fwd)
	}
	// And `~` is now an ordinary character.
	fwd2, t2 := feedString(newEscapeScanner('`'), "~r")
	if t2 != 0 || !bytes.Equal(fwd2, []byte("~r")) {
		t.Fatalf("with custom key, `~r` is literal, got triggers=%d fwd=%q", t2, fwd2)
	}
}

func TestRunEscalationSendsCommandThenPassword(t *testing.T) {
	insp := newExpectInspector(io.Discard)
	var out syncBuffer
	steps := []config.LoginStep{
		{Command: "su - sbsadmin", Expect: "Password:", Response: "s3cret", TimeoutMS: 1000},
	}
	done := make(chan error, 1)
	go func() {
		done <- runEscalation(steps, config.HostConfig{}, &out, insp, func(string) {})
	}()
	// Runner arms expect then writes the command; once we see it, simulate the
	// remote printing the password prompt.
	waitUntil(t, time.Second, func() bool { return strings.Contains(out.String(), "su - sbsadmin") })
	insp.Write([]byte("Password: "))

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runEscalation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runEscalation did not finish")
	}
	if got := out.String(); got != "su - sbsadmin\ns3cret\n" {
		t.Fatalf("command then password expected, got %q", got)
	}
}

func TestRunEscalationTimeoutDoesNotSendPassword(t *testing.T) {
	insp := newExpectInspector(io.Discard)
	var out syncBuffer
	steps := []config.LoginStep{
		{Command: "su - x", Expect: "Password:", Response: "s3cret", TimeoutMS: 40},
	}
	// Never feed the prompt → the step must time out.
	err := runEscalation(steps, config.HostConfig{}, &out, insp, func(string) {})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	got := out.String()
	if strings.Contains(got, "s3cret") {
		t.Fatalf("password must NOT be sent on timeout, got %q", got)
	}
	if !strings.Contains(got, "su - x") {
		t.Fatalf("command should have been sent before the wait, got %q", got)
	}
}

func TestRunEscalationTwoStepsInOrder(t *testing.T) {
	insp := newExpectInspector(io.Discard)
	var out syncBuffer
	steps := []config.LoginStep{
		{Command: "su - sbsadmin", Expect: "assword", Response: "p1", TimeoutMS: 1000},
		{Command: "sudo su -", Expect: "assword", Response: "p2", TimeoutMS: 1000},
	}
	done := make(chan error, 1)
	go func() {
		done <- runEscalation(steps, config.HostConfig{}, &out, insp, func(string) {})
	}()
	waitUntil(t, time.Second, func() bool { return strings.Contains(out.String(), "su - sbsadmin") })
	insp.Write([]byte("Password: "))
	waitUntil(t, time.Second, func() bool { return strings.Contains(out.String(), "sudo su -") })
	insp.Write([]byte("[sudo] password for sbsadmin: "))

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runEscalation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runEscalation did not finish")
	}
	if got := out.String(); got != "su - sbsadmin\np1\nsudo su -\np2\n" {
		t.Fatalf("two-step order wrong, got %q", got)
	}
}
