package tui

import (
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/systeampl/sshmgr/internal/config"
)

func TestResolveAnimLevelPrecedence(t *testing.T) {
	cases := []struct {
		name string
		env  string
		cfg  string
		ssh  bool
		want animLevel
	}{
		{"default is informative", "", "", false, animInformative},
		{"config wins over default", "", "off", false, animOff},
		{"env wins over config", "off", "full", false, animOff},
		{"unknown value falls back", "", "sparkly", false, animInformative},
		{"full honoured locally", "", "full", false, animFull},
		{"env full honoured locally", "full", "", false, animFull},
		// Over SSH the decorative layer is a sustained ~280 KB/s of repaint,
		// so an implicit full demotes; an explicit config full does not.
		{"ssh demotes env full", "full", "", true, animInformative},
		{"ssh keeps explicit config full", "", "full", true, animFull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SSHMGR_ANIM", tc.env)
			cfg := &config.Config{Animations: tc.cfg}
			if got := resolveAnimLevel(cfg, tc.ssh); got != tc.want {
				t.Errorf("resolveAnimLevel(cfg=%q, env=%q, ssh=%v) = %v, want %v",
					tc.cfg, tc.env, tc.ssh, got, tc.want)
			}
		})
	}
}

func TestResolveAnimLevelHandlesNilConfig(t *testing.T) {
	t.Setenv("SSHMGR_ANIM", "")
	if got := resolveAnimLevel(nil, false); got != animInformative {
		t.Errorf("nil config = %v, want informative", got)
	}
}

func TestAnimLevelString(t *testing.T) {
	for _, tc := range []struct {
		l    animLevel
		want string
	}{
		{animOff, "off"}, {animInformative, "informative"}, {animFull, "full"},
	} {
		if got := tc.l.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.l, got, tc.want)
		}
	}
}

func TestAnimLevelCycle(t *testing.T) {
	// m cycles off -> informative -> full -> off
	l := animOff
	for _, want := range []animLevel{animInformative, animFull, animOff} {
		l = l.next()
		if l != want {
			t.Errorf("next() = %v, want %v", l, want)
		}
	}
}

// TestAdvanceSpinnerSteadyState pins advanceSpinner's own half of the
// steady-state guard: with no probe round running, it must report "nothing
// changed" and must not touch animFrame, every time it is called. This is
// belt-and-braces, not where the "no repaint at all" guarantee lives -- that
// guarantee is spinnerWanted gating startTicker's goroutine before
// QueueUpdateDraw is ever called (see startTicker's doc comment and
// TestStartTickerSkipsQueueWhenNotWanted). Even if this guard were removed,
// spinnerWanted would still stop the draw from happening; this test exists
// because advanceSpinner is also unit-testable on its own and a regression
// here would still be a bug worth catching.
func TestAdvanceSpinnerSteadyState(t *testing.T) {
	s := &uiState{pings: newPingMap()}
	for i := 0; i < 3; i++ {
		if s.advanceSpinner() {
			t.Fatalf("call %d: advanceSpinner() = true with no round running", i)
		}
	}
	if s.animFrame != 0 {
		t.Errorf("animFrame = %d, want 0 (unchanged in steady state)", s.animFrame)
	}
}

// TestAdvanceSpinnerDuringRound is the other half: once a round is in
// flight, advanceSpinner must report "changed" and advance the frame.
func TestAdvanceSpinnerDuringRound(t *testing.T) {
	s := &uiState{pings: newPingMap()}
	s.pings.setProgress(3, 10)
	if !s.advanceSpinner() {
		t.Fatalf("advanceSpinner() = false with a round in progress")
	}
	if s.animFrame != 1 {
		t.Errorf("animFrame = %d, want 1", s.animFrame)
	}
}

// TestMixColorBoundaries pins the interpolation endpoints: t=0 must return
// exactly the first colour and t=1 exactly the second, with no off-by-one
// drift. That drift would be invisible by eye but wrong.
func TestMixColorBoundaries(t *testing.T) {
	a := tcell.NewRGBColor(10, 20, 30)
	b := tcell.NewRGBColor(200, 150, 100)

	if got := mixColor(a, b, 0); got != a {
		ar, ag, ab := a.RGB()
		gr, gg, gb := got.RGB()
		t.Errorf("mixColor(a, b, 0) = rgb(%d,%d,%d), want rgb(%d,%d,%d)", gr, gg, gb, ar, ag, ab)
	}
	if got := mixColor(a, b, 1); got != b {
		br, bg, bb := b.RGB()
		gr, gg, gb := got.RGB()
		t.Errorf("mixColor(a, b, 1) = rgb(%d,%d,%d), want rgb(%d,%d,%d)", gr, gg, gb, br, bg, bb)
	}
	// Out-of-range t clamps rather than extrapolates.
	if got := mixColor(a, b, -1); got != a {
		t.Errorf("mixColor(a, b, -1) = %v, want clamped to a", got)
	}
	if got := mixColor(a, b, 2); got != b {
		t.Errorf("mixColor(a, b, 2) = %v, want clamped to b", got)
	}
}

// TestBreatheBorderChecksLevelAtExecutionTime pins the fix for a queued-tick
// race: QueueUpdateDraw can deliver a decorative tick after the level has
// already changed away from full (e.g. the m handler reset the border to
// Primary, and a tick queued just before stopDecor closed the channel lands
// afterwards). breatheBorder must re-check the level itself and refuse to
// hand back a colour when it is stale, rather than trusting the level it was
// queued under.
func TestBreatheBorderChecksLevelAtExecutionTime(t *testing.T) {
	s := &uiState{animLevel: animInformative}
	if _, ok := s.breatheBorder(5); ok {
		t.Errorf("breatheBorder() ok = true with animLevel = informative, want false")
	}

	s.animLevel = animFull
	c, ok := s.breatheBorder(5)
	if !ok {
		t.Fatalf("breatheBorder() ok = false with animLevel = full, want true")
	}
	if c == tcell.ColorDefault {
		t.Errorf("breatheBorder() colour = ColorDefault, want an interpolated colour")
	}
}

// TestStartDecorativeTickerNotFullSpawnsNoGoroutine confirms that with the
// level anywhere below full, cycling never creates the decorative goroutine.
func TestStartDecorativeTickerNotFullSpawnsNoGoroutine(t *testing.T) {
	for _, lvl := range []animLevel{animOff, animInformative} {
		s := &uiState{animLevel: lvl}
		before := runtime.NumGoroutine()
		stop := s.startDecorativeTicker()
		defer stop()
		time.Sleep(10 * time.Millisecond)
		if after := runtime.NumGoroutine(); after > before {
			t.Errorf("startDecorativeTicker(%v) spawned a goroutine: before=%d after=%d", lvl, before, after)
		}
	}
}

// TestStartTickerOffSpawnsNoGoroutine confirms animOff returns its no-op
// stop before launching anything -- an idle sshmgr with animations disabled
// costs nothing beyond what it costs today.
func TestStartTickerOffSpawnsNoGoroutine(t *testing.T) {
	s := &uiState{animLevel: animOff}
	before := runtime.NumGoroutine()
	stop := s.startTicker(90*time.Millisecond, nil, func() {})
	defer stop()
	// Give any errant goroutine a moment to start before comparing.
	time.Sleep(10 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("startTicker(animOff) spawned a goroutine: before=%d after=%d", before, after)
	}
}

// TestStartTickerSkipsQueueWhenNotWanted is the real test of the finding-1
// fix: wanted is consulted in the ticker goroutine, and when it returns
// false the tick is never handed to QueueUpdateDraw at all -- not "queued
// but a no-op", not called at all. s.app is left nil deliberately: tview's
// QueueUpdateDraw dereferences the Application's internal state, so if the
// gate were ever bypassed this test would crash with a nil-pointer panic
// instead of quietly passing.
//
// What this does NOT verify (out of reach without a running Application):
// that tview's real draw loop (screen.Clear + root.Draw + screen.Show) is
// actually skipped end-to-end when nothing is queued. That is tview's own
// documented behaviour (QueueUpdateDraw always draws after the callback),
// not sshmgr's to test -- the fix here is entirely about not calling it.
func TestStartTickerSkipsQueueWhenNotWanted(t *testing.T) {
	s := &uiState{animLevel: animInformative} // s.app stays nil on purpose
	var wantedCalls int32
	stop := s.startTicker(5*time.Millisecond, func() bool {
		atomic.AddInt32(&wantedCalls, 1)
		return false
	}, func() {
		t.Fatal("tick was queued despite wanted() returning false every time")
	})
	defer stop()

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&wantedCalls) == 0 {
		t.Fatal("wanted() was never consulted -- the ticker goroutine isn't gating at all")
	}
}

// TestSpinnerWantedReflectsProgress pins the predicate passed to startTicker
// for the spinner: wanted only while a round is actually in flight.
func TestSpinnerWantedReflectsProgress(t *testing.T) {
	s := &uiState{pings: newPingMap()}
	if s.spinnerWanted() {
		t.Error("spinnerWanted() = true with no round running")
	}
	s.pings.setProgress(1, 5)
	if !s.spinnerWanted() {
		t.Error("spinnerWanted() = false with a round in progress")
	}
}

// TestDecorWantedReflectsLevel pins the predicate passed to startTicker for
// the decorative ticker: wanted only at animFull.
func TestDecorWantedReflectsLevel(t *testing.T) {
	s := &uiState{animLevel: animInformative}
	if s.decorWanted() {
		t.Error("decorWanted() = true at informative")
	}
	s.animLevel = animFull
	if !s.decorWanted() {
		t.Error("decorWanted() = false at full")
	}
}

// TestPersistAnimLevelSkipsFullOverSSH pins finding 4: a config `full` must
// never be written from inside an SSH session, because resolveAnimLevel
// treats a config full as an explicit decision and skips the SSH demotion --
// one stray m press down a tunnel would otherwise disable that protection
// permanently, on every future session, on every host.
func TestPersistAnimLevelSkipsFullOverSSH(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22")
	t.Setenv("SSH_TTY", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	s := &uiState{
		cfg:        &config.Config{Hosts: map[string]config.HostConfig{}},
		configPath: path,
		animLevel:  animFull,
		pages:      tview.NewPages(),
	}

	s.persistAnimLevel()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("persistAnimLevel wrote %s for animFull inside an SSH session, want no write (err=%v)", path, err)
	}
	if s.cfg.Animations != "" {
		t.Errorf("cfg.Animations = %q, want unchanged (unsaved)", s.cfg.Animations)
	}
}

// TestPersistAnimLevelSavesFullLocally is the control: outside an SSH
// session, full still persists exactly as before.
func TestPersistAnimLevelSavesFullLocally(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	s := &uiState{
		cfg:        &config.Config{Hosts: map[string]config.HostConfig{}},
		configPath: path,
		animLevel:  animFull,
		pages:      tview.NewPages(),
	}

	s.persistAnimLevel()

	if s.cfg.Animations != "full" {
		t.Errorf("cfg.Animations = %q, want %q", s.cfg.Animations, "full")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("persistAnimLevel did not write %s: %v", path, err)
	}
}

// TestPersistAnimLevelSavesInformativeOverSSH confirms the SSH guard is
// scoped to full specifically -- off and informative still persist from
// inside an SSH session same as always.
func TestPersistAnimLevelSavesInformativeOverSSH(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22")
	t.Setenv("SSH_TTY", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	s := &uiState{
		cfg:        &config.Config{Hosts: map[string]config.HostConfig{}},
		configPath: path,
		animLevel:  animInformative,
		pages:      tview.NewPages(),
	}

	s.persistAnimLevel()

	if s.cfg.Animations != "informative" {
		t.Errorf("cfg.Animations = %q, want %q", s.cfg.Animations, "informative")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("persistAnimLevel did not write %s: %v", path, err)
	}
}
