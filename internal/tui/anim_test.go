package tui

import (
	"runtime"
	"testing"
	"time"

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

// TestAdvanceSpinnerSteadyState pins the central promise of the informative
// level: with no probe round running, advanceSpinner must report "nothing
// changed" and must not touch animFrame, every time it is called. This is
// the decision that keeps an idle sshmgr from repainting at all -- the
// ticker in Run only calls updateStatus when advanceSpinner returns true.
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

// TestStartTickerOffSpawnsNoGoroutine confirms animOff returns its no-op
// stop before launching anything -- an idle sshmgr with animations disabled
// costs nothing beyond what it costs today.
func TestStartTickerOffSpawnsNoGoroutine(t *testing.T) {
	s := &uiState{animLevel: animOff}
	before := runtime.NumGoroutine()
	stop := s.startTicker(90*time.Millisecond, func() {})
	defer stop()
	// Give any errant goroutine a moment to start before comparing.
	time.Sleep(10 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("startTicker(animOff) spawned a goroutine: before=%d after=%d", before, after)
	}
}
