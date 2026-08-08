package tui

import (
	"sync"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
)

func TestHistoryIsBoundedAndOrdered(t *testing.T) {
	p := newPingMap()
	// Write more than the ring holds; the oldest must fall off.
	for i := 0; i < historyLen+5; i++ {
		if i%2 == 0 {
			p.Record("h", statusOnline)
		} else {
			p.Record("h", statusOffline)
		}
	}
	got := p.History("h")
	if len(got) != historyLen {
		t.Fatalf("history length %d, want %d", len(got), historyLen)
	}
	// The last write was index historyLen+4; parity tells us what it was.
	wantLast := statusOffline
	if (historyLen+4)%2 == 0 {
		wantLast = statusOnline
	}
	if got[len(got)-1] != wantLast {
		t.Errorf("newest entry = %v, want %v", got[len(got)-1], wantLast)
	}
}

// statusConnecting is the transient flash the pinger sets on every alias at
// the start of a round. Recording it would make every host look like it flaps.
func TestConnectingIsNeverRecorded(t *testing.T) {
	p := newPingMap()
	p.Record("h", statusOnline)
	p.Record("h", statusConnecting)
	p.Record("h", statusOnline)
	for i, s := range p.History("h") {
		if s == statusConnecting {
			t.Errorf("history[%d] is statusConnecting, which must never be recorded", i)
		}
	}
	if n := len(p.History("h")); n != 2 {
		t.Errorf("history length %d, want 2 (the connecting write dropped)", n)
	}
}

// statusUnknown means the host was never contacted this round (proxy-only or
// external without a live ControlMaster) -- it is not evidence of downtime,
// so recording it would make an unprobed host look identical to one that was
// actually down every round. On the real fleet this is 95% of hosts.
func TestUnknownIsNeverRecorded(t *testing.T) {
	p := newPingMap()
	p.Record("h", statusOnline)
	p.Record("h", statusUnknown)
	p.Record("h", statusOnline)
	for i, s := range p.History("h") {
		if s == statusUnknown {
			t.Errorf("history[%d] is statusUnknown, which must never be recorded", i)
		}
	}
	if n := len(p.History("h")); n != 2 {
		t.Errorf("history length %d, want 2 (the unknown write dropped)", n)
	}
}

func TestHistoryOfUnknownAliasIsEmpty(t *testing.T) {
	p := newPingMap()
	if got := p.History("nope"); len(got) != 0 {
		t.Errorf("History of an unprobed alias = %v, want empty", got)
	}
}

func TestRecordIsSafeUnderConcurrency(t *testing.T) {
	p := newPingMap()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p.Record("h", statusOnline)
			_ = p.History("h")
		}(i)
	}
	wg.Wait()
	if n := len(p.History("h")); n != historyLen {
		t.Errorf("after 50 concurrent writes history length = %d, want %d", n, historyLen)
	}
}

func TestAvailabilityLine(t *testing.T) {
	cases := []struct {
		name    string
		hist    []pingStatus
		wantPct int
	}{
		{"all up", []pingStatus{statusOnline, statusOnline, statusOnline}, 100},
		{"all down", []pingStatus{statusOffline, statusOffline}, 0},
		{"half", []pingStatus{statusOnline, statusOffline}, 50},
		{"unknown counts as down", []pingStatus{statusOnline, statusUnknown}, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spark, pct := availabilityLine(tc.hist)
			if pct != tc.wantPct {
				t.Errorf("uptime = %d%%, want %d%%", pct, tc.wantPct)
			}
			if len([]rune(spark)) != len(tc.hist) {
				t.Errorf("spark %q has %d cells, want %d", spark, len([]rune(spark)), len(tc.hist))
			}
		})
	}
}

func TestAvailabilityLineOfEmptyHistory(t *testing.T) {
	spark, pct := availabilityLine(nil)
	if spark != "" || pct != 0 {
		t.Errorf("empty history gave (%q, %d), want (\"\", 0)", spark, pct)
	}
}

// TestResolveProbeIntervalPrecedence mirrors TestResolveAnimLevelPrecedence
// in anim_test.go: environment wins over config, config wins over the
// default, an unparseable value falls back to the default (matching how an
// unknown theme falls back to "default"), and the 30-second floor clamps
// anything shorter regardless of which source it came from.
func TestResolveProbeIntervalPrecedence(t *testing.T) {
	cases := []struct {
		name string
		env  string
		cfg  string
		want time.Duration
	}{
		{"default is ten minutes", "", "", 10 * time.Minute},
		{"config wins over default", "", "5m", 5 * time.Minute},
		{"env wins over config", "2m", "5m", 2 * time.Minute},
		{"unparseable config falls back to default", "", "banana", 10 * time.Minute},
		{"unparseable env falls back to default", "banana", "", 10 * time.Minute},
		{"floor clamps 1s", "", "1s", 30 * time.Second},
		{"floor clamps 10ms", "", "10ms", 30 * time.Second},
		{"floor leaves 45s alone", "", "45s", 45 * time.Second},
		{"env floor clamps 1s", "1s", "", 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SSHMGR_PROBE_INTERVAL", tc.env)
			cfg := &config.Config{ProbeInterval: tc.cfg}
			if got := resolveProbeInterval(cfg); got != tc.want {
				t.Errorf("resolveProbeInterval(cfg=%q, env=%q) = %v, want %v",
					tc.cfg, tc.env, got, tc.want)
			}
		})
	}
}

func TestResolveProbeIntervalHandlesNilConfig(t *testing.T) {
	t.Setenv("SSHMGR_PROBE_INTERVAL", "")
	if got := resolveProbeInterval(nil); got != 10*time.Minute {
		t.Errorf("nil config = %v, want 10m", got)
	}
}

// TestHistorySpan pins the compact span formatter behind the AVAILABILITY
// line's round count: ten rounds at the 10-minute default is "1h40m", ten
// rounds at the 30-second floor is "5m", and no history (or no interval)
// renders nothing rather than "0s" or similar noise.
func TestHistorySpan(t *testing.T) {
	cases := []struct {
		name     string
		rounds   int
		interval time.Duration
		want     string
	}{
		{"ten rounds at ten minutes", 10, 10 * time.Minute, "1h40m"},
		{"ten rounds at thirty seconds", 10, 30 * time.Second, "5m"},
		{"zero rounds", 0, 10 * time.Minute, ""},
		{"zero interval", 10, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := historySpan(tc.rounds, tc.interval); got != tc.want {
				t.Errorf("historySpan(%d, %v) = %q, want %q", tc.rounds, tc.interval, got, tc.want)
			}
		})
	}
}
