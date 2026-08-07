package tui

import (
	"sync"
	"testing"
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
