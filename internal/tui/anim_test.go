package tui

import (
	"testing"

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
