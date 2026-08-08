package tui

import (
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/theme"
)

// animLevel is how much of the UI is allowed to move.
type animLevel int

const (
	// animOff repaints only in response to input.
	animOff animLevel = iota
	// animInformative runs motion only while work is happening: a probe
	// round, a transfer, a fleet exec. In steady state nothing repaints.
	animInformative
	// animFull adds the decorative layer, which needs a ticker running
	// continuously.
	animFull
)

func (l animLevel) String() string {
	switch l {
	case animOff:
		return "off"
	case animFull:
		return "full"
	default:
		return "informative"
	}
}

// next cycles the level, for the m hotkey.
func (l animLevel) next() animLevel {
	switch l {
	case animOff:
		return animInformative
	case animInformative:
		return animFull
	default:
		return animOff
	}
}

func parseAnimLevel(s string) (animLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none":
		return animOff, true
	case "informative", "on":
		return animInformative, true
	case "full", "all":
		return animFull, true
	default:
		return animInformative, false
	}
}

// resolveAnimLevel picks the level with the same precedence as the theme:
// environment, then config, then the default.
//
// sshSession demotes an implicitly-chosen full to informative. The decorative
// layer repaints the whole screen continuously, which is roughly 280 KB/s of
// escape sequences -- unnoticeable locally, painful down a tunnel. A full set
// explicitly in the config is honoured anyway: that is someone who has decided.
func resolveAnimLevel(cfg *config.Config, sshSession bool) animLevel {
	if v := os.Getenv("SSHMGR_ANIM"); v != "" {
		l, _ := parseAnimLevel(v)
		if l == animFull && sshSession {
			return animInformative
		}
		return l
	}
	if cfg != nil && cfg.Animations != "" {
		l, ok := parseAnimLevel(cfg.Animations)
		if !ok {
			return animInformative
		}
		return l
	}
	return animInformative
}

// inSSHSession reports whether this process is running inside an SSH session.
func inSSHSession() bool {
	return os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""
}

// startTicker runs tick on an interval until the returned stop is called,
// queueing each tick onto the draw loop. It follows the same shape as
// startPinger: a stop channel closed exactly once, so nothing outlives the
// application.
//
// Returns a no-op stop when animation is off, so callers need no special case.
func (s *uiState) startTicker(interval time.Duration, tick func()) func() {
	if s.animLevel == animOff {
		return func() {}
	}
	stopCh := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				s.app.QueueUpdateDraw(tick)
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stopCh) }) }
}

// mixColor interpolates between two colours. A truecolor terminal renders the
// intermediate steps exactly; a 256-colour one approximates them, which is
// why the decorative layer is opt-in rather than default.
func mixColor(a, b tcell.Color, t float64) tcell.Color {
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	ar, ag, ab := a.RGB()
	br, bg, bb := b.RGB()
	return tcell.NewRGBColor(
		ar+int32(float64(br-ar)*t),
		ag+int32(float64(bg-ag)*t),
		ab+int32(float64(bb-ab)*t),
	)
}

// breatheBorder returns the border colour for the given frame, and false when
// the decorative layer is no longer active. A tick queued through
// QueueUpdateDraw can be delivered after the level changed, so the callback
// re-checks at execution time rather than trusting the level it was queued
// under -- otherwise a stale tick repaints over the reset and leaves the
// border frozen mid-breath.
func (s *uiState) breatheBorder(frame int) (tcell.Color, bool) {
	if s.animLevel != animFull {
		return tcell.ColorDefault, false
	}
	phase := (math.Sin(float64(frame)/12) + 1) / 2
	return mixColor(theme.Current.UnfocusBdr, theme.Current.FocusBdr, phase), true
}

// startDecorativeTicker breathes the focused pane's border. Returns a no-op
// stop unless the level is full, so the caller needs no special case.
func (s *uiState) startDecorativeTicker() func() {
	if s.animLevel != animFull {
		return func() {}
	}
	frame := 0
	return s.startTicker(120*time.Millisecond, func() {
		frame++
		c, ok := s.breatheBorder(frame)
		if !ok {
			return
		}
		s.table.SetBorderColor(c)
		s.tree.SetBorderColor(c)
	})
}

// advanceSpinner steps the spinner frame if a probe round is in flight, and
// reports whether anything changed. Returns false in steady state, which is
// what keeps an idle sshmgr from repainting at all -- the central promise of
// the informative animation level. Do not remove the early return.
func (s *uiState) advanceSpinner() bool {
	if _, total := s.pings.Progress(); total == 0 {
		return false
	}
	s.animFrame++
	return true
}

// spinner is the braille cycle used for in-progress work. One cell wide.
var spinner = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

func spinnerFrame(i int) string {
	if len(spinner) == 0 {
		return ""
	}
	return string(spinner[i%len(spinner)])
}
