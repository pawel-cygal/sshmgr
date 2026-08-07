package tui

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
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

// spinner is the braille cycle used for in-progress work. One cell wide.
var spinner = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

func spinnerFrame(i int) string {
	if len(spinner) == 0 {
		return ""
	}
	return string(spinner[i%len(spinner)])
}
