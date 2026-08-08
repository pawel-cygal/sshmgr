package tui

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
)

// pingStatus is what's currently known about a host's reachability.
type pingStatus int

const (
	statusUnknown pingStatus = iota
	statusOnline
	statusOffline
	statusConnecting
)

// emoji returns a 2-cell-wide visual status indicator (emoji keeps its own
// color across tview selection styling, unlike a color-tagged Unicode dot).
func (p pingStatus) emoji() string {
	switch p {
	case statusOnline:
		return "🟢 "
	case statusOffline:
		return "🔴 "
	case statusConnecting:
		return "🟡 "
	default:
		return "⚫ "
	}
}

// glyph returns a one-cell status indicator. It replaces the emoji the List
// needed: emoji occupy two columns and their width varies by terminal, while a
// Table cell can carry its own colour, so a plain glyph now works.
func (p pingStatus) glyph() string {
	switch p {
	case statusOnline:
		return "●"
	case statusOffline:
		return "○"
	case statusConnecting:
		return "◐"
	default:
		return "◌"
	}
}

// color returns the palette colour for the status.
func (p pingStatus) color() tcell.Color {
	switch p {
	case statusOnline:
		return theme.Current.Success
	case statusOffline:
		return theme.Current.Error
	case statusConnecting:
		return theme.Current.Warning
	default:
		return theme.Current.Dim
	}
}

// historyLen is how many probe rounds are kept per host: long enough to
// catch a flap, short enough to render in ten cells. The wall-clock span it
// covers depends on the resolved probe interval (see resolveProbeInterval);
// historySpan renders that span next to the round count so "10 rounds"
// means something at a glance.
const historyLen = 10

// defaultProbeInterval is how often a probe round repeats when nothing else
// says otherwise. sshmgr is a convenience readout of host reachability, not
// a monitoring tool -- dialing a 388-host fleet every minute is far more
// often than a convenience needs. Ten minutes across historyLen rounds also
// gives the availability sparkline a useful span (roughly an hour and forty
// minutes) instead of ten minutes.
const defaultProbeInterval = 10 * time.Minute

// minProbeInterval is the floor every resolved interval is clamped to,
// regardless of source. This dials every host in the fleet each round; a
// careless "1s" in the config or $SSHMGR_PROBE_INTERVAL would hammer 388
// hosts continuously, so anything shorter is bumped up rather than honoured.
const minProbeInterval = 30 * time.Second

// parseProbeInterval parses a duration string, reporting ok=false when it
// doesn't parse. On failure it returns defaultProbeInterval, so a caller
// that discards ok (as resolveProbeInterval's env-var branch does, mirroring
// parseAnimLevel's shape in anim.go) still gets a sane value.
func parseProbeInterval(s string) (time.Duration, bool) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return defaultProbeInterval, false
	}
	return d, true
}

// clampProbeInterval enforces minProbeInterval. Clamping is deliberate, not
// defensive noise: see minProbeInterval's doc comment.
func clampProbeInterval(d time.Duration) time.Duration {
	if d < minProbeInterval {
		return minProbeInterval
	}
	return d
}

// resolveProbeInterval picks the probe round interval with the same
// precedence resolveAnimLevel uses for the animation level (itself matching
// the theme): environment, then config, then the default. An unparseable
// value from either source falls back to the default rather than erroring,
// the same way an unknown theme falls back to "default". Every resolved
// value passes through clampProbeInterval before it is returned.
func resolveProbeInterval(cfg *config.Config) time.Duration {
	if v := os.Getenv("SSHMGR_PROBE_INTERVAL"); v != "" {
		d, _ := parseProbeInterval(v)
		return clampProbeInterval(d)
	}
	if cfg != nil && cfg.ProbeInterval != "" {
		d, ok := parseProbeInterval(cfg.ProbeInterval)
		if !ok {
			return defaultProbeInterval
		}
		return clampProbeInterval(d)
	}
	return defaultProbeInterval
}

type pingMap struct {
	mu   sync.RWMutex
	m    map[string]pingStatus
	hist map[string][]pingStatus

	// done/total track a probe round in flight, for the status-bar spinner.
	// Both zero means no round is running.
	done, total int
}

type probeCall struct {
	status pingStatus
	done   chan struct{}
}

func memoProbe(cache map[string]*probeCall, mu *sync.Mutex, key string, probe func() pingStatus) pingStatus {
	mu.Lock()
	if call, ok := cache[key]; ok {
		mu.Unlock()
		<-call.done
		return call.status
	}
	call := &probeCall{done: make(chan struct{})}
	cache[key] = call
	mu.Unlock()
	call.status = probe()
	close(call.done)
	return call.status
}

func newPingMap() *pingMap {
	return &pingMap{
		m:    map[string]pingStatus{},
		hist: map[string][]pingStatus{},
	}
}

func (p *pingMap) Get(alias string) pingStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.m[alias]
}

func (p *pingMap) Set(alias string, s pingStatus) {
	p.mu.Lock()
	p.m[alias] = s
	p.mu.Unlock()
}

// Record appends a resolved status to the host's history, evicting the oldest
// entry past historyLen.
//
// Two statuses are dropped, for different reasons:
//
//   - statusConnecting is the pinger's UI flash, set on every alias at the
//     start of a round before any probe has run. Recording it would make
//     every host look like it flaps every round.
//   - statusUnknown means the host was never actually contacted this round
//     (a proxy_jump/proxy_command host we don't probe directly, or an
//     external host with no live ControlMaster) -- unlike a genuine
//     statusOffline, it is not evidence the host was down. Recording it
//     anyway would render as a red 0% sparkline for hosts we never touched:
//     against the maintainer's real fleet, 369 of 388 hosts (95%) are
//     exactly this shape, which made the availability feature actively
//     misleading rather than merely incomplete. A host we cannot probe now
//     simply accumulates no history, so the AVAILABILITY section correctly
//     does not appear for it instead of asserting downtime it never saw.
//
// A future refinement could give unknown its own glyph and compute uptime
// over known rounds only, rather than omitting the section for that host
// entirely -- not built here.
func (p *pingMap) Record(alias string, s pingStatus) {
	if s == statusConnecting || s == statusUnknown {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := append(p.hist[alias], s)
	if len(h) > historyLen {
		h = h[len(h)-historyLen:]
	}
	p.hist[alias] = h
}

// History returns the recorded rounds, oldest first. The returned slice is a
// copy; callers render from it while the pinger keeps writing.
func (p *pingMap) History(alias string) []pingStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	h := p.hist[alias]
	if len(h) == 0 {
		return nil
	}
	out := make([]pingStatus, len(h))
	copy(out, h)
	return out
}

// Progress reports how far the current round has got. Both zero means no
// round is running.
func (p *pingMap) Progress() (done, total int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.done, p.total
}

func (p *pingMap) setProgress(done, total int) {
	p.mu.Lock()
	p.done, p.total = done, total
	p.mu.Unlock()
}

// addDone increments the round's completed count by one, once a probe has
// resolved (successfully, unknown, or skipped early — anything that means we
// are done considering that alias for this round).
func (p *pingMap) addDone() {
	p.mu.Lock()
	p.done++
	p.mu.Unlock()
}

// sparkCell maps a status to its sparkline glyph. Up is a full block, down a
// low one, so the shape reads at a glance without relying on colour.
func sparkCell(s pingStatus) rune {
	if s == statusOnline {
		return '█'
	}
	return '▁'
}

// availabilityLine renders the history as a sparkline plus an uptime
// percentage. Anything that is not statusOnline counts as down -- an unknown
// result is not evidence the host was up.
func availabilityLine(hist []pingStatus) (string, int) {
	if len(hist) == 0 {
		return "", 0
	}
	var b strings.Builder
	up := 0
	for _, s := range hist {
		b.WriteRune(sparkCell(s))
		if s == statusOnline {
			up++
		}
	}
	return b.String(), up * 100 / len(hist)
}

// historySpan reports the wall-clock span that rounds of history covers at
// interval, formatted compactly (e.g. "1h40m", "5m"). It returns "" when
// there is nothing to span -- no rounds, or no interval -- matching the
// AVAILABILITY section itself, which is omitted entirely until a host has
// history.
func historySpan(rounds int, interval time.Duration) string {
	if rounds <= 0 || interval <= 0 {
		return ""
	}
	return formatCompactDuration(time.Duration(rounds) * interval)
}

// formatCompactDuration renders d as e.g. "1h40m" or "5m": hours and
// minutes, no trailing zero units, and seconds only when the span is under
// a minute. This is not a general-purpose formatter -- it exists for
// historySpan, whose input is always historyLen rounds times a probe
// interval measured in minutes at worst tens of seconds.
func formatCompactDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	sec := d / time.Second

	var b strings.Builder
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if h > 0 || m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if h == 0 && m == 0 {
		fmt.Fprintf(&b, "%ds", sec)
	}
	return b.String()
}

// startPinger spawns a goroutine that probes every configured alias on
// interval (first round immediately). external/proxied hosts are probed
// against their .Host:.Port; hosts with a proxy_command/proxy_jump skip
// probing (we can't reach them from this side cheaply).
//
// onChange is invoked from a tview.Application.QueueUpdateDraw context so
// repaints land cleanly.
func startPinger(pings *pingMap, interval time.Duration, onChange func()) (stop func()) {
	stopCh := make(chan struct{})

	// Cache ssh-master check results per jump within one round so we don't run
	// `ssh -O check bastion-eu` 364 times for fleet hosts.
	doRound := func() {
		cfg, _, err := config.Load()
		if err != nil {
			return
		}
		jumpCache := map[string]*probeCall{}
		tcpCache := map[string]*probeCall{}
		var jumpMu sync.Mutex
		var tcpMu sync.Mutex
		jumpProbe := func(name string) pingStatus {
			return memoProbe(jumpCache, &jumpMu, name, func() pingStatus { return probeSSHMaster(name) })
		}
		tcpProbe := func(addr string) pingStatus {
			return memoProbe(tcpCache, &tcpMu, addr, func() pingStatus {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					return statusOffline
				}
				_ = conn.Close()
				return statusOnline
			})
		}

		var wg sync.WaitGroup
		pings.setProgress(0, len(cfg.Hosts))
		// Flip every alias to "connecting" before probing so the UI shows the
		// round in progress (yellow dot until we learn online/offline).
		for alias := range cfg.Hosts {
			pings.Set(alias, statusConnecting)
		}
		onChange()
		for alias := range cfg.Hosts {
			alias := alias
			h, _ := cfg.ResolveHost(alias)

			switch {
			case h.External:
				// External hosts: check the ssh ControlMaster status. If the
				// user already has a master alive, mark online; otherwise
				// unknown (we don't want to spawn fresh ssh connections
				// every round just for status).
				wg.Add(1)
				go func() {
					defer wg.Done()
					pings.Set(alias, jumpProbe(h.Host))
					pings.addDone()
				}()
			case h.ProxyCommand != "":
				// Hosts behind proxy_command share fate with the jump it
				// goes through. Extract `ssh <X> -W` and check master of X.
				jump := config.ExtractSSHJumpAlias(h.ProxyCommand)
				if jump == "" {
					pings.Set(alias, statusUnknown)
					pings.addDone()
					continue
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					pings.Set(alias, jumpProbe(jump))
					pings.addDone()
				}()
			case h.ProxyJump != "":
				// Recursively follow proxy_jump aliases (in our config) to
				// find the head jump and probe that.
				headAlias := h.ProxyJump
				seen := map[string]bool{}
				for !seen[headAlias] {
					seen[headAlias] = true
					jh, ok := cfg.ResolveHost(headAlias)
					if !ok || jh.ProxyJump == "" {
						break
					}
					headAlias = jh.ProxyJump
				}
				jh, ok := cfg.ResolveHost(headAlias)
				if !ok || (jh.ProxyJump != "" && seen[jh.ProxyJump]) {
					pings.Set(alias, statusUnknown)
					pings.addDone()
					continue
				}
				if jh.ProxyCommand != "" {
					jump := config.ExtractSSHJumpAlias(jh.ProxyCommand)
					if jump == "" {
						pings.Set(alias, statusUnknown)
						pings.addDone()
						continue
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						status := jumpProbe(jump)
						if status == statusOnline {
							status = statusUnknown
						}
						pings.Set(alias, status)
						pings.addDone()
					}()
					continue
				}
				port := jh.Port
				if port == 0 {
					port = 22
				}
				addr := net.JoinHostPort(jh.Host, strconv.Itoa(port))
				wg.Add(1)
				go func() {
					defer wg.Done()
					status := tcpProbe(addr)
					if status == statusOnline {
						// Only the head jump was probed. Do not claim the target
						// itself is online when it was never contacted.
						status = statusUnknown
					}
					pings.Set(alias, status)
					pings.addDone()
				}()
			default:
				port := h.Port
				if port == 0 {
					port = 22
				}
				addr := net.JoinHostPort(h.Host, strconv.Itoa(port))
				wg.Add(1)
				go func() {
					defer wg.Done()
					pings.Set(alias, tcpProbe(addr))
					pings.addDone()
				}()
			}
		}
		wg.Wait()
		// Record the round's resolved status once, after every probe has
		// settled. Recording inside the probes would capture the connecting
		// flash instead.
		for alias := range cfg.Hosts {
			pings.Record(alias, pings.Get(alias))
		}
		pings.setProgress(0, 0)
		onChange()
	}

	go func() {
		doRound()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				doRound()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stopCh) }) }
}

// probeSSHMaster returns Online when `ssh -O check <name>` reports an active
// ControlMaster (i.e. the user already has a live SSH session to that name),
// Unknown otherwise. We don't open fresh SSH connections — that would burn
// Duo prompts or run knock-proxy 364 times per round.
func probeSSHMaster(name string) pingStatus {
	cmd := exec.Command("ssh", "-O", "check", name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		return statusOnline
	}
	return statusUnknown
}
