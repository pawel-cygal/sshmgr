package tui

import (
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"sshmgr/internal/config"
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

type pingMap struct {
	mu sync.RWMutex
	m  map[string]pingStatus
}

func newPingMap() *pingMap { return &pingMap{m: map[string]pingStatus{}} }

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

// startPinger spawns a goroutine that probes every configured alias on a
// 60-second interval (first round immediately). external/proxied hosts are
// probed against their .Host:.Port; hosts with a proxy_command/proxy_jump
// skip probing (we can't reach them from this side cheaply).
//
// onChange is invoked from a tview.Application.QueueUpdateDraw context so
// repaints land cleanly.
func startPinger(cfg *config.Config, pings *pingMap, onChange func()) (stop func()) {
	stopCh := make(chan struct{})

	// Cache ssh-master check results per jump within one round so we don't run
	// `ssh -O check bastion-eu` 364 times for fleet hosts.
	doRound := func() {
		jumpCache := map[string]pingStatus{}
		var jumpMu sync.Mutex
		jumpProbe := func(name string) pingStatus {
			jumpMu.Lock()
			if v, ok := jumpCache[name]; ok {
				jumpMu.Unlock()
				return v
			}
			jumpMu.Unlock()
			s := probeSSHMaster(name)
			jumpMu.Lock()
			jumpCache[name] = s
			jumpMu.Unlock()
			return s
		}

		var wg sync.WaitGroup
		// Flip every alias to "connecting" before probing so the UI shows the
		// round in progress (yellow dot until we learn online/offline).
		for alias := range cfg.Hosts {
			pings.Set(alias, statusConnecting)
		}
		onChange()
		// Give the UI a moment to repaint the yellow flash — without this,
		// fast TCP probes (LAN hosts) settle before tview's next redraw and
		// the user never sees the connecting state.
		time.Sleep(500 * time.Millisecond)
		for alias := range cfg.Hosts {
			alias := alias
			h, _ := cfg.ResolveHost(alias)

			switch {
			case h.External:
				// External hosts: check the ssh ControlMaster status. If the
				// user already has a master alive, mark online; otherwise
				// unknown (we don't want to spawn fresh ssh connections
				// every minute just for status).
				wg.Add(1)
				go func() {
					defer wg.Done()
					pings.Set(alias, jumpProbe(h.Host))
				}()
			case h.ProxyCommand != "":
				// Hosts behind proxy_command share fate with the jump it
				// goes through. Extract `ssh <X> -W` and check master of X.
				jump := extractSSHJump(h.ProxyCommand)
				if jump == "" {
					pings.Set(alias, statusUnknown)
					continue
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					pings.Set(alias, jumpProbe(jump))
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
				jh, _ := cfg.ResolveHost(headAlias)
				port := jh.Port
				if port == 0 {
					port = 22
				}
				addr := net.JoinHostPort(jh.Host, strconv.Itoa(port))
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						pings.Set(alias, statusOffline)
						return
					}
					conn.Close()
					pings.Set(alias, statusOnline)
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
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						pings.Set(alias, statusOffline)
						return
					}
					conn.Close()
					pings.Set(alias, statusOnline)
				}()
			}
		}
		wg.Wait()
		onChange()
	}

	go func() {
		doRound()
		t := time.NewTicker(60 * time.Second)
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
// Duo prompts or run knock-proxy 364 times per minute.
func probeSSHMaster(name string) pingStatus {
	cmd := exec.Command("ssh", "-O", "check", name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		return statusOnline
	}
	return statusUnknown
}

// extractSSHJump parses "ssh <name> -W %h:%p" and returns "<name>", or "" if
// the proxy_command doesn't match that common form.
func extractSSHJump(proxyCmd string) string {
	fields := strings.Fields(proxyCmd)
	if len(fields) < 2 || fields[0] != "ssh" {
		return ""
	}
	for _, f := range fields[1:] {
		if !strings.HasPrefix(f, "-") {
			return f
		}
	}
	return ""
}
