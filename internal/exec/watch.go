package exec

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/external"
	"sshmgr/internal/sshc"
	"sshmgr/internal/theme"

	"golang.org/x/crypto/ssh"
)

// Watch re-runs cmd on a single host every interval, clearing the screen and
// re-printing each time. Lines that changed since the previous run are
// highlighted in the theme's accent color. Blocks until SIGINT/SIGTERM.
func Watch(cfg *config.Config, alias, cmd string, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	var prev []string
	tick := time.NewTicker(interval)
	defer tick.Stop()

	render := func() {
		out, ec, err := watchRun(cfg, alias, cmd)
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

		// Clear screen + home cursor.
		fmt.Print("\x1b[2J\x1b[H")
		hdr := fmt.Sprintf("%severy %s · %s · %s%s",
			theme.ANSI(theme.Current.Primary), interval, alias,
			time.Now().Format("15:04:05"), theme.Reset())
		if err != nil {
			hdr += "  " + theme.ANSI(theme.Current.Error) + "(error: " + err.Error() + ")" + theme.Reset()
		} else if ec != 0 {
			hdr += fmt.Sprintf("  %s(exit %d)%s", theme.ANSI(theme.Current.Error), ec, theme.Reset())
		}
		fmt.Println(hdr)
		fmt.Println(strings.Repeat("─", 60))

		prevSet := map[string]bool{}
		for _, l := range prev {
			prevSet[l] = true
		}
		for _, l := range lines {
			if len(prev) > 0 && !prevSet[l] {
				// Changed/new line — highlight.
				fmt.Println(theme.ANSI(theme.Current.AccentB) + l + theme.Reset())
			} else {
				fmt.Println(l)
			}
		}
		fmt.Printf("\n%s[Ctrl-C to stop]%s\n", theme.ANSI(theme.Current.Dim), theme.Reset())
		prev = lines
	}

	render()
	for {
		select {
		case <-stop:
			fmt.Println()
			return nil
		case <-tick.C:
			render()
		}
	}
}

func watchRun(cfg *config.Config, alias, cmd string) (string, int, error) {
	// External hosts re-run the command through the system ssh client.
	if h, ok := cfg.ResolveHost(alias); ok && h.External {
		return external.RunCaptured(h, cmd)
	}
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		return "", 0, err
	}
	defer sshc.CloseChain(client)

	session, err := client.NewSession()
	if err != nil {
		return "", 0, err
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf
	runErr := session.Run(cmd)
	if runErr == nil {
		return buf.String(), 0, nil
	}
	if ee, ok := runErr.(*ssh.ExitError); ok {
		return buf.String(), ee.ExitStatus(), nil
	}
	return buf.String(), 1, runErr
}
