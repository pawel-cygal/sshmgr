package main

import (
	"fmt"
	"os"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/logo"

	"github.com/gdamore/tcell/v2"
)

// cmdAbout prints the logo and build information. The logo is emitted as
// half-block cells with truecolor escapes, and is skipped entirely when
// stdout is not a terminal -- piping `sshmgr about` into a file should give
// readable text, not a screenful of escape sequences.
func cmdAbout(args []string) {
	if len(args) != 0 {
		fatal("about takes no arguments")
	}

	if stdoutIsTTY() {
		printLogo(os.Stdout)
	}

	info := currentBuildInfo()
	cfg, path, err := config.Load()
	hosts := 0
	if err == nil {
		hosts = len(cfg.Hosts)
	} else {
		path = "(not loaded: " + err.Error() + ")"
	}

	fmt.Fprintf(os.Stdout, "sshmgr %s by SysTeam · SysTeam.pl\n\n", info.Version)
	fmt.Fprintf(os.Stdout, "  commit   %s\n", info.Commit)
	fmt.Fprintf(os.Stdout, "  built    %s\n", info.BuildDate)
	fmt.Fprintf(os.Stdout, "  go       %s\n", info.GoVersion)
	fmt.Fprintf(os.Stdout, "  platform %s/%s\n", info.OS, info.Arch)
	fmt.Fprintf(os.Stdout, "  config   %s\n", path)
	fmt.Fprintf(os.Stdout, "  hosts    %d\n", hosts)
	fmt.Fprintf(os.Stdout, "  license  MIT\n")
	fmt.Fprintf(os.Stdout, "  source   github.com/systeampl/sshmgr\n")
}

// stdoutIsTTY reports whether stdout is a terminal.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// printLogo writes the logo as half-block rows. Each cell is one '▀' with a
// truecolor foreground (upper pixel) and background (lower pixel).
func printLogo(w *os.File) {
	cells, err := logo.Cells(logo.Width, logo.Height, tcell.NewRGBColor(0, 0, 0))
	if err != nil {
		return
	}
	for row := 0; row < logo.Height; row++ {
		fmt.Fprint(w, "  ")
		for col := 0; col < logo.Width; col++ {
			c := cells[row*logo.Width+col]
			fr, fg, fb := c.Fg.RGB()
			br, bg, bb := c.Bg.RGB()
			fmt.Fprintf(w, "\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm%c",
				fr, fg, fb, br, bg, bb, c.Ch)
		}
		fmt.Fprint(w, "\x1b[0m\n")
	}
	fmt.Fprintln(w)
}
