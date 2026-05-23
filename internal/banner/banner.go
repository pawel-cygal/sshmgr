// Package banner holds the sshmgr ASCII banner shown at the top of the TUI
// and in CLI help output.
package banner

import "sshmgr/internal/theme"

// ASCII is the multi-line banner. Width is ~78 columns including the wolf
// head on the right. Designed to fit a standard 80-column terminal.
const ASCII = `███████╗███████╗██╗  ██╗███╗   ███╗ ██████╗ ██████╗      /\___/\
██╔════╝██╔════╝██║  ██║████╗ ████║██╔════╝ ██╔══██╗    ( o . o )
███████╗███████╗███████║██╔████╔██║██║  ███╗██████╔╝     \  v  /
╚════██║╚════██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗      \___/
███████║███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝     modern SSH mgr`

// ColoredTview returns ASCII wrapped with the active theme's primary color
// tag so the banner repaints when the theme changes.
func ColoredTview() string {
	return theme.Current.PrimaryTag() + ASCII + "[-]"
}

// Height returns the number of rows the banner occupies (constant).
func Height() int { return 6 }
