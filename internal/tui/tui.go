package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/banner"
	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/fwdregistry"
	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Action describes what the user wants to do with the picked alias.
type Action string

const (
	ActionNone    Action = ""        // user quit without picking
	ActionConnect Action = "connect" // open an interactive shell
	ActionSFTP    Action = "sftp"    // open an SFTP REPL
	ActionFiles   Action = "files"   // open the 2-pane file manager
	ActionForward Action = "forward" // run a port forward (extra args carry -L/-R/-D <spec>)
	// ActionExec runs a command across one or more hosts. extraArgs is
	// {"--host", "a,b,c", "<cmd…>"} or {"--group", "g", "<cmd…>"},
	// optionally prefixed with "--diff".
	ActionExec Action = "exec"
	// ActionWatch re-runs a command on one host. extraArgs is {"<cmd…>"};
	// alias carries the host.
	ActionWatch Action = "watch"
	// ActionAudit runs the task-oriented audit workflow with automatic private
	// project state. extraArgs carries the canonical selector or a lookup.
	ActionAudit Action = "audit"
	// ActionAccess runs an access lifecycle or expert command. extraArgs starts
	// with the access subcommand and carries every option selected in the form.
	ActionAccess Action = "access"
	// ActionCloud runs a Cloud artifact/profile command. Offline preparation
	// stays local; login, status, and upload are explicit network operations.
	ActionCloud Action = "cloud"
	// ActionPlaybook runs an Ansible playbook. extraArgs is the playbook
	// name followed by a {--host a,b | --group g} selector and optional
	// {--check, --diff, --extra-vars V} flags.
	ActionPlaybook Action = "playbook"
)

// buildVersion is the version string shown in the compact banner. main sets
// it at startup; it stays empty in tests.
var buildVersion = "dev"

// buildCommit is the commit shown on the about screen. main sets it at
// startup alongside buildVersion.
var buildCommit = "unknown"

// SetBuildInfo lets main hand the linker-injected build details to the TUI.
func SetBuildInfo(version, commit string) {
	buildVersion = version
	buildCommit = commit
}

// Run launches the TUI. Returns (alias, action, extraArgs). If action is
// ActionNone the user quit without picking anything. extraArgs carries extra
// command-line args for actions that need them (e.g. ActionForward returns
// {"-L", "8080:remote:3306"}).
func Run(cfg *config.Config, configPath string) (string, Action, []string, error) {
	applyTheme(cfg)

	app := tview.NewApplication()

	state := &uiState{
		app:           app,
		cfg:           cfg,
		configPath:    configPath,
		mode:          modeTree,
		sort:          sortName,
		pings:         newPingMap(),
		multiSelected: map[string]bool{},
	}
	state.animLevel = resolveAnimLevel(cfg, inSSHSession())
	state.probeInterval = resolveProbeInterval(cfg)

	buildHostWidget(state)

	state.tree = tview.NewTreeView().
		SetGraphics(true).
		SetTopLevel(1) // hide root, show groups as top level
	state.tree.SetBorder(true).
		SetTitle(" hosts (tree) ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

	state.leftPages = tview.NewPages().
		AddPage(modeFlat, state.table, true, false).
		AddPage(modeTree, state.tree, true, true)

	state.details = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	state.details.SetBorder(true).
		SetTitle(" details ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Dim).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

	state.help = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	state.help.SetText(helpText(24))

	state.status = tview.NewTextView().SetDynamicColors(true).SetWrap(false)

	state.filterInput = tview.NewInputField().
		SetLabel("filter: ").
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text)
	state.filterInput.SetChangedFunc(func(text string) {
		state.filter = strings.ToLower(strings.TrimSpace(text))
		state.refresh(state.currentAlias())
	})
	state.filterInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			state.filterInput.SetText("")
			state.filter = ""
			state.refresh(state.currentAlias())
		}
		state.exitFilterMode()
	})

	state.bottom = tview.NewPages().
		AddPage("help", state.help, true, true).
		AddPage("filter", state.filterInput, true, false)

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(state.details, 0, 1, false).
		AddItem(state.status, 1, 0, false).
		AddItem(state.bottom, 2, 0, false)
	state.rightCol = right
	state.footerRows = 2

	body := tview.NewFlex().
		AddItem(state.leftPages, 58, 0, true).
		AddItem(right, 0, 1, false)

	bannerView := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft).
		SetWrap(false)
	state.bannerView = bannerView
	state.bannerVariant = banner.Compact
	state.wantFullBanner = resolveWantFullBanner(cfg)
	bannerView.SetText(banner.Render(banner.Compact, state.bannerContext(), 0))

	state.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(bannerView, banner.Height(banner.Compact), 0, false).
		AddItem(body, 0, 1, true)

	state.pages = tview.NewPages().AddPage("main", state.layout, true, true)

	state.table.SetSelectionChangedFunc(func(row, col int) {
		state.showDetails(state.aliasAtRow(row))
	})
	state.table.SetSelectedFunc(func(row, col int) {
		if a := state.aliasAtRow(row); a != "" {
			state.selected = a
			state.action = ActionConnect
			app.Stop()
		}
	})

	state.tree.SetChangedFunc(func(node *tview.TreeNode) {
		if alias, ok := node.GetReference().(string); ok {
			state.showDetails(alias)
		}
	})
	state.tree.SetSelectedFunc(func(node *tview.TreeNode) {
		if alias, ok := node.GetReference().(string); ok && alias != "" {
			state.selected = alias
			state.action = ActionConnect
			app.Stop()
			return
		}
		// Group node — toggle expand/collapse.
		node.SetExpanded(!node.IsExpanded())
	})

	commonKeys := func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			if state.filter != "" {
				state.filterInput.SetText("")
				state.filter = ""
				state.refresh(state.currentAlias())
				return nil
			}
			app.Stop()
			return nil
		case tcell.KeyTab:
			state.toggleMode()
			return nil
		case tcell.KeyF1:
			state.showAbout()
			return nil
		}
		switch event.Rune() {
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		case 'q':
			app.Stop()
			return nil
		case '/':
			state.enterFilterMode()
			return nil
		case 'a':
			state.openForm("", config.HostConfig{Port: 22})
			return nil
		case 'e':
			if alias := state.currentAlias(); alias != "" {
				state.openForm(alias, state.cfg.Hosts[alias])
			}
			return nil
		case 'd':
			if alias := state.currentAlias(); alias != "" {
				state.confirmDelete(alias)
			}
			return nil
		case 's':
			if alias := state.currentAlias(); alias != "" {
				state.selected = alias
				state.action = ActionSFTP
				app.Stop()
			}
			return nil
		case 'f':
			if alias := state.currentAlias(); alias != "" {
				state.selected = alias
				state.action = ActionFiles
				app.Stop()
			}
			return nil
		case 'p':
			if alias := state.currentAlias(); alias != "" {
				state.openForwardMenu(alias)
			}
			return nil
		case 'c':
			if alias := state.currentAlias(); alias != "" {
				state.openSnippetMenu(alias)
			}
			return nil
		case 'i':
			if alias := state.currentAlias(); alias != "" {
				state.showResolvedConfig(alias)
			}
			return nil
		case '*':
			if alias := state.currentAlias(); alias != "" {
				state.togglePin(alias)
			}
			return nil
		case ' ':
			if alias := state.currentAlias(); alias != "" {
				if state.multiSelected[alias] {
					delete(state.multiSelected, alias)
				} else {
					state.multiSelected[alias] = true
				}
				state.refresh(alias)
			}
			return nil
		case 'x':
			state.openExecPrompt()
			return nil
		case 'w':
			if alias := state.currentAlias(); alias != "" {
				state.openWatchPrompt(alias)
			}
			return nil
		case 'u':
			state.openAccessMenu()
			return nil
		case 'P':
			state.openPlaybookForm()
			return nil
		case '?':
			state.showHelpOverlay()
			return nil
		case 'S':
			if state.sort == sortName {
				state.sort = sortRecent
			} else {
				state.sort = sortName
			}
			state.refresh(state.currentAlias())
			return nil
		case 'A':
			state.addGroupPrompt()
			return nil
		case 'R':
			state.renameGroupPrompt()
			return nil
		case 'D':
			state.deleteGroupPrompt()
			return nil
		case 'K':
			if alias := state.currentAlias(); alias != "" {
				state.killActiveForHost(alias)
			}
			return nil
		case 'V':
			if alias := state.currentAlias(); alias != "" {
				state.openKVMMenu(alias)
			}
			return nil
		case 'm':
			state.animLevel = state.animLevel.next()
			state.persistAnimLevel()
			state.stopDecor()
			state.stopDecor = state.startDecorativeTicker()
			state.stopSpin()
			state.stopSpin = state.startSpinTicker()
			if state.animLevel != animFull {
				// leave the border at its resting colour
				state.table.SetBorderColor(theme.Current.Primary)
				state.tree.SetBorderColor(theme.Current.Primary)
			}
			state.updateStatus()
			return nil
		}
		return event
	}

	state.table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'g':
			if n := state.table.GetRowCount(); n > 1 {
				state.table.Select(1, 0)
			}
			return nil
		case 'G':
			if n := state.table.GetRowCount(); n > 1 {
				state.table.Select(n-1, 0)
			}
			return nil
		}
		return commonKeys(event)
	})

	state.tree.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'g':
			if kids := state.tree.GetRoot().GetChildren(); len(kids) > 0 {
				state.tree.SetCurrentNode(kids[0])
			}
			return nil
		case 'G':
			kids := state.tree.GetRoot().GetChildren()
			if len(kids) > 0 {
				last := kids[len(kids)-1]
				if last.IsExpanded() {
					if hc := last.GetChildren(); len(hc) > 0 {
						last = hc[len(hc)-1]
					}
				}
				state.tree.SetCurrentNode(last)
			}
			return nil
		}
		return commonKeys(event)
	})

	state.refresh("")

	stopPing := startPinger(state.pings, state.probeInterval, func() {
		app.QueueUpdateDraw(func() { state.refresh(state.currentAlias()) })
	})
	defer stopPing()

	// One ticker for the session rather than one per round: it does nothing
	// between rounds (spinnerWanted gates the tick before it is ever queued;
	// see anim.go), which costs a channel receive every 90ms and keeps the
	// lifecycle trivial.
	state.stopSpin = state.startSpinTicker()
	defer func() { state.stopSpin() }()

	state.stopDecor = state.startDecorativeTicker()
	defer func() { state.stopDecor() }()

	// The terminal size is not known until the first draw. Pick the banner
	// variant then, and again on every resize, so the layout adapts instead
	// of being fixed at construction time.
	app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		w, h := screen.Size()
		state.termColors = screen.Colors()
		state.termWidth = w

		// The compact line's content depends on the width it has to fit, so
		// a resize has to re-render it even when the variant is unchanged.
		want := banner.ChooseVariant(h, w, state.wantFullBanner)
		if want != state.bannerVariant || w != state.bannerWidth {
			state.bannerVariant = want
			state.bannerWidth = w
			state.bannerView.SetText(banner.Render(want, state.bannerContext(), w))
			state.layout.ResizeItem(state.bannerView, banner.Height(want), 0)
		}

		if fh := footerHeight(h); fh != state.footerRows {
			state.footerRows = fh
			state.help.SetText(helpText(h))
			state.rightCol.ResizeItem(state.bottom, fh, 0)
		}

		return false
	})

	if err := app.SetRoot(state.pages, true).EnableMouse(true).Run(); err != nil {
		return "", ActionNone, nil, err
	}
	return state.selected, state.action, state.extraArgs, nil
}

// hostCol* are the column widths of the flat host table, sized for the 58-column
// left pane: 58 minus two border columns and two padding columns leaves 54
// usable inner columns. tview inserts a one-cell separator after every
// column, so the 5-column layout (mark/dot, alias, host, tags, last) spends 4
// of those 54 cells on separators before any content is drawn.
//
//	bar/dot/gap(3) + alias(14) + host(18) + tags(11) + last(4) = 50 content
//	+ 4 inter-column separators = 54 usable
const (
	hostColAlias = 14
	hostColHost  = 18
	hostColTags  = 11
	hostColLast  = 4
)

// column indices
const (
	colMark = iota // selection bar + status dot + gap
	colAlias
	colHost
	colTags
	colLast
	colCount
)

// buildHostWidget constructs the flat host view and stores it on s. Extracted
// from Run so tests can build the widget without an Application.
func buildHostWidget(s *uiState) {
	t := tview.NewTable().
		SetFixed(1, 0).            // header row stays put while the body scrolls
		SetSelectable(true, false) // whole rows, never individual cells
	t.SetBorder(true).
		SetTitle(" hosts (flat) ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)
	t.SetSelectedStyle(tcell.StyleDefault.
		Background(theme.Current.Selection).
		Foreground(theme.Current.SelText).
		Bold(true))
	s.table = t
}

const (
	modeFlat   = "flat"
	modeTree   = "tree"
	sortName   = "name"
	sortRecent = "recent"
)

// footerMinHeight is the terminal height at or above which the footer keeps
// both of its rows.
const footerMinHeight = 24

// pill renders a key as a small filled "button" — the key padded on a
// HelpKey-colored block — followed by its label in ordinary text. The
// [-:-] reset clears both foreground and background so the color never
// bleeds into the rest of the footer line.
func pill(key, label string) string {
	t := theme.Current
	return "[" + theme.ColorTag(t.Inverse) + ":" + theme.ColorTag(t.HelpKey) + "] " +
		key + " [-:-]" + label
}

// helpTextFull is the two-row footer. The key list does not fit one
// 80-column row, so it wraps to a second.
func helpTextFull() string {
	line1 := []string{
		pill("Enter", "shell"), pill("s", "sftp"), pill("f", "files"),
		pill("p", "fwd"), pill("c", "snippet"), pill("x", "exec"),
		pill("w", "watch"), pill("u", "audit"), pill("P", "playbook"),
	}
	line2 := []string{
		pill("Space", "mark"), pill("Tab", "tree"), pill("S", "sort"),
		pill("a/e/d", "host"), pill("A/R/D", "group"), pill("/", "filter"),
		pill("?", "help"), pill("q", "quit"),
	}
	return strings.Join(line1, " ") + "\n" + strings.Join(line2, " ")
}

// helpTextCompact is the single-row footer used when vertical space is
// scarce. It keeps the actions that have no other discoverable route and
// drops the rest, which the ? overlay already lists in full.
func helpTextCompact() string {
	return strings.Join([]string{
		pill("Enter", "shell"), pill("s", "sftp"), pill("f", "files"),
		pill("p", "fwd"), pill("x", "exec"), pill("u", "audit"), pill("/", "filter"),
		pill("?", "help"), pill("q", "quit"),
	}, " ")
}

// footerHeight is the row count for a terminal of the given height. Below
// footerMinHeight the second row costs more than it returns: with a compact
// banner (1 row), the status line (1) and a two-row footer, a 24-row
// terminal keeps only 20 rows of panes.
func footerHeight(termHeight int) int {
	if termHeight >= footerMinHeight {
		return 2
	}
	return 1
}

// helpText returns the footer for a terminal of the given height.
func helpText(termHeight int) string {
	if footerHeight(termHeight) == 2 {
		return helpTextFull()
	}
	return helpTextCompact()
}

// fullHelpText is the complete keymap shown by the `?` overlay.
func fullHelpText() string {
	k := theme.Current.HelpKeyTag()
	hd := theme.Current.PrimaryTag()
	row := func(keys, desc string) string {
		return "  " + k + fmt.Sprintf("%-12s", keys) + "[-] " + desc + "\n"
	}
	var b strings.Builder
	b.WriteString(hd + "Host list[-]\n")
	b.WriteString(row("Enter", "open an interactive shell"))
	b.WriteString(row("s / f", "SFTP REPL / 2-pane file manager"))
	b.WriteString(row("p", "forward menu: new / saved / recent / active"))
	b.WriteString(row("c", "snippet picker"))
	b.WriteString(row("i", "inspect resolved config — field sources"))
	b.WriteString(row("F1", "about — version, config, license"))
	b.WriteString(row("P", "run an Ansible playbook"))
	b.WriteString(row("x / w", "exec a command / watch a command"))
	b.WriteString(row("u", "access audit: scan, ownership, offline Cloud artifacts, reports and lookups"))
	b.WriteString(row("Space", "toggle multi-select on the host"))
	b.WriteString(row("Tab", "switch flat / tree view"))
	b.WriteString(row("S", "toggle sort: name / recently used"))
	b.WriteString(row("*", "pin / unpin host (pinned float to the top)"))
	b.WriteString(row("m", "cycle animation: off / informative / full"))
	b.WriteString(row("/", "filter (alias / host / user / tag / group)"))
	b.WriteString(row("j / k", "move down / up"))
	b.WriteString(row("g / G", "jump to top / bottom"))
	b.WriteString(row("a / e / d", "add / edit / delete host"))
	b.WriteString(row("A / R / D", "add / rename / delete group"))
	b.WriteString(row("K", "stop the host's active forward (one at a time)"))
	b.WriteString(row("V", "kvm power menu (reset / power / off / web / status)"))
	b.WriteString(row("Esc / q", "clear filter, or quit"))
	b.WriteString("\n" + hd + "Filter queries[-]  " + theme.Current.DimTag() + "(type after /)[-]\n")
	b.WriteString(row("tag:NAME", "hosts with a matching tag"))
	b.WriteString(row("group:NAME", "hosts in a matching group"))
	b.WriteString(row("backend:", "external | native — by SSH backend"))
	b.WriteString(row("<text>", "plain substring: alias / host / user / tag / group"))
	b.WriteString("\n" + hd + "File manager[-]\n")
	b.WriteString(row("Tab", "switch panel (local / remote)"))
	b.WriteString(row("Enter", "enter directory"))
	b.WriteString(row("Bksp / h", "parent directory"))
	b.WriteString(row("F5 / c", "copy to the other panel"))
	b.WriteString(row("F7 / m", "make directory"))
	b.WriteString(row("F8 / d", "delete (file or empty dir)"))
	b.WriteString(row("F6 / S", "directory sync (one-way, recursive)"))
	b.WriteString(row("r", "refresh both panels"))
	b.WriteString(row("q / Esc", "back to the host list"))
	b.WriteString("\n" + hd + "Exec result viewer[-]\n")
	b.WriteString(row("j / k", "scroll   (PgUp/PgDn page, g/G ends)"))
	b.WriteString(row("o", "cycle filter: all / ok / failed"))
	b.WriteString(row("n / p", "jump to next / previous host"))
	b.WriteString(row("w", "save the full output to a file"))
	b.WriteString(row("q / x", "back to host list / exit to shell"))
	b.WriteString("\n" + hd + "Drift viewer (exec --diff)[-]\n")
	b.WriteString(row("Enter", "open the selected group's diff against baseline"))
	b.WriteString(row("b", "set the highlighted group as the new baseline"))
	b.WriteString(row("n / p", "next / previous group in the diff detail"))
	b.WriteString(row("w", "save the current diff (plain text) to a file"))
	b.WriteString(row("q / Esc", "back (detail → overview → host list)"))
	b.WriteString("\n" + hd + "Inside an SSH session[-]  " + theme.Current.DimTag() + "(after Enter)[-]\n")
	b.WriteString(row("~r", "run this host's login_steps in place"))
	b.WriteString(row("~~", "send a literal ~"))
	b.WriteString("  " + theme.Current.DimTag() +
		"~ is special only at the start of a line, and ~r\n" +
		"  also re-escalates after you exit back down.\n" +
		"  Override the escape char with escalate_key.[-]\n")
	return b.String()
}

// welcomeText fills the details pane when the config has no hosts at all.
func welcomeText() string {
	k := theme.Current.HelpKeyTag()
	return "\n  Welcome to sshmgr.\n\n" +
		"  No hosts configured yet — press " + k + "a[-] to add one.\n\n" +
		"  Or import an existing fleet from a shell:\n" +
		"    sshmgr import ssh-config\n" +
		"    sshmgr import ansible <inventory>\n\n" +
		"  Press " + k + "?[-] for the full key list.\n"
}

// noMatchText fills the details pane when the active filter matches nothing.
func noMatchText(filter string) string {
	k := theme.Current.HelpKeyTag()
	dim := theme.Current.DimTag()
	return fmt.Sprintf("\n  No hosts match filter %q.\n\n", filter) +
		"  " + dim + "queries: tag:web · group:prod · backend:external[-]\n" +
		"  " + dim + "or plain text — alias / host / user / tag / group[-]\n\n" +
		"  Press " + k + "Esc[-] to clear."
}

type uiState struct {
	app        *tview.Application
	cfg        *config.Config
	configPath string

	table         *tview.Table
	tree          *tview.TreeView
	leftPages     *tview.Pages
	details       *tview.TextView
	pages         *tview.Pages
	layout        *tview.Flex
	help          *tview.TextView
	status        *tview.TextView
	bottom        *tview.Pages
	filterInput   *tview.InputField
	bannerView    *tview.TextView
	bannerVariant banner.Variant
	// bannerWidth is the width the banner was last rendered for. The compact
	// line drops parts to fit, so a resize changes its content.
	bannerWidth int
	// wantFullBanner opts into the six-row ASCII art. The compact line is
	// the default at every terminal size; see resolveWantFullBanner.
	wantFullBanner bool
	rightCol       *tview.Flex
	footerRows     int
	termColors     int
	termWidth      int

	mode          string // modeFlat or modeTree
	sort          string // sortName or sortRecent
	filter        string
	aliases       []string
	selected      string
	action        Action
	extraArgs     []string
	pings         *pingMap
	multiSelected map[string]bool

	// animLevel controls how much of the UI is allowed to move; see anim.go.
	animLevel animLevel
	// probeInterval is the resolved repeat interval for probe rounds; see
	// resolveProbeInterval in ping.go. Used to render the AVAILABILITY
	// section's history span alongside its round count.
	probeInterval time.Duration
	// animFrame advances the braille spinner shown while a probe round runs.
	animFrame int
	// stopDecor stops the decorative breathing-border ticker. The m handler
	// restarts it whenever the level is cycled at runtime; see anim.go.
	stopDecor func()
	// stopSpin stops the probe-progress spinner ticker. The m handler
	// restarts it too, symmetrically with stopDecor: without this, cycling
	// from off to informative left no ticker running for the rest of the
	// session (startTicker had already returned its no-op stop under off),
	// and cycling to off left the previous ticker running forever.
	stopSpin func()
}

// updateBanner re-renders the banner text from current state. Only the
// Compact variant carries counters (host count, forward count) that can go
// stale, so the full ASCII variant is skipped as pointless work.
func (s *uiState) updateBanner() {
	if s.bannerVariant != banner.Compact {
		return
	}
	s.bannerView.SetText(banner.Render(banner.Compact, s.bannerContext(), s.termWidth))
}

// bannerContext gathers what the compact banner shows. The forward count is
// read from the registry, which is what the details panel already does.
func (s *uiState) bannerContext() banner.Context {
	active, _ := fwdregistry.List()
	return banner.Context{
		Version:    buildVersion,
		ConfigPath: shortenHome(s.configPath),
		Theme:      theme.Current.Name,
		Hosts:      len(s.cfg.Hosts),
		Forwards:   len(active),
	}
}

// shortenHome replaces the user's home directory prefix with ~ so the
// compact banner stays inside its column budget.
func shortenHome(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !strings.HasPrefix(p, home) {
		return p
	}
	return "~" + p[len(home):]
}

// lastLogin returns the most recent LoginEntry for alias, or zero if none.
func sortedAliases(hosts map[string]config.HostConfig) []string {
	out := make([]string, 0, len(hosts))
	for k := range hosts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func splitCommands(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return 0
}

func centered(p tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, height, 1, true).
			AddItem(nil, 0, 1, false), width, 1, true).
		AddItem(nil, 0, 1, false)
}

// resolveWantFullBanner decides whether the user asked for the six-row ASCII
// art instead of the compact header, using the same precedence as the theme:
// environment override, then config, then the default. The default is
// compact at every terminal size — the compact line carries the config path,
// theme, host count and live forward count, none of which the art shows, and
// it returns five rows to the host list.
func resolveWantFullBanner(cfg *config.Config) bool {
	v := os.Getenv("SSHMGR_BANNER")
	if v == "" && cfg != nil {
		v = cfg.Banner
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "full", "ascii", "art":
		return true
	default:
		return false
	}
}

// applyTheme picks a palette (env override > config > default), stores it in
// theme.Current, and pushes the colors into tview.Styles so newly-created
// widgets inherit them.
func applyTheme(cfg *config.Config) {
	name := os.Getenv("SSHMGR_THEME")
	if name == "" && cfg != nil {
		name = cfg.Theme
	}
	theme.Set(name)
	p := theme.Current

	tview.Styles = tview.Theme{
		PrimitiveBackgroundColor:    tcell.ColorDefault,
		ContrastBackgroundColor:     p.FieldBg,
		MoreContrastBackgroundColor: theme.Current.Inverse,
		BorderColor:                 p.Primary,
		TitleColor:                  p.Primary,
		GraphicsColor:               p.Primary,
		PrimaryTextColor:            p.Text,
		SecondaryTextColor:          p.AccentB,
		TertiaryTextColor:           p.Dim,
		InverseTextColor:            p.Inverse,
		ContrastSecondaryTextColor:  p.Primary,
	}

	// tview.Borders is an anonymous struct var, so fields are set one by
	// one. The *Focus fields default to double-line box drawing; without
	// overriding them the focused pane would render ╔═╗ against the
	// rounded corners of every other pane.
	tview.Borders.TopLeft = '╭'
	tview.Borders.TopRight = '╮'
	tview.Borders.BottomLeft = '╰'
	tview.Borders.BottomRight = '╯'
	tview.Borders.TopLeftFocus = '╭'
	tview.Borders.TopRightFocus = '╮'
	tview.Borders.BottomLeftFocus = '╰'
	tview.Borders.BottomRightFocus = '╯'
	// Focused panes are distinguished by border colour (FocusBdr), not by
	// a heavier line weight, so the focus runes match the normal ones.
	tview.Borders.HorizontalFocus = tview.Borders.Horizontal
	tview.Borders.VerticalFocus = tview.Borders.Vertical
}
