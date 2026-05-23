package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"


	"sshmgr/internal/banner"
	"sshmgr/internal/config"
	"sshmgr/internal/theme"

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
	// ActionPlaybook runs an Ansible playbook. extraArgs is the playbook
	// name followed by a {--host a,b | --group g} selector and optional
	// {--check, --diff, --extra-vars V} flags.
	ActionPlaybook Action = "playbook"
)

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

	state.list = tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	state.list.SetBorder(true).
		SetTitle(" hosts (flat) ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

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
		AddPage(modeFlat, state.list, true, false).
		AddPage(modeTree, state.tree, true, true)

	state.details = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	state.details.SetBorder(true).
		SetTitle(" details ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Dim).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)

	state.help = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	state.help.SetText(helpText())

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

	body := tview.NewFlex().
		AddItem(state.leftPages, 36, 0, true).
		AddItem(right, 0, 1, false)

	bannerView := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft).
		SetWrap(false)
	bannerView.SetText(banner.ColoredTview())

	state.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(bannerView, banner.Height(), 0, false).
		AddItem(body, 0, 1, true)

	state.pages = tview.NewPages().AddPage("main", state.layout, true, true)

	state.list.SetChangedFunc(func(i int, _, _ string, _ rune) {
		state.showDetails(state.aliasAt(i))
	})
	state.list.SetSelectedFunc(func(i int, _, _ string, _ rune) {
		state.selected = state.aliasAt(i)
		state.action = ActionConnect
		app.Stop()
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
		}
		return event
	}

	state.list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'g':
			state.list.SetCurrentItem(0)
			return nil
		case 'G':
			state.list.SetCurrentItem(state.list.GetItemCount() - 1)
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

	stopPing := startPinger(cfg, state.pings, func() {
		app.QueueUpdateDraw(func() { state.refresh(state.currentAlias()) })
	})
	defer stopPing()

	if err := app.SetRoot(state.pages, true).EnableMouse(true).Run(); err != nil {
		return "", ActionNone, nil, err
	}
	return state.selected, state.action, state.extraArgs, nil
}

const (
	modeFlat   = "flat"
	modeTree   = "tree"
	sortName   = "name"
	sortRecent = "recent"
)

// helpText is dynamic so it picks up the current theme's HelpKey color. It
// is two lines — the full key list overflows a single 80-column row.
// pill renders a key as a small filled "button" — the key padded on a
// HelpKey-colored block — followed by its label in ordinary text. The
// [-:-] reset clears both foreground and background so the color never
// bleeds into the rest of the footer line.
func pill(key, label string) string {
	t := theme.Current
	return "[" + theme.ColorTag(t.Inverse) + ":" + theme.ColorTag(t.HelpKey) + "] " +
		key + " [-:-]" + label
}

func helpText() string {
	line1 := []string{
		pill("Enter", "shell"), pill("s", "sftp"), pill("f", "files"),
		pill("p", "fwd"), pill("c", "snippet"), pill("x", "exec"),
		pill("w", "watch"), pill("P", "playbook"),
	}
	line2 := []string{
		pill("Space", "mark"), pill("Tab", "tree"), pill("S", "sort"),
		pill("a/e/d", "host"), pill("A/R/D", "group"), pill("/", "filter"),
		pill("?", "help"), pill("q", "quit"),
	}
	return strings.Join(line1, " ") + "\n" + strings.Join(line2, " ")
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
	b.WriteString(row("P", "run an Ansible playbook"))
	b.WriteString(row("x / w", "exec a command / watch a command"))
	b.WriteString(row("Space", "toggle multi-select on the host"))
	b.WriteString(row("Tab", "switch flat / tree view"))
	b.WriteString(row("S", "toggle sort: name / recently used"))
	b.WriteString(row("*", "pin / unpin host (pinned float to the top)"))
	b.WriteString(row("/", "filter (alias / host / user / tag / group)"))
	b.WriteString(row("j / k", "move down / up"))
	b.WriteString(row("g / G", "jump to top / bottom"))
	b.WriteString(row("a / e / d", "add / edit / delete host"))
	b.WriteString(row("A / R / D", "add / rename / delete group"))
	b.WriteString(row("K", "stop the host's active forward (one at a time)"))
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

	list        *tview.List
	tree        *tview.TreeView
	leftPages   *tview.Pages
	details     *tview.TextView
	pages       *tview.Pages
	layout      *tview.Flex
	help        *tview.TextView
	status      *tview.TextView
	bottom      *tview.Pages
	filterInput *tview.InputField

	mode          string // modeFlat or modeTree
	sort          string // sortName or sortRecent
	filter        string
	aliases       []string
	selected      string
	action        Action
	extraArgs     []string
	pings         *pingMap
	multiSelected map[string]bool
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
}
