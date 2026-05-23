package tui

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"time"

	"sshmgr/internal/ansible"
	"sshmgr/internal/banner"
	"sshmgr/internal/config"
	"sshmgr/internal/forwards"
	"sshmgr/internal/fwdregistry"
	"sshmgr/internal/snippets"
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
func (s *uiState) lastLogin(alias string) (config.LoginEntry, bool) {
	for _, e := range s.cfg.LoginHistory {
		if e.Alias == alias {
			return e, true
		}
	}
	return config.LoginEntry{}, false
}

// aliasOrder returns aliases sorted by the current sort mode.
func (s *uiState) aliasOrder() []string {
	out := sortedAliases(s.cfg.Hosts)
	if s.sort == sortRecent {
		recent := map[string]string{}
		for _, e := range s.cfg.LoginHistory {
			if _, ok := recent[e.Alias]; !ok {
				recent[e.Alias] = e.When
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			ri, rj := recent[out[i]], recent[out[j]]
			if ri == rj {
				return out[i] < out[j]
			}
			return ri > rj // newer (lex-greater RFC3339) first
		})
	}
	// Pinned hosts float to the top as a priority layer, keeping their
	// name/recent order within the pinned and non-pinned blocks.
	sort.SliceStable(out, func(i, j int) bool {
		return s.cfg.Hosts[out[i]].Pinned && !s.cfg.Hosts[out[j]].Pinned
	})
	return out
}

// focusList sends focus back to whichever host list (flat or tree) is active.
// Use after dismissing a modal/form so the user lands on something visible.
func (s *uiState) focusList() {
	if s.mode == modeTree {
		s.app.SetFocus(s.tree)
	} else {
		s.app.SetFocus(s.list)
	}
}

func (s *uiState) toggleMode() {
	alias := s.currentAlias()
	if s.mode == modeFlat {
		s.mode = modeTree
	} else {
		s.mode = modeFlat
	}
	s.leftPages.SwitchToPage(s.mode)
	s.refresh(alias)
	switch s.mode {
	case modeTree:
		s.app.SetFocus(s.tree)
	default:
		s.app.SetFocus(s.list)
	}
}

func (s *uiState) refresh(focusAlias string) {
	switch s.mode {
	case modeTree:
		s.refreshTree(focusAlias)
	default:
		s.refreshList(focusAlias)
	}
	s.updateStatus()
}

// updateStatus refreshes the one-line status bar: view mode, sort order,
// active filter, multi-selection size and the host count.
func (s *uiState) updateStatus() {
	dim := theme.Current.DimTag()
	acc := theme.Current.AccentBTag()
	parts := []string{
		acc + s.mode + "[-]",
		dim + "sort " + s.sort + "[-]",
	}
	if s.filter != "" {
		parts = append(parts, dim+"filter [-]"+acc+s.filter+"[-]")
	}
	if n := len(s.multiSelected); n > 0 {
		parts = append(parts, fmt.Sprintf("%s%d selected[-]", acc, n))
	}
	total := len(s.cfg.Hosts)
	if s.filter != "" {
		matched := 0
		for a := range s.cfg.Hosts {
			if s.matchesFilter(a) {
				matched++
			}
		}
		parts = append(parts, fmt.Sprintf("%s%d/%d hosts[-]", dim, matched, total))
	} else {
		parts = append(parts, fmt.Sprintf("%s%d hosts[-]", dim, total))
	}
	s.status.SetText("  " + strings.Join(parts, dim+"  ·  [-]"))
}

func (s *uiState) enterFilterMode() {
	s.bottom.SwitchToPage("filter")
	s.app.SetFocus(s.filterInput)
}

func (s *uiState) exitFilterMode() {
	s.bottom.SwitchToPage("help")
	if s.mode == modeTree {
		s.app.SetFocus(s.tree)
	} else {
		s.app.SetFocus(s.list)
	}
}

func (s *uiState) matchesFilter(alias string) bool {
	if s.filter == "" {
		return true
	}
	h, ok := s.cfg.ResolveHost(alias)
	if !ok {
		return false
	}
	return hostMatchesQuery(h, alias, s.filter)
}

// hostMatchesQuery reports whether the resolved host h (named alias) matches
// query. A `tag:`, `group:` or `backend:` prefix does a structured match;
// anything else — including an unknown `key:value` prefix — falls back to a
// plain substring search across alias / host / user / tags / groups. query
// is expected already lower-cased.
func hostMatchesQuery(h config.HostConfig, alias, query string) bool {
	if query == "" {
		return true
	}
	if key, val, ok := strings.Cut(query, ":"); ok {
		switch key {
		case "tag":
			return anyContainsFold(h.Tags, val)
		case "group":
			return anyContainsFold(h.Groups, val)
		case "backend":
			backend := "native"
			if h.External {
				backend = "external"
			}
			return strings.HasPrefix(backend, val)
		}
		// unknown prefix — fall through to plain-text matching
	}
	hay := strings.ToLower(alias + " " + h.Host + " " + h.User + " " +
		strings.Join(h.Tags, " ") + " " + strings.Join(h.Groups, " "))
	return strings.Contains(hay, query)
}

// anyContainsFold reports whether any list element contains sub, case-fold.
func anyContainsFold(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(strings.ToLower(s), sub) {
			return true
		}
	}
	return false
}

func (s *uiState) aliasAt(i int) string {
	if i < 0 || i >= len(s.aliases) {
		return ""
	}
	return s.aliases[i]
}

func (s *uiState) currentAlias() string {
	if s.mode == modeTree {
		node := s.tree.GetCurrentNode()
		if node == nil {
			return ""
		}
		if alias, ok := node.GetReference().(string); ok {
			return alias
		}
		return ""
	}
	return s.aliasAt(s.list.GetCurrentItem())
}

// rowMarker is the 2-char list prefix for a host: multi-selection wins,
// then a pin star, then blank.
func (s *uiState) rowMarker(alias string) string {
	if s.multiSelected[alias] {
		return "* "
	}
	if s.cfg.Hosts[alias].Pinned {
		return "★ "
	}
	return "  "
}

// togglePin flips the pinned flag on a host and persists it. A no-op on a
// group node (alias == "").
func (s *uiState) togglePin(alias string) {
	h, ok := s.cfg.Hosts[alias]
	if !ok {
		return
	}
	h.Pinned = !h.Pinned
	s.cfg.Hosts[alias] = h
	if err := config.Save(s.cfg, s.configPath); err != nil {
		s.modal("save failed: "+err.Error(), nil)
		return
	}
	s.refresh(alias)
}

// refreshTree rebuilds the tree view from the current config and filter.
// Hosts are placed under the first group in their `groups:` list; additional
// groups become tags visible after the alias. Hosts with no group land in
// "(ungrouped)".
func (s *uiState) refreshTree(focusAlias string) {
	root := tview.NewTreeNode(".").SetSelectable(false)

	groupHosts := map[string][]string{}
	// Seed empty groups so user-created groups with no members yet are still
	// visible in the tree (otherwise pressing 'A' to add a group looks like
	// a no-op and a second add says the group already exists).
	if s.filter == "" {
		for g := range s.cfg.Groups {
			groupHosts[g] = nil
		}
	}
	allAliases := s.aliasOrder()
	for _, alias := range allAliases {
		if !s.matchesFilter(alias) {
			continue
		}
		h := s.cfg.Hosts[alias]
		key := "(ungrouped)"
		if len(h.Groups) > 0 {
			key = h.Groups[0]
		}
		groupHosts[key] = append(groupHosts[key], alias)
	}

	groupNames := make([]string, 0, len(groupHosts))
	for g := range groupHosts {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)

	// Force a consistent selected style so the highlight is always
	// black-on-Selection (yellow) regardless of each node's own text color.
	selStyle := tcell.StyleDefault.
		Background(theme.Current.Selection).
		Foreground(theme.Current.Inverse).
		Bold(true)

	var focusNode *tview.TreeNode
	var focusGroup *tview.TreeNode
	for _, g := range groupNames {
		groupNode := tview.NewTreeNode(fmt.Sprintf("%s (%d)", g, len(groupHosts[g]))).
			SetSelectable(true).
			SetExpanded(s.filter != "").
			SetColor(theme.Current.Primary).
			SetSelectedTextStyle(selStyle)
		for _, alias := range groupHosts[g] {
			h, _ := s.cfg.ResolveHost(alias)
			extra := []string{}
			for _, other := range s.cfg.Hosts[alias].Groups[min(1, len(s.cfg.Hosts[alias].Groups)):] {
				extra = append(extra, other)
			}
			for _, t := range h.Tags {
				if t == g {
					continue
				}
				extra = append(extra, t)
			}
			label := alias
			if len(extra) > 0 {
				label = fmt.Sprintf("%-22s [%s]", alias, strings.Join(uniqueSorted(extra), " "))
			}
			label = s.pings.Get(alias).emoji() + s.rowMarker(alias) + label
			hostNode := tview.NewTreeNode(label).
				SetReference(alias).
				SetSelectable(true).
				SetColor(theme.Current.Text).
				SetSelectedTextStyle(selStyle)
			groupNode.AddChild(hostNode)
			if alias == focusAlias {
				focusNode = hostNode
				focusGroup = groupNode
			}
		}
		root.AddChild(groupNode)
	}

	// Make sure the parent of the focused host is expanded so the cursor is visible.
	if focusGroup != nil {
		focusGroup.SetExpanded(true)
	}

	s.tree.SetRoot(root)
	switch {
	case focusNode != nil:
		s.tree.SetCurrentNode(focusNode)
		if alias, ok := focusNode.GetReference().(string); ok {
			s.showDetails(alias)
		}
	case len(root.GetChildren()) > 0:
		// No specific focus — land on the first group node (collapsed).
		s.tree.SetCurrentNode(root.GetChildren()[0])
		s.details.SetText("\n  Press [yellow]Enter[-] on a group to expand, [yellow]/[-] to filter, [yellow]Tab[-] for flat view.")
	default:
		if s.filter != "" {
			s.details.SetText(noMatchText(s.filter))
		} else {
			s.details.SetText(welcomeText())
		}
	}
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (s *uiState) refreshList(focusAlias string) {
	all := s.aliasOrder()
	s.aliases = s.aliases[:0]
	for _, a := range all {
		if s.matchesFilter(a) {
			s.aliases = append(s.aliases, a)
		}
	}
	s.list.Clear()
	focusIdx := 0
	for i, alias := range s.aliases {
		h, _ := s.cfg.ResolveHost(alias)
		s.list.AddItem(s.pings.Get(alias).emoji()+s.rowMarker(alias)+listRowText(alias, h), "", 0, nil)
		if alias == focusAlias {
			focusIdx = i
		}
	}
	if len(s.aliases) == 0 {
		if s.filter != "" {
			s.details.SetText(noMatchText(s.filter))
		} else {
			s.details.SetText(welcomeText())
		}
		return
	}
	s.list.SetCurrentItem(focusIdx)
	s.showDetails(s.aliases[focusIdx])
}

// listRowText renders one row with alias + space-separated tag chips on the right.
// tview.List's default rendering does not interpret color tags, so we keep this
// in plain text — tags are shown in brackets so they read clearly.
func listRowText(alias string, h config.HostConfig) string {
	if len(h.Tags) == 0 {
		return alias
	}
	return fmt.Sprintf("%-22s [%s]", alias, strings.Join(h.Tags, " "))
}

// hostBadges renders a host's notable flags and tags as a one-line chip
// strip for the details panel — empty when there is nothing notable.
func hostBadges(h config.HostConfig) string {
	inv := theme.ColorTag(theme.Current.Inverse)
	chip := func(label string, bg tcell.Color) string {
		return "[" + inv + ":" + theme.ColorTag(bg) + "] " + label + " [-:-]"
	}
	var chips []string
	if h.External {
		chips = append(chips, chip("external", theme.Current.Warning))
	}
	if h.AutoDuoPush {
		chips = append(chips, chip("duo", theme.Current.AccentB))
	}
	if h.Persistent != "" {
		chips = append(chips, chip(h.Persistent, theme.Current.AccentB))
	}
	out := strings.Join(chips, " ")
	if len(h.Tags) > 0 {
		tags := theme.Current.DimTag() + "#" + strings.Join(h.Tags, " #") + "[-]"
		if out != "" {
			out += "   "
		}
		out += tags
	}
	return out
}

func (s *uiState) showDetails(alias string) {
	if alias == "" {
		s.details.SetText("")
		return
	}
	h, _ := s.cfg.ResolveHost(alias)
	prim := theme.Current.PrimaryTag()   // field labels
	dim := theme.Current.DimTag()        // metadata / secondary
	warn := theme.Current.WarningTag()   // external / caution
	accent := theme.Current.AccentBTag() // values worth spotting (proxy)
	var b strings.Builder
	// label writes "key:" in the primary color, the value in valueTag
	// (empty → default text color).
	label := func(k, valueTag, v string) {
		fmt.Fprintf(&b, "%s%-22s[-] %s%s[-]\n", prim, k+":", valueTag, v)
	}
	header := alias
	if h.Pinned {
		header = "★ " + alias
	}
	fmt.Fprintf(&b, "[%s::b]%s[-:-:-]\n", theme.ColorTag(theme.Current.Primary), header)
	if badges := hostBadges(h); badges != "" {
		b.WriteString(badges + "\n")
	}
	b.WriteString("\n")

	if h.External {
		label("backend", warn, "external (system ssh / scp / sftp)")
	} else {
		label("backend", "", "native (Go SSH)")
	}
	label("host", "", h.Host)
	if h.Port != 0 {
		label("port", "", strconv.Itoa(h.Port))
	}
	if h.User != "" {
		label("user", "", h.User)
	}
	if h.Key != "" {
		label("key", "", h.Key)
	}
	if len(h.Groups) > 0 {
		label("groups", "", strings.Join(h.Groups, ", "))
	}
	if len(h.Tags) > 0 {
		label("tags", "", strings.Join(h.Tags, ", "))
	}
	label("auto_duo_push", "", fmt.Sprintf("%t", h.AutoDuoPush))
	if h.AutoAcceptHostKey {
		label("auto_accept_host_key", "", "true")
	}
	if h.ProxyJump != "" {
		label("proxy_jump", accent, h.ProxyJump)
	}
	if h.ProxyCommand != "" {
		label("proxy_command", accent, h.ProxyCommand)
	}
	if h.Become.User != "" {
		method := h.Become.Method
		if method == "" {
			method = "sudo"
		}
		label("become", "", method+" -> "+h.Become.User)
	}
	if e, ok := s.lastLogin(alias); ok {
		label("last "+e.Action, dim, e.When)
	}
	if len(h.LoginSteps) > 0 {
		label("login_steps", "", fmt.Sprintf("%d step(s)", len(h.LoginSteps)))
		for i, st := range h.LoginSteps {
			env := st.PasswordEnv
			if env == "" && st.Response != "" {
				env = "<literal>"
			}
			fmt.Fprintf(&b, "  %s%d.[-] %s  %s(expect: %q  pass: %s)[-]\n",
				accent, i+1, st.Command, dim, st.Expect, env)
		}
	}
	if len(h.Commands) > 0 {
		fmt.Fprintf(&b, "\n%scommands:[-]\n", prim)
		for _, c := range h.Commands {
			fmt.Fprintf(&b, "  %s-[-] %s\n", dim, c)
		}
	}
	// Active forwards going through this host (read from the registry on
	// every refresh — typical N is 0-3 so the readdir is negligible).
	active, _ := fwdregistry.List()
	var hostActive []fwdregistry.Entry
	for _, e := range active {
		if e.Alias == alias {
			hostActive = append(hostActive, e)
		}
	}
	if len(hostActive) > 0 {
		fmt.Fprintf(&b, "\n%sactive forwards[-]\n", prim)
		for _, e := range hostActive {
			age := time.Since(e.StartedAt).Round(time.Second)
			fmt.Fprintf(&b, "  %s-%s %s[-]   %spid %d · age %s · %s · %s[-]\n",
				accent, e.Type, e.Spec, dim, e.PID, age, e.Source, e.Backend)
		}
	}

	hk := theme.Current.HelpKeyTag()
	// The footer already lists the global keys; this block only surfaces
	// the two host actions the footer has no room for, plus the kill row
	// when there's a live tunnel that can actually be stopped.
	fmt.Fprintf(&b, "\n%sactions[-]\n", prim)
	fmt.Fprintf(&b, "  %si[-] inspect config   %s*[-] pin / unpin\n", hk, hk)
	if len(hostActive) > 0 {
		suffix := "stop active forward"
		if len(hostActive) > 1 {
			suffix = fmt.Sprintf("stop active forward (1 of %d — pick in `p` for the rest)", len(hostActive))
		}
		fmt.Fprintf(&b, "  %sK[-] %s\n", hk, suffix)
	}
	s.details.SetText(b.String())
}

func (s *uiState) openForm(originalAlias string, h config.HostConfig) {
	form := tview.NewForm()

	alias := originalAlias
	host := h.Host
	port := h.Port
	if port == 0 {
		port = 22
	}
	usr := h.User
	key := h.Key
	autoDuo := h.AutoDuoPush
	autoHostKey := h.AutoAcceptHostKey
	external := h.External
	pinned := h.Pinned
	proxyJump := h.ProxyJump
	proxyCommand := h.ProxyCommand
	groups := strings.Join(h.Groups, ", ")
	tags := strings.Join(h.Tags, ", ")
	becomeUser := h.Become.User
	becomeMethod := h.Become.Method
	if becomeMethod == "" {
		becomeMethod = "sudo"
	}
	commands := strings.Join(h.Commands, "\n")

	form.AddInputField("alias", alias, 30, nil, func(v string) { alias = strings.TrimSpace(v) })
	form.AddInputField("host", host, 40, nil, func(v string) { host = strings.TrimSpace(v) })
	form.AddInputField("port", strconv.Itoa(port), 6, tview.InputFieldInteger, func(v string) {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	})
	form.AddInputField("user", usr, 30, nil, func(v string) { usr = strings.TrimSpace(v) })
	form.AddInputField("key (path)", key, 50, nil, func(v string) { key = strings.TrimSpace(v) })
	form.AddCheckbox("auto_duo_push", autoDuo, func(v bool) { autoDuo = v })
	form.AddCheckbox("auto_accept_host_key", autoHostKey, func(v bool) { autoHostKey = v })
	form.AddCheckbox("external (just exec `ssh <host>`)", external, func(v bool) { external = v })
	form.AddCheckbox("pinned (float to the top of the list)", pinned, func(v bool) { pinned = v })
	form.AddInputField("groups (comma-sep)", groups, 40, nil, func(v string) { groups = v })
	form.AddInputField("tags (comma-sep)", tags, 40, nil, func(v string) { tags = v })
	form.AddInputField("proxy_jump (alias)", proxyJump, 30, nil, func(v string) { proxyJump = strings.TrimSpace(v) })
	form.AddInputField("proxy_command", proxyCommand, 50, nil, func(v string) { proxyCommand = v })
	form.AddInputField("become user", becomeUser, 30, nil, func(v string) { becomeUser = strings.TrimSpace(v) })
	form.AddDropDown("become method", []string{"sudo", "su"}, indexOf([]string{"sudo", "su"}, becomeMethod), func(v string, _ int) { becomeMethod = v })
	form.AddTextArea("commands (one per line)", commands, 60, 6, 0, func(v string) { commands = v })

	if dd, ok := form.GetFormItemByLabel("become method").(*tview.DropDown); ok {
		dd.SetListStyles(
			tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(theme.Current.Text),
			tcell.StyleDefault.Background(theme.Current.Selection).Foreground(theme.Current.Inverse).Bold(true),
		)
	}

	title := " add host "
	if originalAlias != "" {
		title = " edit " + originalAlias + " "
	}
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).
		SetTitle(title).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	closeForm := func() {
		s.pages.RemovePage("form")
		s.focusList()
	}

	form.AddButton("Save", func() {
		alias = strings.TrimSpace(alias)
		if alias == "" || host == "" {
			s.modal("alias and host are required", func() { s.app.SetFocus(form) })
			return
		}
		if originalAlias != "" && alias != originalAlias {
			delete(s.cfg.Hosts, originalAlias)
			// Carry a multi-selection over to the renamed alias.
			if s.multiSelected[originalAlias] {
				delete(s.multiSelected, originalAlias)
				s.multiSelected[alias] = true
			}
		}
		if _, exists := s.cfg.Hosts[alias]; exists && originalAlias == "" {
			s.modal(fmt.Sprintf("alias %q already exists", alias), func() { s.app.SetFocus(form) })
			return
		}
		newHost := config.HostConfig{
			Host:              host,
			Port:              port,
			User:              usr,
			Key:               key,
			AutoDuoPush:       autoDuo,
			AutoAcceptHostKey: autoHostKey,
			External:          external,
			Pinned:            pinned,
			ProxyJump:         proxyJump,
			ProxyCommand:      strings.TrimSpace(proxyCommand),
			Groups:            splitCSV(groups),
			Tags:              splitCSV(tags),
			Commands:          splitCommands(commands),
		}
		if becomeUser != "" {
			newHost.Become = config.BecomeConfig{Method: becomeMethod, User: becomeUser}
		}
		s.cfg.Hosts[alias] = newHost
		if err := config.Save(s.cfg, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		closeForm()
		s.refresh(alias)
	})
	form.AddButton("Cancel", closeForm)

	form.SetCancelFunc(closeForm)

	s.pages.AddPage("form", centered(form, 76, 32), true, true)
	s.app.SetFocus(form)
}

// currentGroup returns the group name relevant to the current selection.
// In tree mode: the name of the highlighted group node, or the parent group
// of a highlighted host node. In flat mode: the primary group of the
// highlighted host (or "" if the host has no group).
func (s *uiState) currentGroup() string {
	if s.mode == modeTree {
		node := s.tree.GetCurrentNode()
		if node == nil {
			return ""
		}
		if alias, ok := node.GetReference().(string); ok && alias != "" {
			if h, ok := s.cfg.Hosts[alias]; ok && len(h.Groups) > 0 {
				return h.Groups[0]
			}
			return ""
		}
		// Group node — strip color tags + count suffix from the text.
		raw := node.GetText()
		raw = stripColorTags(raw)
		if i := strings.LastIndex(raw, "("); i > 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		return raw
	}
	alias := s.currentAlias()
	if alias == "" {
		return ""
	}
	if h, ok := s.cfg.Hosts[alias]; ok && len(h.Groups) > 0 {
		return h.Groups[0]
	}
	return ""
}

func stripColorTags(s string) string {
	// remove [aqua::b]...[-:-:-] style tags
	out := strings.Builder{}
	depth := 0
	for _, r := range s {
		switch {
		case r == '[':
			depth++
		case r == ']':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

func (s *uiState) addGroupPrompt() {
	s.inputPrompt("New group name:", "", func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if s.cfg.Groups == nil {
			s.cfg.Groups = map[string]config.GroupDefaults{}
		}
		if _, exists := s.cfg.Groups[name]; exists {
			s.modal(fmt.Sprintf("group %q already exists", name), nil)
			return
		}
		s.cfg.Groups[name] = config.GroupDefaults{}
		if err := config.Save(s.cfg, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), nil)
			return
		}
		s.refresh(s.currentAlias())
	})
}

func (s *uiState) renameGroupPrompt() {
	current := s.currentGroup()
	if current == "" {
		s.modal("no group selected — move cursor to a group node first", nil)
		return
	}
	s.inputPrompt(fmt.Sprintf("Rename group %q to:", current), current, func(newName string) {
		newName = strings.TrimSpace(newName)
		if newName == "" || newName == current {
			return
		}
		if _, exists := s.cfg.Groups[newName]; exists {
			s.modal(fmt.Sprintf("group %q already exists", newName), nil)
			return
		}
		if s.cfg.Groups == nil {
			s.cfg.Groups = map[string]config.GroupDefaults{}
		}
		s.cfg.Groups[newName] = s.cfg.Groups[current]
		delete(s.cfg.Groups, current)
		// Rewrite every host that referenced the old name.
		for alias, h := range s.cfg.Hosts {
			changed := false
			for i, g := range h.Groups {
				if g == current {
					h.Groups[i] = newName
					changed = true
				}
			}
			if changed {
				s.cfg.Hosts[alias] = h
			}
		}
		if err := config.Save(s.cfg, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), nil)
			return
		}
		s.refresh(s.currentAlias())
	})
}

func (s *uiState) deleteGroupPrompt() {
	current := s.currentGroup()
	if current == "" {
		s.modal("no group selected — move cursor to a group node first", nil)
		return
	}
	count := 0
	for _, h := range s.cfg.Hosts {
		for _, g := range h.Groups {
			if g == current {
				count++
				break
			}
		}
	}
	if count > 0 {
		s.modal(fmt.Sprintf("group %q has %d host(s) — remove them first", current, count), nil)
		return
	}
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Delete empty group %q?", current)).
		AddButtons([]string{"Delete", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			s.pages.RemovePage("confirm")
			if s.mode == modeTree {
				s.app.SetFocus(s.tree)
			} else {
				s.app.SetFocus(s.list)
			}
			if label != "Delete" {
				return
			}
			delete(s.cfg.Groups, current)
			if err := config.Save(s.cfg, s.configPath); err != nil {
				s.modal("save failed: "+err.Error(), nil)
				return
			}
			s.refresh("")
		})
	s.pages.AddPage("confirm", modal, true, true)
}

// openExecPrompt opens an input field for a command and chooses the scope:
//   - if any hosts are space-selected, run on those
//   - else if the cursor is on a tree group node, run on every host in
//     that group
//   - else run on the single highlighted host
// On submit the TUI exits and main re-execs `sshmgr exec --host a,b,c <cmd>`
// (or --group <g>).
// scopeSelector resolves the current selection into a fleet target: the
// multi-selected hosts, else the group node under the cursor, else the host
// under the cursor. ok is false when nothing is selectable. The args slice
// is a {--host a,b} or {--group g} pair, ready to splice into extraArgs.
func (s *uiState) scopeSelector() (label string, args []string, ok bool) {
	if len(s.multiSelected) > 0 {
		aliases := make([]string, 0, len(s.multiSelected))
		for a := range s.multiSelected {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
		return fmt.Sprintf("%d selected host(s)", len(aliases)),
			[]string{"--host", strings.Join(aliases, ",")}, true
	}
	// On a tree group node currentAlias is "" — scope to the whole group.
	alias := s.currentAlias()
	if alias == "" {
		if g := s.currentGroup(); g != "" {
			return "group " + g, []string{"--group", g}, true
		}
		return "", nil, false
	}
	return alias, []string{"--host", alias}, true
}

// execExtraArgs assembles the ActionExec extraArgs: an optional --diff, the
// {--host|--group} selector, then "--" and the command. The "--" terminator
// keeps a command that starts with a dash (e.g. "--version") from being
// parsed as an sshmgr exec flag.
func execExtraArgs(diff bool, selectorArgs []string, command string) []string {
	var args []string
	if diff {
		args = append(args, "--diff")
	}
	args = append(args, selectorArgs...)
	return append(args, "--", command)
}

func (s *uiState) openExecPrompt() {
	selectorLabel, selectorArgs, ok := s.scopeSelector()
	if !ok {
		s.modal("nothing selected — move the cursor to a host (or a group node) first, or Space to multi-select", nil)
		return
	}

	// Build the snippet list shared by every host in scope. For ActionExec
	// only snippets that ALL targets have make sense (else some hosts will
	// fail). For single-host scope it's just that host's snippets.
	targetAliases := s.execScopeAliases(selectorArgs)
	shared := s.sharedSnippets(targetAliases)

	var commands string
	form := tview.NewForm()

	// Add the textarea FIRST so the dropdown callback below can find it via
	// GetFormItemByLabel — if we added the dropdown first the lookup would
	// return nil (it walks the items added so far) and snippet picks would
	// silently fail to update the visible text.
	form.AddTextArea("commands (one per line)", "", 60, 6, 0, func(v string) { commands = v })

	driftMode := false
	form.AddCheckbox("group identical output (drift detection)", false, func(v bool) { driftMode = v })

	if len(shared) > 0 {
		opts := []string{"(none)"}
		for _, sn := range shared {
			label := sn.Name
			if sn.Description != "" {
				label += "  — " + sn.Description
			}
			opts = append(opts, label)
		}
		form.AddDropDown("snippet (optional)", opts, 0, func(_ string, i int) {
			if i <= 0 {
				return
			}
			sn := shared[i-1]
			if commands == "" {
				commands = sn.Command
			} else {
				commands = commands + "\n" + sn.Command
			}
			if ta, ok := form.GetFormItemByLabel("commands (one per line)").(*tview.TextArea); ok {
				ta.SetText(commands, true)
			}
		})
		if dd, ok := form.GetFormItemByLabel("snippet (optional)").(*tview.DropDown); ok {
			dd.SetListStyles(
				tcell.StyleDefault.Background(tcell.ColorDefault).Foreground(theme.Current.Text),
				tcell.StyleDefault.Background(theme.Current.Selection).Foreground(theme.Current.Inverse).Bold(true),
			)
		}
	}

	form.AddButton("Run", func() {
		var clean []string
		for _, l := range strings.Split(commands, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				clean = append(clean, l)
			}
		}
		if len(clean) == 0 {
			s.modal("no commands entered", func() { s.app.SetFocus(form) })
			return
		}
		// Multiple lines run as a single shell command joined with '; '. SSH
		// already wraps in `sh -c` on the remote so this is the natural way
		// to chain steps.
		s.action = ActionExec
		s.extraArgs = execExtraArgs(driftMode, selectorArgs, strings.Join(clean, "; "))
		s.pages.RemovePage("execform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("execform")
		s.focusList()
	})
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" run command on %s ", selectorLabel)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	s.pages.AddPage("execform", centered(form, 80, 16), true, true)
	s.app.SetFocus(form)
}

// execScopeAliases returns the alias list described by selectorArgs (--host
// a,b,c or --group g). Used to gather shared snippets for the exec prompt.
func (s *uiState) execScopeAliases(selectorArgs []string) []string {
	if len(selectorArgs) < 2 {
		return nil
	}
	switch selectorArgs[0] {
	case "--host":
		return strings.Split(selectorArgs[1], ",")
	case "--group":
		out := []string{}
		group := selectorArgs[1]
		for alias, h := range s.cfg.Hosts {
			for _, g := range h.Groups {
				if g == group {
					out = append(out, alias)
					break
				}
			}
		}
		return out
	}
	return nil
}

// sharedSnippets returns snippets whose Name is visible (across the file /
// group / host layers) on every alias in scope.
func (s *uiState) sharedSnippets(aliases []string) []config.Snippet {
	if len(aliases) == 0 {
		return nil
	}
	type agg struct {
		count    int
		snippet  config.Snippet
		conflict bool // same name, different command across hosts
	}
	counts := map[string]*agg{}
	for _, a := range aliases {
		for _, sn := range snippets.For(s.cfg, a) {
			if c, ok := counts[sn.Name]; ok {
				c.count++
				if c.snippet.Command != sn.Command {
					c.conflict = true
				}
			} else {
				counts[sn.Name] = &agg{count: 1, snippet: sn.Snippet}
			}
		}
	}
	// A snippet is "shared" only when every selected host has the name AND
	// the command is identical everywhere — a host- or file-level override
	// to a different command would otherwise be run fleet-wide unnoticed.
	out := []config.Snippet{}
	for _, c := range counts {
		if c.count == len(aliases) && !c.conflict {
			out = append(out, c.snippet)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sourceLabel shortens a snippet's Source for the picker. The picker is
// already scoped to one host, so "host:" collapses to "host"; group and
// file keep their name so the user knows where to edit it.
// filterStrings keeps strings that contain q (case-insensitive). Empty q
// passes everything through — used by the playbook picker's filter input.
func filterStrings(items []string, q string) []string {
	if q == "" {
		return items
	}
	needle := strings.ToLower(q)
	out := make([]string, 0, len(items))
	for _, s := range items {
		if strings.Contains(strings.ToLower(s), needle) {
			out = append(out, s)
		}
	}
	return out
}

// filterResolved keeps snippets whose name, description, command or source
// label contains q (case-insensitive). An empty q passes everything
// through — used by the snippet picker's `/`-filter mode.
func filterResolved(items []snippets.Resolved, q string) []snippets.Resolved {
	if q == "" {
		return items
	}
	needle := strings.ToLower(q)
	out := make([]snippets.Resolved, 0, len(items))
	for _, sn := range items {
		if strings.Contains(strings.ToLower(sn.Name), needle) ||
			strings.Contains(strings.ToLower(sn.Description), needle) ||
			strings.Contains(strings.ToLower(sn.Command), needle) ||
			strings.Contains(strings.ToLower(sn.Source), needle) {
			out = append(out, sn)
		}
	}
	return out
}

func sourceLabel(src string) string {
	if strings.HasPrefix(src, "host:") {
		return "host"
	}
	return src // "group:<name>" or "file:<filename>"
}

// openWatchPrompt asks for a command to watch on the host, then exits the
// TUI so main re-execs `sshmgr watch <alias> <cmd>`.
func (s *uiState) openWatchPrompt(alias string) {
	var command string
	interval := "2"
	form := tview.NewForm()
	form.AddInputField("command", "", 60, nil, func(v string) { command = v })
	form.AddInputField("interval (seconds)", "2", 6, tview.InputFieldInteger, func(v string) { interval = v })
	form.AddButton("Watch", func() {
		command = strings.TrimSpace(command)
		if command == "" {
			s.modal("command is empty", func() { s.app.SetFocus(form) })
			return
		}
		if interval == "" {
			interval = "2"
		}
		s.selected = alias
		s.action = ActionWatch
		// extraArgs = {interval, command}; main assembles the flag order.
		s.extraArgs = []string{interval, command}
		s.pages.RemovePage("watchform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("watchform")
		s.focusList()
	})
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" watch · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	s.pages.AddPage("watchform", centered(form, 74, 10), true, true)
	s.app.SetFocus(form)
}

// snippetScope picks the hosts the snippet menu runs against: any non-empty
// multi-selection wins (matching the `x` exec flow), otherwise the single
// highlighted alias. Returns the aliases (for sharedSnippets), the exec
// --host selector, and whether multi-select is active.
func (s *uiState) snippetScope(alias string) (aliases, selector []string, multi bool) {
	if len(s.multiSelected) > 0 {
		aliases = make([]string, 0, len(s.multiSelected))
		for a := range s.multiSelected {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
		return aliases, []string{"--host", strings.Join(aliases, ",")}, true
	}
	return []string{alias}, []string{"--host", alias}, false
}

// openSnippetMenu lists the snippets visible on the host across all three
// layers — file libraries, the host's groups and the host itself — each
// tagged with its source. Enter runs the highlighted snippet via
// `sshmgr exec` so the scrollable result viewer (and its back-to-UI / exit
// choice) applies. With a non-empty multi-selection the picker offers only
// the snippets every selected host shares and runs on all of them. 'a' adds
// a new host-level snippet; 'd' deletes a host-level one (group / file
// snippets show a note pointing at where they're defined) — both require
// a single-host scope. 'Esc' closes.
func (s *uiState) openSnippetMenu(alias string) {
	scopeAliases, selectorArgs, multi := s.snippetScope(alias)

	var all []snippets.Resolved
	if multi {
		for _, sn := range s.sharedSnippets(scopeAliases) {
			all = append(all, snippets.Resolved{Snippet: sn, Source: "shared"})
		}
	} else {
		all = snippets.For(s.cfg, alias)
	}

	titleScope := alias
	titleKeys := "(a=add  d=del  Enter=run  /=filter  Esc)"
	if multi {
		titleScope = fmt.Sprintf("%d selected hosts", len(scopeAliases))
		titleKeys = "(Enter=run on all  /=filter  Esc · deselect to add/del)"
	}

	list := tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" snippets · %s   %s ", titleScope, titleKeys)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	// `visible` parallels list items, indexed by row, so Enter from the
	// filter input can trigger the highlighted row's run action.
	var visible []snippets.Resolved
	rebuild := func(filter string) {
		list.Clear()
		visible = filterResolved(all, filter)
		for _, sn := range visible {
			sn := sn
			body := sn.Description
			if body == "" {
				body = sn.Command
			}
			list.AddItem(sn.Name, "["+sourceLabel(sn.Source)+"]  "+body, 0, func() {
				s.action = ActionExec
				s.extraArgs = execExtraArgs(false, selectorArgs, sn.Command)
				s.app.Stop()
			})
		}
		if list.GetItemCount() == 0 {
			msg := "(no snippets yet — press 'a' to add)"
			switch {
			case multi:
				msg = "(no snippets shared across the selection)"
			case filter != "":
				msg = fmt.Sprintf("(no match for %q)", filter)
			}
			list.AddItem(msg, "", 0, nil)
		}
	}
	rebuild("")

	filterInput := tview.NewInputField().
		SetLabel("/ ").
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.FieldText).
		SetLabelColor(theme.Current.Dim)
	filterInput.SetChangedFunc(func(text string) { rebuild(text) })

	close := func() {
		s.pages.RemovePage("snippets")
		s.focusList()
	}

	runSelected := func() {
		idx := list.GetCurrentItem()
		if idx < 0 || idx >= len(visible) {
			return
		}
		sn := visible[idx]
		s.action = ActionExec
		s.extraArgs = execExtraArgs(false, selectorArgs, sn.Command)
		s.app.Stop()
	}

	deleteSelected := func() {
		idx := list.GetCurrentItem()
		if idx < 0 || idx >= len(visible) {
			return
		}
		r := visible[idx]
		close()
		switch {
		case strings.HasPrefix(r.Source, "host:"):
			s.deleteSnippet(alias, r.Name)
		case strings.HasPrefix(r.Source, "group:"):
			s.modal(fmt.Sprintf("snippet %q is inherited from %s — edit that group's snippets list to remove it", r.Name, r.Source), nil)
		default:
			s.modal(fmt.Sprintf("snippet %q comes from a file library (%s) — edit that file to remove it", r.Name, r.Source), nil)
		}
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		switch event.Rune() {
		case '/':
			s.app.SetFocus(filterInput)
			return nil
		case 'a':
			if multi {
				s.modal("multi-select is active — Space to deselect, then 'a' to add a snippet", nil)
				return nil
			}
			close()
			s.addSnippetPrompt(alias)
			return nil
		case 'd':
			if multi {
				s.modal("multi-select is active — Space to deselect, then 'd' to delete a snippet", nil)
				return nil
			}
			deleteSelected()
			return nil
		}
		return event
	})

	// While the filter input has focus the user types into the filter;
	// Up/Down still drive the list and Enter runs the highlighted entry,
	// so the snippet picker stays usable without leaving the input field.
	filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			filterInput.SetText("")
			rebuild("")
			s.app.SetFocus(list)
			return nil
		case tcell.KeyEnter:
			runSelected()
			return nil
		case tcell.KeyUp:
			i := list.GetCurrentItem() - 1
			if i < 0 {
				i = 0
			}
			list.SetCurrentItem(i)
			return nil
		case tcell.KeyDown:
			i := list.GetCurrentItem() + 1
			if i >= list.GetItemCount() {
				i = list.GetItemCount() - 1
			}
			list.SetCurrentItem(i)
			return nil
		}
		return event
	})

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(list, 0, 1, true).
		AddItem(filterInput, 1, 0, false)
	s.pages.AddPage("snippets", centered(layout, 80, 18), true, true)
	s.app.SetFocus(list)
}

// addSnippetPrompt shows a small form to attach a new snippet to the host.
func (s *uiState) addSnippetPrompt(alias string) {
	var (
		name, cmd, desc string
	)
	form := tview.NewForm().
		AddInputField("name", "", 30, nil, func(v string) { name = strings.TrimSpace(v) }).
		AddInputField("command", "", 60, nil, func(v string) { cmd = v }).
		AddInputField("description", "", 60, nil, func(v string) { desc = v })
	form.AddButton("Save", func() {
		if name == "" || cmd == "" {
			s.modal("name and command are required", func() { s.app.SetFocus(form) })
			return
		}
		h := s.cfg.Hosts[alias]
		h.Snippets = append(h.Snippets, config.Snippet{Name: name, Command: cmd, Description: desc})
		s.cfg.Hosts[alias] = h
		if err := config.Save(s.cfg, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.pages.RemovePage("snippet-add")
		s.focusList()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("snippet-add")
		s.focusList()
	})
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" new snippet · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	s.pages.AddPage("snippet-add", centered(form, 72, 12), true, true)
	s.app.SetFocus(form)
}

func (s *uiState) deleteSnippet(alias, name string) {
	h := s.cfg.Hosts[alias]
	out := make([]config.Snippet, 0, len(h.Snippets))
	for _, sn := range h.Snippets {
		if sn.Name != name {
			out = append(out, sn)
		}
	}
	if len(out) == len(h.Snippets) {
		s.modal(fmt.Sprintf("snippet %q is inherited from a group — edit the group's snippets list to remove it", name), nil)
		return
	}
	h.Snippets = out
	s.cfg.Hosts[alias] = h
	if err := config.Save(s.cfg, s.configPath); err != nil {
		s.modal("save failed: "+err.Error(), nil)
	}
}

// openPlaybookForm starts the two-step Ansible-playbook launcher: a
// filterable picker for the playbook (step 1), then a small form for
// check / diff / extra-vars (step 2). The target follows the same rule as
// exec — multi-select, else the group node, else the host under the
// cursor. On Run the TUI exits and main re-execs `sshmgr playbook …`.
func (s *uiState) openPlaybookForm() {
	label, selectorArgs, ok := s.scopeSelector()
	if !ok {
		s.modal("nothing selected — move the cursor to a host (or a group node) first, or Space to multi-select", nil)
		return
	}
	dir := s.cfg.ResolvePlaybooksDir()
	books, err := ansible.DiscoverPlaybooks(dir)
	if err != nil {
		s.modal("cannot read playbooks dir: "+err.Error(), nil)
		return
	}
	if len(books) == 0 {
		s.modal(fmt.Sprintf("no playbooks (*.yml / *.yaml) in %s\nset playbooks_dir in the config or add files there", dir), nil)
		return
	}
	s.openPlaybookPicker(label, selectorArgs, books)
}

// openPlaybookPicker shows the filterable playbook list. Mirrors the
// snippet picker: `/` focuses the filter, Up/Down still drive the list and
// Enter from the filter runs the highlighted entry, Esc clears the filter
// (or closes the picker when focus is on the list).
func (s *uiState) openPlaybookPicker(label string, selectorArgs, books []string) {
	list := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" pick a playbook · %s   (Enter=continue  /=filter  Esc=close) ", label)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	var visible []string
	rebuild := func(filter string) {
		list.Clear()
		visible = filterStrings(books, filter)
		for _, b := range visible {
			b := b
			list.AddItem(b, "", 0, func() {
				s.pages.RemovePage("playbookpicker")
				s.openPlaybookOptions(label, selectorArgs, books, b)
			})
		}
		if list.GetItemCount() == 0 {
			list.AddItem(fmt.Sprintf("(no playbook matching %q)", filter), "", 0, nil)
		}
	}
	rebuild("")

	filterInput := tview.NewInputField().
		SetLabel("/ ").
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.FieldText).
		SetLabelColor(theme.Current.Dim)
	filterInput.SetChangedFunc(func(text string) { rebuild(text) })

	close := func() {
		s.pages.RemovePage("playbookpicker")
		s.focusList()
	}
	runSelected := func() {
		idx := list.GetCurrentItem()
		if idx < 0 || idx >= len(visible) {
			return
		}
		picked := visible[idx]
		s.pages.RemovePage("playbookpicker")
		s.openPlaybookOptions(label, selectorArgs, books, picked)
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		if event.Rune() == '/' {
			s.app.SetFocus(filterInput)
			return nil
		}
		return event
	})
	filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			filterInput.SetText("")
			rebuild("")
			s.app.SetFocus(list)
			return nil
		case tcell.KeyEnter:
			runSelected()
			return nil
		case tcell.KeyUp:
			i := list.GetCurrentItem() - 1
			if i < 0 {
				i = 0
			}
			list.SetCurrentItem(i)
			return nil
		case tcell.KeyDown:
			i := list.GetCurrentItem() + 1
			if i >= list.GetItemCount() {
				i = list.GetItemCount() - 1
			}
			list.SetCurrentItem(i)
			return nil
		}
		return event
	})

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(list, 0, 1, true).
		AddItem(filterInput, 1, 0, false)
	s.pages.AddPage("playbookpicker", centered(layout, 80, 18), true, true)
	s.app.SetFocus(list)
}

// openPlaybookOptions is step 2 of the playbook launcher: a small form
// for check / diff / extra-vars + Run / Cancel. Esc returns to the picker
// so the user can change their mind without leaving the manager flow.
func (s *uiState) openPlaybookOptions(label string, selectorArgs, books []string, playbook string) {
	var (
		check     bool
		diff      bool
		extraVars string
	)
	form := tview.NewForm()
	form.AddCheckbox("check mode (--check)", false, func(v bool) { check = v })
	form.AddCheckbox("show diffs (--diff)", false, func(v bool) { diff = v })
	form.AddInputField("extra-vars", "", 50, nil, func(v string) { extraVars = v })

	form.AddButton("Run", func() {
		s.action = ActionPlaybook
		s.extraArgs = playbookExtraArgs(playbook, selectorArgs, check, diff, extraVars)
		s.pages.RemovePage("playbookform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("playbookform")
		s.focusList()
	})
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" ansible-playbook · %s · %s ", playbook, label)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			s.pages.RemovePage("playbookform")
			s.openPlaybookPicker(label, selectorArgs, books)
			return nil
		}
		return event
	})

	s.pages.AddPage("playbookform", centered(form, 76, 12), true, true)
	s.app.SetFocus(form)
}

// playbookExtraArgs assembles the ActionPlaybook extraArgs: the playbook
// name, the {--host|--group} selector, then the optional flags.
func playbookExtraArgs(playbook string, selectorArgs []string, check, diff bool, extraVars string) []string {
	args := append([]string{playbook}, selectorArgs...)
	if check {
		args = append(args, "--check")
	}
	if diff {
		args = append(args, "--diff")
	}
	if ev := strings.TrimSpace(extraVars); ev != "" {
		args = append(args, "--extra-vars", ev)
	}
	return args
}

// openForwardMenu shows a forward-manager menu for the host: a "new
// forward" entry that opens the existing setup form, plus inline rows for
// every saved profile matching this alias, every recent run from history,
// and every currently-active tunnel (informational — selecting an active
// row is a no-op). Selecting a saved or recent entry runs it via the same
// re-exec path as the form.
func (s *uiState) openForwardMenu(alias string) {
	list := tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(theme.Current.Text).
		SetSecondaryTextColor(theme.Current.Dim).
		SetSelectedTextColor(theme.Current.Inverse).
		SetSelectedBackgroundColor(theme.Current.Selection)
	list.SetBorder(true).
		SetTitle(fmt.Sprintf(" forwards · %s   (Enter=run  Esc=close) ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	close := func() {
		s.pages.RemovePage("forwardmenu")
		s.focusList()
	}

	runProfile := func(typ, spec, targetAlias string) {
		s.action = ActionForward
		s.extraArgs = []string{"-" + typ, spec}
		s.selected = targetAlias
		close()
		s.app.Stop()
	}

	list.AddItem("new forward", "open the setup form for a fresh forward", 0, func() {
		close()
		s.openForwardForm(alias)
	})

	for _, p := range forwards.ForAlias(s.cfg, alias) {
		p := p
		desc := p.Description
		sourceTag := p.Source
		if desc == "" {
			desc = sourceTag
		} else {
			desc = desc + "  ·  " + sourceTag
		}
		list.AddItem(
			fmt.Sprintf("[saved]   %s   -%s %s", p.Name, p.Type, p.Spec),
			desc, 0,
			func() { runProfile(p.Type, p.Spec, p.Alias) },
		)
	}

	for _, e := range s.cfg.ForwardHistory {
		if e.Alias != alias {
			continue
		}
		e := e
		sec := "last used " + e.LastUsed
		list.AddItem(
			fmt.Sprintf("[recent]  -%s %s", e.Type, e.Spec),
			sec, 0,
			func() { runProfile(e.Type, e.Spec, alias) },
		)
	}

	active, _ := fwdregistry.List()
	for _, e := range active {
		if e.Alias != alias {
			continue
		}
		e := e
		age := time.Since(e.StartedAt).Round(time.Second)
		list.AddItem(
			fmt.Sprintf("[active]  -%s %s   pid %d   age %s", e.Type, e.Spec, e.PID, age),
			e.Source+"  ·  "+e.Backend,
			0,
			// Enter on an active row asks to stop it rather than relaunching
			// it (which would race the live tunnel and double-bind). After
			// the confirm flow we reopen the forward menu so the user keeps
			// the manager context.
			func() {
				close()
				s.confirmKillForward(alias, e, func() { s.openForwardMenu(alias) })
			},
		)
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		return event
	})

	s.pages.AddPage("forwardmenu", centered(list, 80, 16), true, true)
	s.app.SetFocus(list)
}

// openForwardForm shows a port-forward setup dialog: type dropdown,
// spec field (with format hint), and a recent-history dropdown filtered to
// the current alias. On Save, sets state.action=ActionForward + extraArgs and
// stops the app so main can re-exec `sshmgr fwd <alias> -L/-R/-D <spec>`.
func (s *uiState) openForwardForm(alias string) {
	fwdTypes := []string{"L (local listen, dial remote)", "R (remote listen, dial local)", "D (SOCKS5 proxy)"}
	flags := []string{"-L", "-R", "-D"}
	typeIdx := 0
	spec := ""

	// Build the history dropdown options, most recent first, for this alias.
	histOpts := []string{"(new entry)"}
	histRefs := []config.ForwardEntry{{}}
	for _, h := range s.cfg.ForwardHistory {
		if h.Alias != alias {
			continue
		}
		histOpts = append(histOpts, fmt.Sprintf("-%s %s", h.Type, h.Spec))
		histRefs = append(histRefs, h)
	}

	form := tview.NewForm()
	specField := tview.NewInputField().SetLabel("spec ").SetFieldWidth(40)
	specField.SetChangedFunc(func(t string) { spec = strings.TrimSpace(t) })

	// Style for the expanded options list inside DropDown — without this the
	// popup uses tview's defaults and ignores our theme.
	listUnsel := tcell.StyleDefault.
		Background(tcell.ColorDefault).
		Foreground(theme.Current.Text)
	listSel := tcell.StyleDefault.
		Background(theme.Current.Selection).
		Foreground(theme.Current.Inverse).
		Bold(true)

	form.AddDropDown("type", fwdTypes, 0, func(_ string, i int) { typeIdx = i; updateSpecPlaceholder(specField, flags[i]) })
	form.AddDropDown("from history", histOpts, 0, func(_ string, i int) {
		if i == 0 {
			return
		}
		h := histRefs[i]
		for j, f := range flags {
			if strings.TrimPrefix(f, "-") == h.Type {
				typeIdx = j
				break
			}
		}
		// Reflect into the type dropdown widget.
		if dd, ok := form.GetFormItemByLabel("type").(*tview.DropDown); ok {
			dd.SetCurrentOption(typeIdx)
		}
		specField.SetText(h.Spec)
		spec = h.Spec
	})
	form.AddFormItem(specField)
	updateSpecPlaceholder(specField, "-L")

	if dd, ok := form.GetFormItemByLabel("type").(*tview.DropDown); ok {
		dd.SetListStyles(listUnsel, listSel)
	}
	if dd, ok := form.GetFormItemByLabel("from history").(*tview.DropDown); ok {
		dd.SetListStyles(listUnsel, listSel)
	}

	form.AddButton("Run", func() {
		if spec == "" {
			s.modal("spec is empty", func() { s.app.SetFocus(form) })
			return
		}
		s.selected = alias
		s.action = ActionForward
		s.extraArgs = []string{flags[typeIdx], spec}
		s.pages.RemovePage("fwdform")
		s.app.Stop()
	})
	form.AddButton("Cancel", func() {
		s.pages.RemovePage("fwdform")
		if s.mode == modeTree {
			s.app.SetFocus(s.tree)
		} else {
			s.app.SetFocus(s.list)
		}
	})
	form.
		SetLabelColor(theme.Current.Primary).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" port forward · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary)

	s.pages.AddPage("fwdform", centered(form, 72, 14), true, true)
	s.app.SetFocus(form)
}

func updateSpecPlaceholder(f *tview.InputField, flag string) {
	switch flag {
	case "-L":
		f.SetPlaceholder("port:host:port  or  bind:port:host:port")
	case "-R":
		f.SetPlaceholder("remotePort:localHost:localPort")
	case "-D":
		f.SetPlaceholder("port  (SOCKS5 bind)")
	}
}

// inputPrompt shows a simple "label + InputField + OK/Cancel" modal that
// invokes onSubmit with the entered text on OK.
func (s *uiState) inputPrompt(label, def string, onSubmit func(string)) {
	input := tview.NewInputField().
		SetLabel(label + " ").
		SetText(def).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetLabelColor(theme.Current.Primary)
	form := tview.NewForm().
		AddFormItem(input).
		AddButton("OK", func() {
			s.pages.RemovePage("input")
			if s.mode == modeTree {
				s.app.SetFocus(s.tree)
			} else {
				s.app.SetFocus(s.list)
			}
			onSubmit(input.GetText())
		}).
		AddButton("Cancel", func() {
			s.pages.RemovePage("input")
			if s.mode == modeTree {
				s.app.SetFocus(s.tree)
			} else {
				s.app.SetFocus(s.list)
			}
		}).
		SetButtonBackgroundColor(theme.Current.Primary).
		SetButtonTextColor(theme.Current.Inverse)
	form.SetBorder(true).SetBorderColor(theme.Current.Primary).SetTitle(" " + label + " ").SetTitleColor(theme.Current.Primary)
	s.pages.AddPage("input", centered(form, 60, 7), true, true)
	s.app.SetFocus(input)
}

// showHelpOverlay pops a scrollable modal with the full keymap (`?` key).
func (s *uiState) showHelpOverlay() {
	tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	tv.SetText(fullHelpText())
	tv.SetBorder(true).
		SetTitle(" keys — Esc to close ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)
	closeOverlay := func() {
		s.pages.RemovePage("help-overlay")
		s.focusList()
	}
	tv.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEsc || e.Rune() == 'q' || e.Rune() == '?' {
			closeOverlay()
			return nil
		}
		switch e.Rune() {
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		}
		return e
	})
	s.pages.AddPage("help-overlay", centered(tv, 62, 30), true, true)
	s.app.SetFocus(tv)
}

// showResolvedConfig pops a modal tracing where each inherited field of the
// host comes from — the host itself or a specific group (`i` key).
func (s *uiState) showResolvedConfig(alias string) {
	fields, ok := s.cfg.ResolveTrace(alias)
	if !ok {
		return
	}
	prim := theme.Current.PrimaryTag()
	dim := theme.Current.DimTag()
	acc := theme.Current.AccentBTag()
	var b strings.Builder
	fmt.Fprintf(&b, "[%s::b]%s[-:-:-]  %sresolved config[-]\n\n",
		theme.ColorTag(theme.Current.Primary), alias, dim)
	if raw, okk := s.cfg.Hosts[alias]; okk && len(raw.Groups) > 0 {
		fmt.Fprintf(&b, "  %sgroups[-]  %s\n\n", prim, strings.Join(raw.Groups, ", "))
	}
	if len(fields) == 0 {
		b.WriteString("  " + dim + "(no inheritable fields are set)[-]\n")
	}
	for _, f := range fields {
		srcTag := acc // a group-inherited value stands out
		if f.Source == "host" {
			srcTag = dim
		}
		fmt.Fprintf(&b, "  %s%-15s[-] %s   %s<- %s[-]\n", prim, f.Name, f.Value, srcTag, f.Source)
	}

	tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	tv.SetText(b.String())
	tv.SetBorder(true).
		SetTitle(" resolved config — Esc to close ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Primary).
		SetTitleColor(theme.Current.Primary).
		SetBorderPadding(0, 0, 1, 1)
	closeOverlay := func() {
		s.pages.RemovePage("resolved")
		s.focusList()
	}
	tv.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEsc || e.Rune() == 'q' || e.Rune() == 'i' {
			closeOverlay()
			return nil
		}
		switch e.Rune() {
		case 'j':
			return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
		case 'k':
			return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
		}
		return e
	})
	s.pages.AddPage("resolved", centered(tv, 64, 20), true, true)
	s.app.SetFocus(tv)
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// killActiveForHost handles the host-list 'K' shortcut: confirm-stop when
// alias has exactly one live tunnel, hint at the p-menu when it has more,
// and say so plainly when it has none.
func (s *uiState) killActiveForHost(alias string) {
	all, _ := fwdregistry.List()
	var live []fwdregistry.Entry
	for _, e := range all {
		if e.Alias == alias {
			live = append(live, e)
		}
	}
	switch len(live) {
	case 0:
		s.modal(fmt.Sprintf("no active forwards on %s", alias), nil)
	case 1:
		// K is launched from the host list — nil onClose so the user lands
		// back on the host list instead of being dropped into the p-menu
		// they didn't open.
		s.confirmKillForward(alias, live[0], nil)
	default:
		s.modal(fmt.Sprintf("%s has %d active forwards — open the menu with `p` and Enter on the one to stop", alias, len(live)), nil)
	}
}

// confirmKillForward asks the user to confirm stopping a live tunnel. On
// Stop it sends SIGTERM (escalating to SIGKILL after a brief grace).
// onClose runs after every exit path (Cancel, Stop+success, Stop+error)
// so callers control where the user lands — the p-menu flow reopens the
// menu, the host-list `K` flow returns straight to the host list.
func (s *uiState) confirmKillForward(alias string, e fwdregistry.Entry, onClose func()) {
	afterClose := func() {
		if onClose != nil {
			onClose()
		} else {
			s.focusList()
		}
	}
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Stop forward -%s %s on %s (pid %d)?", e.Type, e.Spec, e.Alias, e.PID)).
		AddButtons([]string{"Stop", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			s.pages.RemovePage("killconfirm")
			if label != "Stop" {
				afterClose()
				return
			}
			if err := fwdregistry.Kill(e, 2*time.Second); err != nil {
				s.modal("kill failed: "+err.Error(), afterClose)
				return
			}
			s.modal(fmt.Sprintf("stopped -%s %s (pid %d)", e.Type, e.Spec, e.PID), afterClose)
		})
	s.pages.AddPage("killconfirm", modal, true, true)
}

func (s *uiState) confirmDelete(alias string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Delete host %q?", alias)).
		AddButtons([]string{"Delete", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			s.pages.RemovePage("confirm")
			if s.mode == modeTree {
				s.app.SetFocus(s.tree)
			} else {
				s.app.SetFocus(s.list)
			}
			if label != "Delete" {
				return
			}
			delete(s.cfg.Hosts, alias)
			delete(s.multiSelected, alias)
			if err := config.Save(s.cfg, s.configPath); err != nil {
				s.modal("save failed: "+err.Error(), nil)
				return
			}
			s.refresh("")
		})
	s.pages.AddPage("confirm", modal, true, true)
}

func (s *uiState) modal(text string, onClose func()) {
	m := tview.NewModal().
		SetText(text).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			s.pages.RemovePage("info")
			if onClose != nil {
				onClose()
			} else {
				s.focusList()
			}
		})
	s.pages.AddPage("info", m, true, true)
}

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
