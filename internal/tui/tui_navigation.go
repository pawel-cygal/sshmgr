package tui

import (
	"fmt"
	"sort"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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
		strings.Join(h.Tags, " ") + " " + strings.Join(h.Groups, " ") + " " + badgeTokens(h))
	return strings.Contains(hay, query)
}

// badgeTokens returns the badge keywords for a resolved host so the filter can
// match them as plain text (e.g. typing "kvm" or "duo" finds the badged hosts).
// Derived from the badge renderer itself so the two never drift — any badge
// hostBadges shows is automatically filterable.
func badgeTokens(h config.HostConfig) string {
	return stripColorTags(hostBadges(h))
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
