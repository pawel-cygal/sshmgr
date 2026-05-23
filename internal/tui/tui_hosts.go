package tui

import (
	"fmt"
	"strconv"
	"strings"

	"sshmgr/internal/config"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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

