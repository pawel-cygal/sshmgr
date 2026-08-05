package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/forwards"
	"github.com/systeampl/sshmgr/internal/theme"

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
	kvmEnabled := h.KVM != nil
	var kvmHost, kvmScheme, kvmUser, kvmKeyring string
	if h.KVM != nil {
		kvmHost = h.KVM.Host
		kvmScheme = h.KVM.Scheme
		kvmUser = h.KVM.User
		kvmKeyring = h.KVM.PasswordKeyring
	}

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
	form.AddCheckbox("kvm configured", kvmEnabled, func(v bool) { kvmEnabled = v })
	form.AddInputField("kvm host (ip/name)", kvmHost, 40, nil, func(v string) { kvmHost = strings.TrimSpace(v) })
	form.AddInputField("kvm scheme (http/https)", kvmScheme, 12, nil, func(v string) { kvmScheme = strings.TrimSpace(v) })
	form.AddInputField("kvm user", kvmUser, 20, nil, func(v string) { kvmUser = strings.TrimSpace(v) })
	form.AddInputField("kvm password_keyring", kvmKeyring, 30, nil, func(v string) { kvmKeyring = strings.TrimSpace(v) })

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
		if port < 1 || port > 65535 {
			s.modal("port must be in range 1..65535", func() { s.app.SetFocus(form) })
			return
		}
		if _, exists := s.cfg.Hosts[alias]; exists && alias != originalAlias {
			s.modal(fmt.Sprintf("alias %q already exists", alias), func() { s.app.SetFocus(form) })
			return
		}

		// Patch the existing raw host instead of rebuilding HostConfig. Rebuilding
		// silently dropped every field the compact form does not expose (secret
		// backends, login_steps, X11, agent forwarding, timeouts, snippets, etc.).
		newHost := h
		newHost.Host = host
		newHost.Port = port
		newHost.User = usr
		newHost.Key = key
		newHost.SetAutoDuoPush(autoDuo)
		newHost.SetAutoAcceptHostKey(autoHostKey)
		newHost.External = external
		newHost.Pinned = pinned
		newHost.ProxyJump = proxyJump
		newHost.ProxyCommand = strings.TrimSpace(proxyCommand)
		newHost.Groups = splitCSV(groups)
		newHost.Tags = splitCSV(tags)
		newHost.Commands = splitCommands(commands)
		if becomeUser != "" {
			newHost.Become = config.BecomeConfig{Method: becomeMethod, User: becomeUser}
		} else {
			newHost.Become = config.BecomeConfig{}
		}
		if kvmEnabled {
			kvm := config.KVMConfig{}
			if h.KVM != nil {
				kvm = *h.KVM
			}
			kvm.Host = kvmHost
			kvm.Scheme = kvmScheme
			kvm.User = kvmUser
			kvm.PasswordKeyring = kvmKeyring
			newHost.KVM = &kvm
		} else {
			newHost.KVM = nil
		}

		// Build and persist a copy first. A failed CAS/save leaves the live TUI
		// state untouched instead of half-applying a rename.
		next := s.cfg.Clone()
		if originalAlias != "" && alias != originalAlias {
			if refs := forwards.FileAliasReferences(s.cfg, originalAlias); len(refs) > 0 {
				s.modal(fmt.Sprintf("cannot rename %q; file libraries still reference it: %s", originalAlias, strings.Join(refs, ", ")), func() { s.app.SetFocus(form) })
				return
			}
			delete(next.Hosts, originalAlias)
			for name, other := range next.Hosts {
				other.ProxyJump = renameJumpAlias(other.ProxyJump, originalAlias, alias)
				other.ProxyCommand = config.RenameSSHJumpAlias(other.ProxyCommand, originalAlias, alias)
				next.Hosts[name] = other
			}
			for name, profile := range next.Forwards {
				if profile.Alias == originalAlias {
					profile.Alias = alias
					next.Forwards[name] = profile
				}
			}
			for name, defaults := range next.Groups {
				defaults.ProxyJump = renameJumpAlias(defaults.ProxyJump, originalAlias, alias)
				defaults.ProxyCommand = config.RenameSSHJumpAlias(defaults.ProxyCommand, originalAlias, alias)
				next.Groups[name] = defaults
			}
			newHost.ProxyJump = renameJumpAlias(newHost.ProxyJump, originalAlias, alias)
			newHost.ProxyCommand = config.RenameSSHJumpAlias(newHost.ProxyCommand, originalAlias, alias)
		}
		next.Hosts[alias] = newHost
		if err := config.Save(next, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), func() { s.app.SetFocus(form) })
			return
		}
		s.cfg = next
		if originalAlias != "" && alias != originalAlias && s.multiSelected[originalAlias] {
			delete(s.multiSelected, originalAlias)
			s.multiSelected[alias] = true
		}
		closeForm()
		s.refresh(alias)
	})
	form.AddButton("Cancel", closeForm)

	form.SetCancelFunc(closeForm)

	s.pages.AddPage("form", centered(form, 76, 32), true, true)
	s.app.SetFocus(form)
}

func renameJumpAlias(chain, oldAlias, newAlias string) string {
	parts := strings.Split(chain, ",")
	for i := range parts {
		if strings.TrimSpace(parts[i]) == oldAlias {
			parts[i] = newAlias
		}
	}
	return strings.Join(parts, ",")
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
		if _, exists := s.cfg.Groups[name]; exists {
			s.modal(fmt.Sprintf("group %q already exists", name), nil)
			return
		}
		next := s.cfg.Clone()
		next.Groups[name] = config.GroupDefaults{}
		if err := config.Save(next, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), nil)
			return
		}
		s.cfg = next
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
		next := s.cfg.Clone()
		next.Groups[newName] = next.Groups[current]
		delete(next.Groups, current)
		// Rewrite every host that referenced the old name.
		for alias, h := range next.Hosts {
			changed := false
			for i, g := range h.Groups {
				if g == current {
					h.Groups[i] = newName
					changed = true
				}
			}
			if changed {
				next.Hosts[alias] = h
			}
		}
		if err := config.Save(next, s.configPath); err != nil {
			s.modal("save failed: "+err.Error(), nil)
			return
		}
		s.cfg = next
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
			next := s.cfg.Clone()
			delete(next.Groups, current)
			if err := config.Save(next, s.configPath); err != nil {
				s.modal("save failed: "+err.Error(), nil)
				return
			}
			s.cfg = next
			s.refresh("")
		})
	s.pages.AddPage("confirm", modal, true, true)
}

// openExecPrompt opens an input field for a command and chooses the scope:
//   - if any hosts are space-selected, run on those
//   - else if the cursor is on a tree group node, run on every host in
//     that group
//   - else run on the single highlighted host
//
// On submit the TUI exits and main re-execs `sshmgr exec --host a,b,c <cmd>`
// (or --group <g>).
// scopeSelector resolves the current selection into a fleet target: the
// multi-selected hosts, else the group node under the cursor, else the host
// under the cursor. ok is false when nothing is selectable. The args slice
// is a {--host a,b} or {--group g} pair, ready to splice into extraArgs.
func (s *uiState) confirmDelete(alias string) {
	refs := append(s.cfg.AliasReferences(alias), forwards.FileAliasReferences(s.cfg, alias)...)
	if len(refs) > 0 {
		s.modal(fmt.Sprintf("cannot delete %q; still referenced by: %s", alias, strings.Join(refs, ", ")), nil)
		return
	}
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
			next := s.cfg.Clone()
			delete(next.Hosts, alias)
			if err := config.Save(next, s.configPath); err != nil {
				s.modal("save failed: "+err.Error(), nil)
				return
			}
			s.cfg = next
			delete(s.multiSelected, alias)
			s.refresh("")
		})
	s.pages.AddPage("confirm", modal, true, true)
}
