package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/fwdregistry"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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
