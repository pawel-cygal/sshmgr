package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/fwdregistry"
	"github.com/systeampl/sshmgr/internal/theme"

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
	if h.KVM != nil && h.KVM.Host != "" {
		chips = append(chips, chip("KVM", theme.Current.AccentB))
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

// section writes a rule line and a section heading. Sections are the only
// structure in the panel, so an empty one must never be emitted — callers
// check their content first.
func section(b *strings.Builder, title string, width int) {
	dim := theme.Current.DimTag()
	prim := theme.Current.PrimaryTag()
	fmt.Fprintf(b, "\n%s%s[-]\n", dim, strings.Repeat("─", width))
	fmt.Fprintf(b, "%s%s[-]\n", prim, title)
}

// connectionString renders the host in the form a person would type it.
func connectionString(h config.HostConfig) string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	if h.User == "" {
		return fmt.Sprintf("%s:%d", h.Host, port)
	}
	return fmt.Sprintf("%s@%s:%d", h.User, h.Host, port)
}

func (s *uiState) showDetails(alias string) {
	// s.details is nil in tests that build a uiState without the full widget
	// tree (newTestState only builds the host list). Guard rather than
	// require every such test to populate an unrelated widget.
	if s.details == nil {
		return
	}
	if alias == "" {
		s.details.SetText("")
		return
	}
	s.details.SetText(detailsText(s, alias))
}

// detailsText renders the details panel body. Split out from showDetails so
// the rendering can be tested without instantiating a widget.
func detailsText(s *uiState, alias string) string {
	h, _ := s.cfg.ResolveHost(alias)
	dim := theme.Current.DimTag()
	warn := theme.Current.WarningTag()
	accent := theme.Current.AccentBTag()
	ok := theme.Current.SuccessTag()
	const ruleWidth = 36

	var b strings.Builder

	header := alias
	if h.Pinned {
		header = "★ " + alias
	}
	fmt.Fprintf(&b, "[%s::b]%s[-:-:-]\n", theme.ColorTag(theme.Current.Primary), header)

	// status line: backend and badges, the two things worth knowing first
	if h.External {
		fmt.Fprintf(&b, "%sexternal[-]  %ssystem ssh / scp / sftp[-]\n", warn, dim)
	} else {
		fmt.Fprintf(&b, "%snative[-]  %sGo SSH[-]\n", ok, dim)
	}
	if badges := hostBadges(h); badges != "" {
		b.WriteString(badges + "\n")
	}

	// s.pings is nil in tests that build a uiState literal without it (see the
	// s.details guard above for the same pattern) -- skip the section rather
	// than require every such test to populate an unrelated pinger.
	if s.pings != nil {
		if hist := s.pings.History(alias); len(hist) > 0 {
			spark, pct := availabilityLine(hist)
			section(&b, "AVAILABILITY", ruleWidth)
			colour := ok
			switch {
			case pct < 70:
				colour = theme.Current.ErrorTag()
			case pct < 100:
				colour = warn
			}
			fmt.Fprintf(&b, "  %s%s[-]  %s%d%%[-]  %s%d rounds[-]\n",
				colour, spark, colour, pct, dim, len(hist))
		}
	}

	section(&b, "CONNECTION", ruleWidth)
	fmt.Fprintf(&b, "  %s\n", connectionString(h))
	if h.Key != "" {
		fmt.Fprintf(&b, "  %s%s[-]\n", dim, h.Key)
	}
	fmt.Fprintf(&b, "  %sauto_duo_push[-] %t\n", dim, h.AutoDuoPush)
	if h.ProxyJump != "" {
		fmt.Fprintf(&b, "  %sjump[-] %s%s[-]\n", dim, accent, h.ProxyJump)
	}
	if h.ProxyCommand != "" {
		fmt.Fprintf(&b, "  %sproxy[-] %s%s[-]\n", dim, accent, h.ProxyCommand)
	}
	if h.Become.User != "" {
		method := h.Become.Method
		if method == "" {
			method = "sudo"
		}
		fmt.Fprintf(&b, "  %sbecome[-] %s -> %s\n", dim, method, h.Become.User)
	}
	if h.AutoAcceptHostKey {
		fmt.Fprintf(&b, "  %sauto_accept_host_key[-]\n", dim)
	}

	if len(h.Groups) > 0 || len(h.Tags) > 0 {
		section(&b, "MEMBERSHIP", ruleWidth)
		if len(h.Groups) > 0 {
			fmt.Fprintf(&b, "  %s\n", strings.Join(h.Groups, ", "))
		}
		if len(h.Tags) > 0 {
			fmt.Fprintf(&b, "  %s#%s[-]\n", dim, strings.Join(h.Tags, " #"))
		}
	}

	if len(h.LoginSteps) > 0 {
		section(&b, "LOGIN STEPS", ruleWidth)
		fmt.Fprintf(&b, "  %s%s[-]\n", dim, escalateHint(h))
		for i, st := range h.LoginSteps {
			fmt.Fprintf(&b, "  %s%d.[-] %s  %s(expect: %q  pass: %s)[-]\n",
				accent, i+1, st.Command, dim, st.Expect, stepPasswordSource(st))
		}
	}

	if h.KVM != nil && h.KVM.Host != "" {
		section(&b, "KVM", ruleWidth)
		kvmHost := h.KVM.ResolvedHost(map[string]string{
			"alias": alias, "host": h.Host, "user": h.User,
			"port": strconv.Itoa(h.Port),
		})
		typ := h.KVM.Type
		if typ == "" {
			typ = "nanokvm"
		}
		fmt.Fprintf(&b, "  %s%s[-]  %s(%s)[-]\n", accent, kvmHost, dim, typ)
	}

	if len(h.Commands) > 0 {
		section(&b, "COMMANDS", ruleWidth)
		for _, c := range h.Commands {
			fmt.Fprintf(&b, "  %s-[-] %s\n", dim, c)
		}
	}

	active, _ := fwdregistry.List()
	var hostActive []fwdregistry.Entry
	for _, e := range active {
		if e.Alias == alias {
			hostActive = append(hostActive, e)
		}
	}
	if len(hostActive) > 0 {
		section(&b, "ACTIVE FORWARDS", ruleWidth)
		for _, e := range hostActive {
			age := time.Since(e.StartedAt).Round(time.Second)
			fmt.Fprintf(&b, "  %s-%s %s[-]\n", accent, e.Type, e.Spec)
			fmt.Fprintf(&b, "    %spid %d · age %s · %s · %s[-]\n",
				dim, e.PID, age, e.Source, e.Backend)
		}
	}

	if e, ok2 := s.lastLogin(alias); ok2 {
		fmt.Fprintf(&b, "\n%slast %s  %s[-]\n", dim, e.Action, e.When)
	}

	hk := theme.Current.HelpKeyTag()
	section(&b, "ACTIONS", ruleWidth)
	fmt.Fprintf(&b, "  %si[-] inspect config   %s*[-] pin / unpin\n", hk, hk)
	if h.KVM != nil && h.KVM.Host != "" {
		fmt.Fprintf(&b, "  %sV[-] kvm power menu\n", hk)
	}
	if len(hostActive) > 0 {
		suffix := "stop active forward"
		if len(hostActive) > 1 {
			suffix = fmt.Sprintf("stop active forward (1 of %d — pick in `p` for the rest)",
				len(hostActive))
		}
		fmt.Fprintf(&b, "  %sK[-] %s\n", hk, suffix)
	}
	return b.String()
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

// stepPasswordSource names the backend a login step's response comes from, in
// the same precedence order secret.Resolve tries them — so the pane cannot show
// a source the chain would not actually use.
func stepPasswordSource(st config.LoginStep) string {
	switch {
	case st.Expect == "":
		return "none needed"
	case st.Response != "":
		return "<literal>"
	case st.PasswordEnv != "":
		return "env:" + st.PasswordEnv
	case st.PasswordKeyring != "":
		return "keyring:" + st.PasswordKeyring
	case st.PasswordCmd != "":
		return "cmd"
	case st.PasswordPrompt:
		return "prompt"
	default:
		return "unset"
	}
}

// escalateHint spells out, next to the login_steps summary, how the chain is
// actually triggered for this host — the in-session hotkey is otherwise
// invisible from the TUI, which is exactly where people look for it.
func escalateHint(h config.HostConfig) string {
	key := h.EscalateKey
	if key == "" {
		key = "~"
	}
	hotkey := key + "r"
	if h.LoginStepsAuto != nil && !*h.LoginStepsAuto {
		return "(manual — press " + hotkey + " in the session)"
	}
	return "(auto at connect; " + hotkey + " re-runs it)"
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
