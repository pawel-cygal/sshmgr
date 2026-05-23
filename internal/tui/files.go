package tui

import (
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"sshmgr/internal/config"
	"sshmgr/internal/theme"
	"sshmgr/internal/transfer"

	"github.com/gdamore/tcell/v2"
	"github.com/pkg/sftp"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
)

// RunFiles launches the two-pane file manager for an open SSH client.
// Returns when the user quits (Esc/q/F10). Local CWD starts at the OS process
// cwd; remote CWD starts at the SFTP server's reported home directory.
func RunFiles(client *ssh.Client, alias string) error {
	applyTheme(nil) // theme already chosen by main; this pushes it into tview.Styles

	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp not available on %s (%w)\n  this typically means the SSH server doesn't expose the sftp-server subsystem.\n  - QNAP: enable 'Allow SFTP connections' in Control Panel > Network Services > SSH\n  - Cisco/HP switches: not supported (no sftp-server)\n  Try `sshmgr <alias>` for a regular shell instead", alias, err)
	}
	defer sc.Close()

	remoteCwd, err := sc.Getwd()
	if err != nil || remoteCwd == "" {
		remoteCwd = "/"
	}
	localCwd, err := os.Getwd()
	if err != nil {
		localCwd = "/"
	}

	app := tview.NewApplication()

	fm := &fileManager{
		app:       app,
		sc:        sc,
		alias:     alias,
		localCwd:  localCwd,
		remoteCwd: remoteCwd,
	}
	fm.local = newPanel("local")
	fm.remote = newPanel(alias)

	fm.help = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	fm.help.SetText(fileHelpText())

	fm.history = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	fm.history.SetBorder(true).
		SetTitle(fmt.Sprintf(" transfers · %s ", alias)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(theme.Current.Dim).
		SetTitleColor(theme.Current.Primary)
	fm.refreshHistory()

	fm.pages = tview.NewPages()
	body := tview.NewFlex().
		AddItem(fm.local.frame, 0, 1, true).
		AddItem(fm.remote.frame, 0, 1, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(fm.history, 7, 0, false).
		AddItem(fm.help, 1, 0, false)
	fm.pages.AddPage("main", root, true, true)

	fm.setActive(panelLocal)

	fm.local.table.SetSelectedFunc(func(row, _ int) { fm.onEnter(panelLocal, row) })
	fm.remote.table.SetSelectedFunc(func(row, _ int) { fm.onEnter(panelRemote, row) })

	keys := func(side panelSide) func(*tcell.EventKey) *tcell.EventKey {
		return func(event *tcell.EventKey) *tcell.EventKey {
			switch event.Key() {
			case tcell.KeyTab, tcell.KeyBacktab:
				if fm.active == panelLocal {
					fm.setActive(panelRemote)
				} else {
					fm.setActive(panelLocal)
				}
				return nil
			case tcell.KeyEsc, tcell.KeyF10:
				app.Stop()
				return nil
			case tcell.KeyBackspace, tcell.KeyBackspace2:
				fm.goParent(side)
				return nil
			case tcell.KeyF5:
				fm.copy()
				return nil
			case tcell.KeyF7:
				fm.mkdirPrompt()
				return nil
			case tcell.KeyF8, tcell.KeyDelete:
				fm.deletePrompt()
				return nil
			case tcell.KeyF6:
				fm.syncPrompt()
				return nil
			}
			switch event.Rune() {
			case 'q':
				app.Stop()
				return nil
			case 'h':
				fm.goParent(side)
				return nil
			case 'c':
				fm.copy()
				return nil
			case 'm':
				fm.mkdirPrompt()
				return nil
			case 'd':
				fm.deletePrompt()
				return nil
			case 'r':
				fm.refresh()
				return nil
			case 'S':
				fm.syncPrompt()
				return nil
			case 'j':
				return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
			case 'k':
				return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
			}
			return event
		}
	}
	fm.local.table.SetInputCapture(keys(panelLocal))
	fm.remote.table.SetInputCapture(keys(panelRemote))

	fm.refresh()

	return app.SetRoot(fm.pages, true).EnableMouse(true).Run()
}

func fileHelpText() string {
	k := theme.Current.HelpKeyTag()
	return k + "Tab[-] switch  " + k + "Enter[-] cd  " + k + "Bksp[-]/" + k + "h[-] up  " +
		k + "F5[-]/" + k + "c[-] copy  " + k + "F6[-]/" + k + "S[-] sync  " +
		k + "F7[-]/" + k + "m[-] mkdir  " + k + "F8[-]/" + k + "d[-] del  " +
		k + "r[-] refresh  " + k + "q[-]/" + k + "F10[-] quit"
}

type panelSide int

const (
	panelLocal panelSide = iota
	panelRemote
)

type panel struct {
	frame   *tview.Frame
	table   *tview.Table
	entries []fileEntry
	title   string
}

func newPanel(title string) *panel {
	t := tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSeparator(0)
	t.SetSelectedStyle(tcell.StyleDefault.
		Background(theme.Current.Primary).
		Foreground(theme.Current.Inverse).
		Attributes(tcell.AttrBold))
	t.SetBorder(true).
		SetTitleAlign(tview.AlignLeft).
		SetTitleColor(theme.Current.Primary)
	f := tview.NewFrame(t).SetBorders(0, 0, 0, 0, 0, 0)
	return &panel{frame: f, table: t, title: title}
}

func (p *panel) setPath(path string) {
	p.table.SetTitle(fmt.Sprintf(" %s: %s ", p.title, path))
}

func (p *panel) selectedEntry() (fileEntry, bool) {
	row, _ := p.table.GetSelection()
	idx := row - 1 // header row
	if idx < 0 || idx >= len(p.entries) {
		return fileEntry{}, false
	}
	return p.entries[idx], true
}

type fileEntry struct {
	name  string
	isDir bool
	size  int64
	mtime time.Time
	mode  string // "drwxr-xr-x" style
	owner string // uname or uid
	group string // gname or gid
}

type fileManager struct {
	app        *tview.Application
	sc         *sftp.Client
	alias      string
	local      *panel
	remote     *panel
	help       *tview.TextView
	history    *tview.TextView
	pages      *tview.Pages
	localCwd   string
	remoteCwd  string
	active     panelSide
	flashTimer *time.Timer
	running    int32 // atomic counter of in-flight copies
}

func (fm *fileManager) setActive(side panelSide) {
	fm.active = side
	if side == panelLocal {
		fm.local.table.SetBorderColor(theme.Current.Primary)
		fm.remote.table.SetBorderColor(theme.Current.Dim)
		fm.app.SetFocus(fm.local.table)
	} else {
		fm.local.table.SetBorderColor(theme.Current.Dim)
		fm.remote.table.SetBorderColor(theme.Current.Primary)
		fm.app.SetFocus(fm.remote.table)
	}
}

func (fm *fileManager) refresh() {
	fm.loadLocal()
	fm.loadRemote()
}

// refreshHistory reads cfg.TransferHistory and renders the 5 most recent
// entries for the current alias into the bottom pane. The pane title shows
// the number of currently-running transfers so concurrent F5 presses are
// visible.
func (fm *fileManager) refreshHistory() {
	running := atomic.LoadInt32(&fm.running)
	title := fmt.Sprintf(" transfers · %s ", fm.alias)
	if running > 0 {
		title = fmt.Sprintf(" transfers · %s · %d running ", fm.alias, running)
	}
	fm.history.SetTitle(title)

	cfg, _, err := config.Load()
	if err != nil {
		fm.history.SetText("")
		return
	}
	primary := theme.Current.PrimaryTag()
	dim := theme.Current.DimTag()
	accent := theme.Current.AccentBTag()
	var b strings.Builder
	shown := 0
	for _, e := range cfg.TransferHistory {
		if e.Alias != fm.alias {
			continue
		}
		when := e.When
		if t, err := time.Parse(time.RFC3339, e.When); err == nil {
			when = t.Local().Format("2006-01-02 15:04")
		}
		arrow := "↑"
		a, c := e.Local, e.Remote
		if e.Direction == "down" {
			arrow = "↓"
			a, c = e.Remote, e.Local
		}
		fmt.Fprintf(&b, "%s%s[-] %s%s[-]  %s %s%s[-]  %s(%s)[-]\n",
			primary, arrow, dim, when, a, accent, c, dim, humanBytes(e.Bytes))
		shown++
		if shown >= 5 {
			break
		}
	}
	if shown == 0 {
		b.WriteString(dim + "  no transfers yet for this host[-]")
	}
	fm.history.SetText(b.String())
}

func (fm *fileManager) loadLocal() {
	entries, err := readLocalDir(fm.localCwd)
	if err != nil {
		fm.flash("local: " + err.Error())
		entries = nil
	}
	fm.local.entries = entries
	fm.local.setPath(fm.localCwd)
	populateTable(fm.local.table, entries)
}

func (fm *fileManager) loadRemote() {
	entries, err := readRemoteDir(fm.sc, fm.remoteCwd)
	if err != nil {
		fm.flash("remote: " + err.Error())
		entries = nil
	}
	fm.remote.entries = entries
	fm.remote.setPath(fm.remoteCwd)
	populateTable(fm.remote.table, entries)
}

func readLocalDir(path string) ([]fileEntry, error) {
	dirs, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := []fileEntry{{name: "..", isDir: true}}
	for _, d := range dirs {
		info, _ := d.Info()
		fe := fileEntry{name: d.Name(), isDir: d.IsDir()}
		if info != nil {
			fe.size = info.Size()
			fe.mtime = info.ModTime()
			fe.mode = info.Mode().String()
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				fe.owner = lookupUser(int(st.Uid))
				fe.group = lookupGroup(int(st.Gid))
			}
		}
		out = append(out, fe)
	}
	sortEntries(out[1:])
	return out, nil
}

func readRemoteDir(sc *sftp.Client, dir string) ([]fileEntry, error) {
	infos, err := sc.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := []fileEntry{{name: "..", isDir: true}}
	for _, info := range infos {
		fe := fileEntry{
			name:  info.Name(),
			isDir: info.IsDir(),
			size:  info.Size(),
			mtime: info.ModTime(),
			mode:  info.Mode().String(),
		}
		if st, ok := info.Sys().(*sftp.FileStat); ok {
			fe.owner = strconv.Itoa(int(st.UID))
			fe.group = strconv.Itoa(int(st.GID))
		}
		out = append(out, fe)
	}
	sortEntries(out[1:])
	return out, nil
}

var (
	userCache  = map[int]string{}
	groupCache = map[int]string{}
)

func lookupUser(uid int) string {
	if v, ok := userCache[uid]; ok {
		return v
	}
	if u, err := osuser.LookupId(strconv.Itoa(uid)); err == nil {
		userCache[uid] = u.Username
		return u.Username
	}
	v := strconv.Itoa(uid)
	userCache[uid] = v
	return v
}

func lookupGroup(gid int) string {
	if v, ok := groupCache[gid]; ok {
		return v
	}
	if g, err := osuser.LookupGroupId(strconv.Itoa(gid)); err == nil {
		groupCache[gid] = g.Name
		return g.Name
	}
	v := strconv.Itoa(gid)
	groupCache[gid] = v
	return v
}

func sortEntries(entries []fileEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir
		}
		return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
	})
}

func populateTable(t *tview.Table, entries []fileEntry) {
	t.Clear()
	header := func(text string, align int) *tview.TableCell {
		return tview.NewTableCell(text).
			SetSelectable(false).
			SetTextColor(theme.Current.Primary).
			SetAttributes(tcell.AttrBold).
			SetAlign(align)
	}
	t.SetCell(0, 0, header("Name", tview.AlignLeft).SetExpansion(2))
	t.SetCell(0, 1, header("Size", tview.AlignRight))
	t.SetCell(0, 2, header("Mode", tview.AlignLeft))
	t.SetCell(0, 3, header("Owner", tview.AlignLeft))
	t.SetCell(0, 4, header("Modified", tview.AlignLeft))
	for i, e := range entries {
		name := e.name
		size := ""
		nameColor := theme.Current.Text
		nameAttr := tcell.AttrNone
		if e.isDir {
			name += "/"
			nameColor = theme.Current.Primary
			nameAttr = tcell.AttrBold
		} else {
			size = humanBytes(e.size)
		}
		t.SetCell(i+1, 0, tview.NewTableCell(name).
			SetExpansion(2).
			SetTextColor(nameColor).
			SetAttributes(nameAttr))
		t.SetCell(i+1, 1, tview.NewTableCell(size).
			SetAlign(tview.AlignRight).
			SetTextColor(theme.Current.Dim))
		t.SetCell(i+1, 2, tview.NewTableCell(e.mode).SetTextColor(theme.Current.Dim))
		ownerLabel := e.owner
		if e.group != "" {
			if e.owner != "" {
				ownerLabel = e.owner + ":" + e.group
			} else {
				ownerLabel = e.group
			}
		}
		t.SetCell(i+1, 3, tview.NewTableCell(ownerLabel).SetTextColor(theme.Current.Dim))
		mt := ""
		if !e.mtime.IsZero() {
			mt = e.mtime.Format("2006-01-02 15:04")
		}
		t.SetCell(i+1, 4, tview.NewTableCell(mt).SetTextColor(theme.Current.Dim))
	}
	if len(entries) > 0 {
		t.Select(1, 0)
	}
}

func humanBytes(n int64) string {
	const KB = 1024
	const MB = KB * 1024
	const GB = MB * 1024
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1fG", float64(n)/GB)
	case n >= MB:
		return fmt.Sprintf("%.1fM", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.1fK", float64(n)/KB)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func (fm *fileManager) onEnter(side panelSide, row int) {
	var p *panel
	if side == panelLocal {
		p = fm.local
	} else {
		p = fm.remote
	}
	idx := row - 1
	if idx < 0 || idx >= len(p.entries) {
		return
	}
	e := p.entries[idx]
	if !e.isDir {
		return
	}
	if side == panelLocal {
		fm.localCwd = filepath.Clean(filepath.Join(fm.localCwd, e.name))
		fm.loadLocal()
	} else {
		fm.remoteCwd = remoteJoin(fm.remoteCwd, e.name)
		fm.loadRemote()
	}
}

func (fm *fileManager) goParent(side panelSide) {
	if side == panelLocal {
		fm.localCwd = filepath.Dir(fm.localCwd)
		fm.loadLocal()
	} else {
		fm.remoteCwd = remoteParent(fm.remoteCwd)
		fm.loadRemote()
	}
}

func remoteJoin(base, child string) string {
	if child == ".." {
		return remoteParent(base)
	}
	if strings.HasSuffix(base, "/") {
		return base + child
	}
	return base + "/" + child
}

func remoteParent(p string) string {
	if p == "/" || p == "" {
		return "/"
	}
	p = strings.TrimRight(p, "/")
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		return "/"
	}
	return p[:idx]
}

func (fm *fileManager) copy() {
	src := fm.active
	var srcPanel, dstPanel *panel
	if src == panelLocal {
		srcPanel, dstPanel = fm.local, fm.remote
	} else {
		srcPanel, dstPanel = fm.remote, fm.local
	}
	entry, ok := srcPanel.selectedEntry()
	if !ok {
		fm.flash("nothing selected")
		return
	}
	if entry.name == ".." {
		fm.flash("can't copy '..'")
		return
	}

	go func() {
		atomic.AddInt32(&fm.running, 1)
		fm.app.QueueUpdateDraw(fm.refreshHistory)
		defer func() {
			atomic.AddInt32(&fm.running, -1)
			fm.app.QueueUpdateDraw(fm.refreshHistory)
		}()
		var err error
		switch {
		case src == panelLocal && !entry.isDir:
			srcPath := filepath.Join(fm.localCwd, entry.name)
			dstPath := remoteJoin(fm.remoteCwd, entry.name)
			err = transfer.UploadFile(fm.sc, srcPath, dstPath, fm.alias)
		case src == panelLocal && entry.isDir:
			srcPath := filepath.Join(fm.localCwd, entry.name)
			dstPath := remoteJoin(fm.remoteCwd, entry.name)
			err = transfer.UploadDir(fm.sc, srcPath, dstPath, fm.alias)
		case src == panelRemote && !entry.isDir:
			srcPath := remoteJoin(fm.remoteCwd, entry.name)
			dstPath := filepath.Join(fm.localCwd, entry.name)
			err = transfer.DownloadFile(fm.sc, srcPath, dstPath, fm.alias)
		case src == panelRemote && entry.isDir:
			srcPath := remoteJoin(fm.remoteCwd, entry.name)
			dstPath := filepath.Join(fm.localCwd, entry.name)
			err = transfer.DownloadDir(fm.sc, srcPath, dstPath, fm.alias)
		}
		fm.app.QueueUpdateDraw(func() {
			if err != nil {
				fm.flash("copy failed: " + err.Error())
				return
			}
			fm.loadLocal()
			fm.loadRemote()
			fm.refreshHistory()
			_ = dstPanel
			fm.flash(fmt.Sprintf("copied %s", entry.name))
		})
		// Force a full tcell sync after the queued redraw — table.Clear +
		// re-populate occasionally leaves stale glyphs on rows that shrank
		// (e.g. shorter filenames after sorting). Sync() goes through
		// tcell directly so it doesn't re-enter the event queue.
		fm.app.Sync()
	}()
}

func (fm *fileManager) mkdirPrompt() {
	fm.inputPrompt("Create directory:", "", func(name string) {
		if name == "" {
			return
		}
		var err error
		if fm.active == panelLocal {
			err = os.MkdirAll(filepath.Join(fm.localCwd, name), 0o755)
			fm.loadLocal()
		} else {
			err = fm.sc.MkdirAll(remoteJoin(fm.remoteCwd, name))
			fm.loadRemote()
		}
		if err != nil {
			fm.flash("mkdir: " + err.Error())
		}
	})
}

func (fm *fileManager) deletePrompt() {
	var p *panel
	if fm.active == panelLocal {
		p = fm.local
	} else {
		p = fm.remote
	}
	entry, ok := p.selectedEntry()
	if !ok || entry.name == ".." {
		return
	}
	target := entry.name
	fm.confirm(fmt.Sprintf("Delete %q?", target), func() {
		var err error
		if fm.active == panelLocal {
			path := filepath.Join(fm.localCwd, target)
			if entry.isDir {
				err = os.Remove(path) // empty dir only
			} else {
				err = os.Remove(path)
			}
			fm.loadLocal()
		} else {
			path := remoteJoin(fm.remoteCwd, target)
			if entry.isDir {
				err = fm.sc.RemoveDirectory(path) // empty dir only
			} else {
				err = fm.sc.Remove(path)
			}
			fm.loadRemote()
		}
		if err != nil {
			fm.flash("delete: " + err.Error())
		}
	})
}

func (fm *fileManager) inputPrompt(label, def string, onDone func(string)) {
	input := tview.NewInputField().
		SetLabel(label + " ").
		SetText(def).
		SetFieldBackgroundColor(theme.Current.FieldBg).
		SetFieldTextColor(theme.Current.Text).
		SetLabelColor(theme.Current.Primary).
		SetDoneFunc(func(key tcell.Key) {})
	form := tview.NewForm().
		AddFormItem(input).
		AddButton("OK", func() {
			fm.pages.RemovePage("input")
			fm.app.SetFocus(fm.activeTable())
			onDone(strings.TrimSpace(input.GetText()))
		}).
		AddButton("Cancel", func() {
			fm.pages.RemovePage("input")
			fm.app.SetFocus(fm.activeTable())
		})
	form.SetBorder(true).SetBorderColor(theme.Current.Primary).SetTitle(" " + label + " ").SetTitleColor(theme.Current.Primary)
	form.SetButtonBackgroundColor(theme.Current.Primary).SetButtonTextColor(theme.Current.Inverse)
	fm.pages.AddPage("input", centered(form, 60, 7), true, true)
	fm.app.SetFocus(input)
}

func (fm *fileManager) confirm(text string, onYes func()) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"Delete", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			fm.pages.RemovePage("confirm")
			fm.app.SetFocus(fm.activeTable())
			if label == "Delete" {
				onYes()
			}
		})
	fm.pages.AddPage("confirm", modal, true, true)
}

func (fm *fileManager) activeTable() *tview.Table {
	if fm.active == panelLocal {
		return fm.local.table
	}
	return fm.remote.table
}

// syncPrompt drives a one-way directory sync between the active panel and
// the inactive one. The plan is computed first (entries that don't exist on
// the destination, plus entries with different size — mtime comparison is
// flaky over SFTP), shown to the user as a numbered list, and only executed
// after confirmation. Direction matches the active panel: local→remote when
// local is active.
func (fm *fileManager) syncPrompt() {
	var (
		srcRoot, dstRoot string
		dir              string // "up" | "down"
	)
	if fm.active == panelLocal {
		srcRoot, dstRoot, dir = fm.localCwd, fm.remoteCwd, "up"
	} else {
		srcRoot, dstRoot, dir = fm.remoteCwd, fm.localCwd, "down"
	}

	plan, err := fm.planSync(dir, srcRoot, dstRoot)
	if err != nil {
		fm.flash("sync plan failed: " + err.Error())
		return
	}
	if len(plan) == 0 {
		fm.flash("sync: nothing to copy — destination already matches")
		return
	}

	var b strings.Builder
	for i, p := range plan {
		if i >= 100 {
			fmt.Fprintf(&b, "\n... and %d more", len(plan)-i)
			break
		}
		fmt.Fprintf(&b, "%s%s\n", p.kind, p.rel)
	}
	dirArrow := "→"
	if dir == "down" {
		dirArrow = "←"
	}
	text := fmt.Sprintf("Sync %s %s %s\n%d entries will copy:\n\n%s",
		srcRoot, dirArrow, dstRoot, len(plan), b.String())

	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"Run", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			fm.pages.RemovePage("sync")
			fm.app.SetFocus(fm.activeTable())
			if label != "Run" {
				return
			}
			go fm.runSync(dir, srcRoot, dstRoot, plan)
		})
	fm.pages.AddPage("sync", modal, true, true)
}

type syncEntry struct {
	rel  string // path relative to srcRoot
	kind string // "+ " new on dest, "~ " size differs
	isDir bool
}

// planSync walks the source recursively and lists what the destination
// is missing or has at a different size.
func (fm *fileManager) planSync(dir, srcRoot, dstRoot string) ([]syncEntry, error) {
	var plan []syncEntry
	var walk func(rel string) error
	walk = func(rel string) error {
		var srcEntries []entryInfo
		var err error
		if dir == "up" {
			srcEntries, err = localList(filepath.Join(srcRoot, rel))
		} else {
			srcEntries, err = remoteList(fm.sc, remoteJoin(srcRoot, rel))
		}
		if err != nil {
			return err
		}
		for _, e := range srcEntries {
			child := e.name
			childRel := child
			if rel != "" {
				childRel = filepath.Join(rel, child)
			}
			var dstSize int64 = -1
			var dstIsDir bool
			if dir == "up" {
				if info, err := fm.sc.Stat(remoteJoin(dstRoot, childRel)); err == nil {
					dstSize = info.Size()
					dstIsDir = info.IsDir()
				}
			} else {
				if info, err := os.Stat(filepath.Join(dstRoot, childRel)); err == nil {
					dstSize = info.Size()
					dstIsDir = info.IsDir()
				}
			}
			if e.isDir {
				if dstSize == -1 {
					plan = append(plan, syncEntry{rel: childRel + "/", kind: "+ ", isDir: true})
				} else if !dstIsDir {
					plan = append(plan, syncEntry{rel: childRel + "/", kind: "~ ", isDir: true})
				}
				if err := walk(childRel); err != nil {
					return err
				}
				continue
			}
			switch {
			case dstSize == -1:
				plan = append(plan, syncEntry{rel: childRel, kind: "+ "})
			case dstSize != e.size:
				plan = append(plan, syncEntry{rel: childRel, kind: "~ "})
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	return plan, nil
}

type entryInfo struct {
	name  string
	isDir bool
	size  int64
}

func localList(path string) ([]entryInfo, error) {
	dirs, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]entryInfo, 0, len(dirs))
	for _, d := range dirs {
		info, _ := d.Info()
		ei := entryInfo{name: d.Name(), isDir: d.IsDir()}
		if info != nil {
			ei.size = info.Size()
		}
		out = append(out, ei)
	}
	return out, nil
}

func remoteList(sc *sftp.Client, path string) ([]entryInfo, error) {
	infos, err := sc.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]entryInfo, 0, len(infos))
	for _, info := range infos {
		out = append(out, entryInfo{name: info.Name(), isDir: info.IsDir(), size: info.Size()})
	}
	return out, nil
}

// runSync executes a previously-confirmed plan. Each new directory is
// mkdir'd, each new/changed file is copied. Failures are reported via flash
// but the rest of the plan still attempts to run.
func (fm *fileManager) runSync(dir, srcRoot, dstRoot string, plan []syncEntry) {
	failed := 0
	for _, p := range plan {
		// Per-file running increment so the transfers pane title shows live
		// progress through the batch instead of a static "1 running".
		atomic.AddInt32(&fm.running, 1)
		fm.app.QueueUpdateDraw(fm.refreshHistory)

		var src, dst string
		if dir == "up" {
			src = filepath.Join(srcRoot, p.rel)
			dst = remoteJoin(dstRoot, p.rel)
		} else {
			src = remoteJoin(srcRoot, p.rel)
			dst = filepath.Join(dstRoot, p.rel)
		}

		var err error
		switch {
		case p.isDir && dir == "up":
			err = fm.sc.MkdirAll(dst)
		case p.isDir && dir == "down":
			err = os.MkdirAll(dst, 0o755)
		case dir == "up":
			err = transfer.UploadFile(fm.sc, src, dst, fm.alias)
		case dir == "down":
			err = transfer.DownloadFile(fm.sc, src, dst, fm.alias)
		}
		atomic.AddInt32(&fm.running, -1)
		if err != nil {
			failed++
		}
	}
	fm.app.QueueUpdateDraw(func() {
		fm.loadLocal()
		fm.loadRemote()
		fm.refreshHistory()
		if failed > 0 {
			fm.flash(fmt.Sprintf("sync done with %d failure(s)", failed))
		} else {
			fm.flash(fmt.Sprintf("sync done (%d entries)", len(plan)))
		}
	})
}

func (fm *fileManager) flash(msg string) {
	tag := theme.Current.WarningTag() + "[::b]"
	if strings.Contains(strings.ToLower(msg), "fail") || strings.Contains(strings.ToLower(msg), "error") {
		tag = theme.Current.ErrorTag() + "[::b]"
	}
	fm.help.SetText(tag + msg + "[-:-:-]    " + fileHelpText())
	// Cancel a pending reset from a previous flash so the latest message stays
	// visible for the full 3s instead of being wiped early.
	if fm.flashTimer != nil {
		fm.flashTimer.Stop()
	}
	fm.flashTimer = time.AfterFunc(3*time.Second, func() {
		fm.app.QueueUpdateDraw(func() { fm.help.SetText(fileHelpText()) })
	})
}
