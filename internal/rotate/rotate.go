// Package rotate performs safe SSH key rotation across a fleet.
//
// The safety contract: the old key is NEVER removed from a host until a
// brand-new, independent connection — authenticated with ONLY the new key —
// has been proven to work. If anything fails (append, verify, permissions),
// the host is left exactly as it was, with the old key intact.
package rotate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/sshc"
	"github.com/systeampl/sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const authorizedKeysPath = ".ssh/authorized_keys"

// Result is one host's rotation outcome.
type Result struct {
	Alias         string
	Added         bool   // new key appended (false if already present)
	Verified      bool   // a key-only connection with the new key succeeded
	ConfigUpdated bool   // config now points at the verified new key
	OldRemoved    bool   // old key line removed from authorized_keys
	Skipped       bool   // dry-run, or nothing to do
	Err           error  // first failure; old-key removal failures are errors too
	Note          string // human summary
}

type prepared struct {
	result            Result
	oldPub            ssh.PublicKey
	needsConfigUpdate bool
}

// PublicKeyLine reads a private key file and returns its authorized_keys
// line ("ssh-ed25519 AAAA...\n", no comment).
func PublicKeyLine(privKeyPath string) (string, ssh.PublicKey, error) {
	data, err := os.ReadFile(config.ExpandPath(privKeyPath))
	if err != nil {
		return "", nil, fmt.Errorf("read key %s: %w", privKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		pub := signer.PublicKey()
		return string(ssh.MarshalAuthorizedKey(pub)), pub, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return "", nil, fmt.Errorf("parse key %s: %w", privKeyPath, err)
	}
	pubPath := config.ExpandPath(privKeyPath) + ".pub"
	pubData, readErr := os.ReadFile(pubPath)
	if readErr != nil {
		return "", nil, fmt.Errorf("key %s is encrypted and public sidecar %s cannot be read: %w", privKeyPath, pubPath, readErr)
	}
	pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(pubData)
	if parseErr != nil {
		return "", nil, fmt.Errorf("parse public key sidecar %s: %w", pubPath, parseErr)
	}
	return string(ssh.MarshalAuthorizedKey(pub)), pub, nil
}

// Run rotates the new key onto every alias. When removeOld is false (the
// default) it only appends + verifies — a safe first phase you can run
// fleet-wide, confirm, and only later re-run with removeOld=true.
func Run(cfg *config.Config, cfgPath string, aliases []string, newKeyPath string, removeOld, dryRun bool, parallel int) []Result {
	if parallel <= 0 {
		parallel = 6
	}
	newLine, newPub, err := PublicKeyLine(newKeyPath)
	if err != nil {
		// Fatal for the whole run — can't proceed without the new key.
		out := make([]Result, len(aliases))
		for i, a := range aliases {
			out[i] = Result{Alias: a, Err: err}
		}
		return out
	}

	sem := make(chan struct{}, parallel)
	targetLocks := rotationTargetLocks(cfg, aliases)
	preparedHosts := make([]prepared, len(aliases))
	var wg sync.WaitGroup
	for i, alias := range aliases {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, alias string) {
			defer wg.Done()
			defer func() { <-sem }()
			lock := targetLocks[alias]
			lock.Lock()
			defer lock.Unlock()
			preparedHosts[i] = prepareOne(cfg, alias, newKeyPath, newLine, newPub, removeOld, dryRun)
		}(i, alias)
	}
	wg.Wait()

	results := make([]Result, len(preparedHosts))
	for i := range preparedHosts {
		results[i] = preparedHosts[i].result
	}
	if dryRun || !removeOld {
		printSummary(results, removeOld, dryRun)
		return results
	}

	// Persist the verified new key before removing any old key. If this save
	// fails, every old key remains authorized and the existing config remains
	// usable. Hosts that failed append/verify are deliberately left unchanged.
	originals := make(map[string]config.HostConfig)
	for i, p := range preparedHosts {
		if p.result.Err != nil || !p.result.Verified || !p.needsConfigUpdate {
			continue
		}
		originals[p.result.Alias] = cfg.Hosts[p.result.Alias]
		h := cfg.Hosts[p.result.Alias]
		h.Key = newKeyPath
		cfg.Hosts[p.result.Alias] = h
		results[i].ConfigUpdated = true
	}
	if len(originals) > 0 {
		if err := config.Save(cfg, cfgPath); err != nil {
			for alias, h := range originals {
				cfg.Hosts[alias] = h
			}
			for i := range results {
				if results[i].ConfigUpdated {
					results[i].ConfigUpdated = false
					results[i].Err = fmt.Errorf("persist verified new key before old-key removal: %w (old key kept; new key remains authorized)", err)
				}
			}
			printSummary(results, removeOld, dryRun)
			return results
		}
	}

	// Only now is removal allowed. Reconnect explicitly with the new key; do
	// not trust the just-updated config or fall back to any other auth method.
	for i, p := range preparedHosts {
		if results[i].Err != nil || !results[i].Verified {
			continue
		}
		if p.oldPub == nil {
			if results[i].ConfigUpdated {
				results[i].Note = "new key verified + configured; no different old key to remove"
			} else {
				results[i].Skipped = true
				results[i].Note = "new key already configured + verified; no different old key to remove"
			}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, alias string, oldPub ssh.PublicKey) {
			defer wg.Done()
			defer func() { <-sem }()
			lock := targetLocks[alias]
			lock.Lock()
			defer lock.Unlock()
			removeOldOne(cfg, alias, newKeyPath, oldPub, &results[i])
		}(i, p.result.Alias, p.oldPub)
	}
	wg.Wait()
	printSummary(results, removeOld, dryRun)
	return results
}

// rotationTargetLocks serialize read-modify-write operations when several
// aliases describe the same SSH account. Without this, two concurrent
// authorized_keys replacements could each reintroduce the key removed by the
// other. Different aliases remain fully parallel.
func rotationTargetLocks(cfg *config.Config, aliases []string) map[string]*sync.Mutex {
	byTarget := map[string]*sync.Mutex{}
	byAlias := make(map[string]*sync.Mutex, len(aliases))
	for _, alias := range aliases {
		h, ok := cfg.ResolveHost(alias)
		key := "alias\x00" + alias
		if ok {
			key = strings.ToLower(strings.TrimSpace(h.User)) + "\x00" +
				strings.ToLower(strings.TrimSpace(h.Host)) + "\x00" + fmt.Sprintf("%d", h.Port)
		}
		lock := byTarget[key]
		if lock == nil {
			lock = &sync.Mutex{}
			byTarget[key] = lock
		}
		byAlias[alias] = lock
	}
	return byAlias
}

func prepareOne(cfg *config.Config, alias, newKeyPath, newLine string, newPub ssh.PublicKey, removeOld, dryRun bool) prepared {
	p := prepared{result: Result{Alias: alias}}
	r := &p.result

	host, ok := cfg.ResolveHost(alias)
	if !ok {
		r.Err = errors.New("alias not found")
		return p
	}

	// Capture the old key before touching the host. An equal key means the
	// config is already migrated; it must never be removed as "old".
	if removeOld && host.Key != "" {
		_, oldPub, err := PublicKeyLine(host.Key)
		if err != nil {
			r.Err = fmt.Errorf("read configured old key before rotation: %w", err)
			return p
		}
		if !bytes.Equal(oldPub.Marshal(), newPub.Marshal()) {
			p.oldPub = oldPub
			p.needsConfigUpdate = true
		}
	} else if removeOld && host.Key == "" {
		p.needsConfigUpdate = true
	}

	// --- step 1: connect with current credentials ---
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		r.Err = fmt.Errorf("connect: %w", err)
		return p
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		sshc.CloseChain(client)
		r.Err = fmt.Errorf("sftp: %w", err)
		return p
	}

	ak, err := readAuthorizedKeys(sc)
	if err != nil {
		sc.Close()
		sshc.CloseChain(client)
		r.Err = fmt.Errorf("read authorized_keys: %w", err)
		return p
	}
	alreadyHasNew := containsKey(ak, newPub)

	if dryRun {
		sc.Close()
		sshc.CloseChain(client)
		r.Skipped = true
		switch {
		case p.oldPub == nil && removeOld && alreadyHasNew:
			r.Note = "would verify; new key is already configured or no different old key exists"
		case alreadyHasNew && removeOld:
			r.Note = "would verify + remove old key (new key already present)"
		case alreadyHasNew:
			r.Note = "new key already present — nothing to add"
		case removeOld:
			r.Note = "would append new key, verify, then remove old key"
		default:
			r.Note = "would append new key + verify"
		}
		return p
	}

	// --- step 2: append the new key (idempotent) ---
	if !alreadyHasNew {
		updated := appendLine(ak, newLine)
		if err := writeAuthorizedKeys(sc, updated); err != nil {
			sc.Close()
			sshc.CloseChain(client)
			r.Err = fmt.Errorf("append new key: %w", err)
			return p
		}
		r.Added = true
	}

	// --- step 3: verify with a key-only connection ---
	if err := sshc.VerifyKey(cfg, alias, newKeyPath); err != nil {
		if r.Added {
			if rollbackErr := rollbackKey(sc, newPub); rollbackErr != nil {
				r.Err = fmt.Errorf("verify FAILED: %w; rollback of appended key also failed: %v (old key remains intact)", err, rollbackErr)
			} else {
				r.Added = false
				r.Err = fmt.Errorf("verify FAILED — appended key rolled back, old key left intact: %w", err)
			}
		} else {
			r.Err = fmt.Errorf("verify FAILED — old key left intact: %w", err)
		}
		sc.Close()
		sshc.CloseChain(client)
		return p
	}
	sc.Close()
	sshc.CloseChain(client)
	r.Verified = true

	if !removeOld {
		r.Note = "new key added + verified (old key kept — re-run with --remove-old to drop it)"
		return p
	}
	r.Note = "new key verified; ready to persist config before old-key removal"
	return p
}

func rollbackKey(sc *sftp.Client, pub ssh.PublicKey) error {
	current, err := readAuthorizedKeys(sc)
	if err != nil {
		return err
	}
	without, removed := removeKey(current, pub)
	if !removed {
		return nil
	}
	return writeAuthorizedKeys(sc, without)
}

func removeOldOne(cfg *config.Config, alias, newKeyPath string, oldPub ssh.PublicKey, r *Result) {
	client2, err := sshc.ConnectAliasWithKey(cfg, alias, newKeyPath)
	if err != nil {
		r.Err = fmt.Errorf("new-key reconnect for old-key removal: %w (old key kept)", err)
		return
	}
	defer sshc.CloseChain(client2)
	sc2, err := sftp.NewClient(client2)
	if err != nil {
		r.Err = fmt.Errorf("sftp for old-key removal: %w (old key kept)", err)
		return
	}
	defer sc2.Close()
	ak2, err := readAuthorizedKeys(sc2)
	if err != nil {
		r.Err = fmt.Errorf("re-read authorized_keys for old-key removal: %w (old key kept)", err)
		return
	}
	stripped, removed := removeKey(ak2, oldPub)
	if !removed {
		r.Skipped = true
		r.Note = "new key verified + configured; old key already absent"
		return
	}
	if err := writeAuthorizedKeys(sc2, stripped); err != nil {
		r.Err = fmt.Errorf("remove old key: %w (new key is configured; old key may still be present)", err)
		return
	}
	r.OldRemoved = true
	r.Note = "new key verified + configured, old key removed"
}

// readAuthorizedKeys returns the file content, or empty when the file
// genuinely doesn't exist. A permission / IO error is propagated — treating
// it as "empty" would make a later write replace the whole file with just
// the new key, silently wiping every other key on the host.
func readAuthorizedKeys(sc *sftp.Client) ([]byte, error) {
	f, err := sc.Open(authorizedKeysPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // first key on this host — write will create it
		}
		return nil, fmt.Errorf("open %s: %w", authorizedKeysPath, err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeAuthorizedKeys writes content atomically: a temp file in ~/.ssh,
// chmod 0600, then PosixRename over authorized_keys.
func writeAuthorizedKeys(sc *sftp.Client, content []byte) error {
	if err := sc.MkdirAll(".ssh"); err != nil {
		return fmt.Errorf("mkdir .ssh: %w", err)
	}
	if err := sc.Chmod(".ssh", 0o700); err != nil {
		return fmt.Errorf("chmod .ssh: %w", err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("create authorized_keys temp name: %w", err)
	}
	suffix := hex.EncodeToString(nonce[:])
	tmp := ".ssh/.authorized_keys.sshmgr-tmp-" + suffix
	f, err := sc.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		_ = sc.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = sc.Remove(tmp)
		return err
	}
	if err := sc.Chmod(tmp, 0o600); err != nil {
		_ = sc.Remove(tmp)
		return err
	}
	// PosixRename atomically replaces the destination — preferred path.
	if err := sc.PosixRename(tmp, authorizedKeysPath); err == nil {
		return nil
	}
	// Fallback for servers without the posix-rename extension. Never leave
	// authorized_keys absent: move the live file aside FIRST, swap the new
	// one in, then drop the backup. On failure, restore from the backup.
	bak := authorizedKeysPath + ".sshmgr-bak-" + suffix
	_ = sc.Rename(authorizedKeysPath, bak) // ok to fail if file didn't exist
	if err := sc.Rename(tmp, authorizedKeysPath); err != nil {
		_ = sc.Rename(bak, authorizedKeysPath) // put the original back
		_ = sc.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, authorizedKeysPath, err)
	}
	_ = sc.Remove(bak)
	return nil
}

// containsKey reports whether the authorized_keys content already lists pub.
func containsKey(ak []byte, pub ssh.PublicKey) bool {
	want := pub.Marshal()
	rest := ak
	for len(rest) > 0 {
		got, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		if bytes.Equal(got.Marshal(), want) {
			return true
		}
		rest = next
	}
	return false
}

// removeKey returns ak with every line matching pub dropped. comparison is
// on the key blob, so a differing comment field doesn't matter.
func removeKey(ak []byte, pub ssh.PublicKey) (out []byte, removed bool) {
	want := pub.Marshal()
	var kept []string
	for _, line := range strings.Split(string(ak), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		got, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
		if err == nil && bytes.Equal(got.Marshal(), want) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	res := strings.Join(kept, "\n")
	if res != "" {
		res += "\n"
	}
	return []byte(res), removed
}

func appendLine(ak []byte, line string) []byte {
	out := ak
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, []byte(strings.TrimRight(line, "\n")+"\n")...)
	return out
}

func printSummary(results []Result, removeOld, dryRun bool) {
	primary := theme.ANSI(theme.Current.Primary)
	green := theme.ANSI(tcell.ColorGreen)
	red := theme.ANSI(theme.Current.Error)
	dim := theme.ANSI(theme.Current.Dim)
	reset := theme.Reset()

	mode := "append + verify"
	if removeOld {
		mode = "append + verify + remove-old"
	}
	if dryRun {
		mode = "DRY RUN"
	}
	ok, fail := 0, 0
	for _, r := range results {
		if r.Err != nil {
			fail++
		} else {
			ok++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s=== key rotation (%s) ===%s  %s%d ok%s  %s%d failed%s\n",
		primary, mode, reset, green, ok, reset, red, fail, reset)

	sorted := append([]Result(nil), results...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Alias < sorted[j].Alias })
	for _, r := range sorted {
		mark, color := "✓", green
		if r.Err != nil {
			mark, color = "✗", red
		}
		note := r.Note
		if r.Err != nil {
			note = r.Err.Error()
		}
		fmt.Fprintf(os.Stderr, "  %s%s%s  %-24s  %s%s%s\n",
			color, mark, reset, r.Alias, dim, note, reset)
	}
}
