// Package rotate performs safe SSH key rotation across a fleet.
//
// The safety contract: the old key is NEVER removed from a host until a
// brand-new, independent connection — authenticated with ONLY the new key —
// has been proven to work. If anything fails (append, verify, permissions),
// the host is left exactly as it was, with the old key intact.
package rotate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"sshmgr/internal/config"
	"sshmgr/internal/sshc"
	"sshmgr/internal/theme"

	"github.com/gdamore/tcell/v2"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const authorizedKeysPath = ".ssh/authorized_keys"

// Result is one host's rotation outcome.
type Result struct {
	Alias      string
	Added      bool   // new key appended (false if already present)
	Verified   bool   // a key-only connection with the new key succeeded
	OldRemoved bool   // old key line removed from authorized_keys
	Skipped    bool   // dry-run, or nothing to do
	Err        error  // first failure; when set, nothing destructive happened
	Note       string // human summary
}

// PublicKeyLine reads a private key file and returns its authorized_keys
// line ("ssh-ed25519 AAAA...\n", no comment).
func PublicKeyLine(privKeyPath string) (string, ssh.PublicKey, error) {
	data, err := os.ReadFile(config.ExpandPath(privKeyPath))
	if err != nil {
		return "", nil, fmt.Errorf("read key %s: %w", privKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", nil, fmt.Errorf("parse key %s: %w", privKeyPath, err)
	}
	pub := signer.PublicKey()
	return string(ssh.MarshalAuthorizedKey(pub)), pub, nil
}

// Run rotates the new key onto every alias. When removeOld is false (the
// default) it only appends + verifies — a safe first phase you can run
// fleet-wide, confirm, and only later re-run with removeOld=true.
func Run(cfg *config.Config, aliases []string, newKeyPath string, removeOld, dryRun bool, parallel int) []Result {
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
	results := make([]Result, len(aliases))
	var wg sync.WaitGroup
	for i, alias := range aliases {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, alias string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = rotateOne(cfg, alias, newKeyPath, newLine, newPub, removeOld, dryRun)
		}(i, alias)
	}
	wg.Wait()
	printSummary(results, removeOld, dryRun)
	return results
}

func rotateOne(cfg *config.Config, alias, newKeyPath, newLine string, newPub ssh.PublicKey, removeOld, dryRun bool) Result {
	r := Result{Alias: alias}

	host, ok := cfg.ResolveHost(alias)
	if !ok {
		r.Err = errors.New("alias not found")
		return r
	}

	// Refuse to rotate a key onto itself. If --new-key is (accidentally) the
	// host's currently-configured key, a --remove-old run would strip the
	// only key from authorized_keys and lock the host out.
	if removeOld && host.Key != "" {
		if _, oldPub, err := PublicKeyLine(host.Key); err == nil && bytes.Equal(oldPub.Marshal(), newPub.Marshal()) {
			r.Err = fmt.Errorf("--new-key is the same key already configured for this host — refusing (would remove the only key)")
			return r
		}
	}

	// --- step 1: connect with current credentials ---
	client, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		r.Err = fmt.Errorf("connect: %w", err)
		return r
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		sshc.CloseChain(client)
		r.Err = fmt.Errorf("sftp: %w", err)
		return r
	}

	ak, err := readAuthorizedKeys(sc)
	if err != nil {
		sc.Close()
		sshc.CloseChain(client)
		r.Err = fmt.Errorf("read authorized_keys: %w", err)
		return r
	}
	alreadyHasNew := containsKey(ak, newPub)

	if dryRun {
		sc.Close()
		sshc.CloseChain(client)
		r.Skipped = true
		switch {
		case alreadyHasNew && removeOld:
			r.Note = "would verify + remove old key (new key already present)"
		case alreadyHasNew:
			r.Note = "new key already present — nothing to add"
		case removeOld:
			r.Note = "would append new key, verify, then remove old key"
		default:
			r.Note = "would append new key + verify"
		}
		return r
	}

	// --- step 2: append the new key (idempotent) ---
	if !alreadyHasNew {
		updated := appendLine(ak, newLine)
		if err := writeAuthorizedKeys(sc, updated); err != nil {
			sc.Close()
			sshc.CloseChain(client)
			r.Err = fmt.Errorf("append new key: %w", err)
			return r
		}
		r.Added = true
	}
	sc.Close()
	sshc.CloseChain(client)

	// --- step 3: verify with a key-only connection ---
	if err := sshc.VerifyKey(cfg, alias, newKeyPath); err != nil {
		r.Err = fmt.Errorf("verify FAILED — old key left intact: %w", err)
		return r
	}
	r.Verified = true

	if !removeOld {
		r.Note = "new key added + verified (old key kept — re-run with --remove-old to drop it)"
		return r
	}

	// --- step 4: remove the old key — only reached after verify passed ---
	if host.Key == "" {
		r.Note = "verified; no 'key:' configured so there's no old key to remove"
		return r
	}
	_, oldPub, err := PublicKeyLine(host.Key)
	if err != nil {
		r.Note = "verified; could not derive old public key (" + err.Error() + ") — old key kept"
		return r
	}
	// Reconnect (the new key works now, so this still succeeds) and strip the old line.
	client2, err := sshc.ConnectAlias(cfg, alias)
	if err != nil {
		r.Note = "verified + new key added, but reconnect to remove old key failed: " + err.Error()
		return r
	}
	defer sshc.CloseChain(client2)
	sc2, err := sftp.NewClient(client2)
	if err != nil {
		r.Note = "verified; sftp for old-key removal failed: " + err.Error()
		return r
	}
	defer sc2.Close()
	ak2, err := readAuthorizedKeys(sc2)
	if err != nil {
		r.Note = "verified; re-read of authorized_keys failed: " + err.Error()
		return r
	}
	stripped, removed := removeKey(ak2, oldPub)
	if !removed {
		r.Note = "verified; old key was not present in authorized_keys (nothing to remove)"
		return r
	}
	if err := writeAuthorizedKeys(sc2, stripped); err != nil {
		r.Note = "verified; removing old key failed: " + err.Error() + " — old key may still be present"
		return r
	}
	r.OldRemoved = true
	r.Note = "new key added + verified, old key removed"
	return r
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
	tmp := ".ssh/.authorized_keys.sshmgr-tmp"
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
	bak := authorizedKeysPath + ".sshmgr-bak"
	_ = sc.Remove(bak)
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
