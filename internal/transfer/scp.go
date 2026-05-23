// Package transfer implements SCP (one-shot copy) and SFTP (interactive REPL)
// over an existing *ssh.Client. Reuses sshc's ConnectAlias chain (proxy_jump,
// proxy_command, password backends) so transfers go through the same tunnels
// as interactive shells.
package transfer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sshmgr/internal/theme"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SCP copies a single file (or, with recursive=true, a directory tree) between
// the local filesystem and a remote host reached through client. Direction is
// inferred from src/dst — exactly one must be of the form alias:/path; alias
// here is informational (the actual client is already connected).
//
// Both paths use forward slashes; remote paths are interpreted relative to the
// SSH user's home if not absolute.
type Direction int

const (
	Upload Direction = iota
	Download
)

func SCP(client *ssh.Client, src, dst string, recursive bool) error {
	srcAlias, srcPath, srcIsRemote := splitRemote(src)
	dstAlias, dstPath, dstIsRemote := splitRemote(dst)

	if srcIsRemote == dstIsRemote {
		return errors.New("scp: exactly one of src/dst must be remote (alias:/path)")
	}

	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp init: %w", err)
	}
	defer sc.Close()

	if srcIsRemote {
		return download(sc, srcPath, dstPath, recursive, srcAlias)
	}
	return upload(sc, srcPath, dstPath, recursive, dstAlias)
}

func download(sc *sftp.Client, remote, local string, recursive bool, alias string) error {
	info, err := sc.Stat(remote)
	if err != nil {
		return fmt.Errorf("remote stat %s: %w", remote, err)
	}
	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s is a directory (use -r)", remote)
		}
		return downloadDir(sc, remote, local, alias)
	}
	if li, err := os.Stat(local); err == nil && li.IsDir() {
		local = filepath.Join(local, filepath.Base(remote))
	}
	return downloadFile(sc, remote, local, alias)
}

// DownloadFile copies a single remote file to local path via sc, logging the
// transfer under alias (which appears in TransferHistory).
func DownloadFile(sc *sftp.Client, remote, local, alias string) error {
	return downloadFile(sc, remote, local, alias)
}

// UploadFile copies a single local file to remote path via sc.
func UploadFile(sc *sftp.Client, local, remote, alias string) error {
	return uploadFile(sc, local, remote, alias)
}

// DownloadDir recursively downloads remote directory to local path.
func DownloadDir(sc *sftp.Client, remote, local, alias string) error {
	return downloadDir(sc, remote, local, alias)
}

// UploadDir recursively uploads local directory to remote path.
func UploadDir(sc *sftp.Client, local, remote, alias string) error {
	return uploadDir(sc, local, remote, alias)
}

func downloadFile(sc *sftp.Client, remote, local, alias string) error {
	rf, err := sc.Open(remote)
	if err != nil {
		return fmt.Errorf("remote open %s: %w", remote, err)
	}
	defer rf.Close()
	lf, err := os.Create(local)
	if err != nil {
		return fmt.Errorf("local create %s: %w", local, err)
	}
	defer lf.Close()
	start := time.Now()
	n, err := io.Copy(lf, rf)
	if err != nil {
		return fmt.Errorf("copy %s -> %s: %w", remote, local, err)
	}
	fmt.Fprintf(os.Stderr, "%s[sshmgr]%s %s%s%s -> %s%s%s  (%s, %s)\n", theme.ANSI(theme.Current.Primary), theme.Reset(), theme.ANSI(theme.Current.AccentB), remote, theme.Reset(), theme.ANSI(theme.Current.AccentB), local, theme.Reset(), formatBytes(n), time.Since(start).Round(time.Millisecond))
	logXfer("down", alias, local, remote, n)
	return nil
}

func downloadDir(sc *sftp.Client, remote, local, alias string) error {
	if err := os.MkdirAll(local, 0o755); err != nil {
		return err
	}
	entries, err := sc.ReadDir(remote)
	if err != nil {
		return fmt.Errorf("remote readdir %s: %w", remote, err)
	}
	for _, e := range entries {
		rname := path(remote, e.Name())
		lname := filepath.Join(local, e.Name())
		if e.IsDir() {
			if err := downloadDir(sc, rname, lname, alias); err != nil {
				return err
			}
			continue
		}
		if err := downloadFile(sc, rname, lname, alias); err != nil {
			return err
		}
	}
	return nil
}

func upload(sc *sftp.Client, local, remote string, recursive bool, alias string) error {
	info, err := os.Stat(local)
	if err != nil {
		return fmt.Errorf("local stat %s: %w", local, err)
	}
	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s is a directory (use -r)", local)
		}
		return uploadDir(sc, local, remote, alias)
	}
	if ri, err := sc.Stat(remote); err == nil && ri.IsDir() {
		remote = path(remote, filepath.Base(local))
	}
	return uploadFile(sc, local, remote, alias)
}

func uploadFile(sc *sftp.Client, local, remote, alias string) error {
	lf, err := os.Open(local)
	if err != nil {
		return fmt.Errorf("local open %s: %w", local, err)
	}
	defer lf.Close()
	rf, err := sc.Create(remote)
	if err != nil {
		return fmt.Errorf("remote create %s: %w", remote, err)
	}
	defer rf.Close()
	start := time.Now()
	n, err := io.Copy(rf, lf)
	if err != nil {
		return fmt.Errorf("copy %s -> %s: %w", local, remote, err)
	}
	fmt.Fprintf(os.Stderr, "%s[sshmgr]%s %s%s%s -> %s%s%s  (%s, %s)\n", theme.ANSI(theme.Current.Primary), theme.Reset(), theme.ANSI(theme.Current.AccentB), local, theme.Reset(), theme.ANSI(theme.Current.AccentB), remote, theme.Reset(), formatBytes(n), time.Since(start).Round(time.Millisecond))
	logXfer("up", alias, local, remote, n)
	return nil
}

func uploadDir(sc *sftp.Client, local, remote, alias string) error {
	if err := sc.MkdirAll(remote); err != nil {
		return fmt.Errorf("remote mkdir %s: %w", remote, err)
	}
	entries, err := os.ReadDir(local)
	if err != nil {
		return err
	}
	for _, e := range entries {
		lname := filepath.Join(local, e.Name())
		rname := path(remote, e.Name())
		if e.IsDir() {
			if err := uploadDir(sc, lname, rname, alias); err != nil {
				return err
			}
			continue
		}
		if err := uploadFile(sc, lname, rname, alias); err != nil {
			return err
		}
	}
	return nil
}

// splitRemote tells whether spec is of the form "alias:/path". Returns
// (alias, path, true) if so, ("", spec, false) otherwise.
func splitRemote(spec string) (string, string, bool) {
	// alias must be a single token without slashes; first colon is the separator.
	idx := strings.IndexByte(spec, ':')
	if idx <= 0 {
		return "", spec, false
	}
	if strings.ContainsAny(spec[:idx], "/\\") {
		return "", spec, false
	}
	return spec[:idx], spec[idx+1:], true
}

// path joins remote path components with forward slashes (SFTP uses POSIX paths
// regardless of the local OS).
func path(parts ...string) string {
	s := strings.Join(parts, "/")
	// Collapse repeated slashes.
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	return s
}

// HumanBytes formats a byte count with KiB/MiB/GiB suffix. Exported so the
// TUI and CLI can share one implementation.
func HumanBytes(n int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.2f GiB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.2f MiB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.2f KiB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// formatBytes is kept as a local alias for the existing call sites inside
// this package.
func formatBytes(n int64) string { return HumanBytes(n) }
