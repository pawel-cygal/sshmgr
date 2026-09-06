// Package projectstate owns sshmgr's private, per-project local state.
//
// The state is deliberately separate from the inventory and Cloud runner
// credentials. Audits, deployment plans, and receipts are private local
// artifacts; only an explicit Cloud push may transmit a redacted bundle.
package projectstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/accessplan"
	"github.com/systeampl/sshmgr/internal/cloudprofile"
	"github.com/systeampl/sshmgr/internal/provision"
)

var safeComponent = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type Context struct {
	Organization string
	Project      string
}

type Paths struct {
	Root     string
	Audits   string
	Plans    string
	Receipts string
	Latest   string
	Context  Context
}

type auditItem struct{ path, completed string }

// ActiveContext resolves the human-facing project context. Explicit
// environment values are useful for offline/CI use; otherwise the active
// Cloud profile supplies the context. A local default keeps audits useful
// before Cloud is configured without inventing a network dependency.
func ActiveContext() Context {
	organization := strings.TrimSpace(os.Getenv("SSHMGR_ORGANIZATION"))
	project := strings.TrimSpace(os.Getenv("SSHMGR_PROJECT"))
	if organization != "" && project != "" {
		return Context{Organization: organization, Project: project}
	}
	profiles, _, err := cloudprofile.Load()
	if err == nil {
		_, profile, resolveErr := cloudprofile.Resolve(profiles, "")
		if resolveErr == nil {
			if profile.UsesProjectContext() {
				return Context{Organization: profile.Organization, Project: profile.Project}
			}
			if profile.Workspace != "" {
				return Context{Organization: "legacy", Project: profile.Workspace}
			}
		}
	}
	return Context{Organization: "local", Project: "default"}
}

func Resolve(context Context) (Paths, error) {
	context.Organization = strings.TrimSpace(context.Organization)
	context.Project = strings.TrimSpace(context.Project)
	if !safeComponent.MatchString(context.Organization) || !safeComponent.MatchString(context.Project) {
		return Paths{}, errors.New("project state organization and project must be lowercase slugs")
	}
	base, err := baseDirectory()
	if err != nil {
		return Paths{}, err
	}
	root := filepath.Join(base, "projects", context.Organization, context.Project)
	return Paths{
		Root: root, Audits: filepath.Join(root, "audits"), Plans: filepath.Join(root, "plans"),
		Receipts: filepath.Join(root, "receipts"), Latest: filepath.Join(root, "latest"), Context: context,
	}, nil
}

func ResolveActive() (Paths, error) { return Resolve(ActiveContext()) }

func baseDirectory() (string, error) {
	var base string
	if value := strings.TrimSpace(os.Getenv("SSHMGR_CLOUD_STATE")); value != "" {
		base = expandHome(value)
	} else if value := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); value != "" {
		base = filepath.Join(value, "sshmgr")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory for sshmgr state: %w", err)
		}
		base = filepath.Join(home, ".local", "state", "sshmgr")
	}
	absolute, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolve sshmgr state directory: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func expandHome(value string) string {
	if value == "~" || strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if value == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	return value
}

// StoreAudit writes an immutable snapshot and atomically advances latest.
// A repeated scan ID is accepted only when its canonical bytes are identical.
func StoreAudit(paths Paths, snapshot *access.Snapshot) (string, error) {
	return storeAudit(paths, snapshot, true)
}

func StorePostScan(paths Paths, snapshot *access.Snapshot) (string, error) {
	return storeAudit(paths, snapshot, false)
}

func storeAudit(paths Paths, snapshot *access.Snapshot, advanceLatest bool) (string, error) {
	if snapshot == nil || !regexp.MustCompile(`^scan_[A-Za-z0-9._-]+$`).MatchString(snapshot.ScanID) {
		return "", errors.New("audit has an invalid scan ID")
	}
	if err := ensurePrivateDirectory(paths.Root); err != nil {
		return "", err
	}
	if err := ensurePrivateDirectory(paths.Audits); err != nil {
		return "", err
	}
	target := filepath.Join(paths.Audits, snapshot.ScanID+".json")
	if existing, err := access.ReadSnapshot(target); err == nil {
		left, _ := renderSnapshot(existing)
		right, _ := renderSnapshot(snapshot)
		if !bytes.Equal(left, right) {
			return "", errors.New("immutable audit ID already exists with different content")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else if err := access.WriteSnapshot(target, snapshot); err != nil {
		return "", err
	}
	if advanceLatest {
		if err := writePrivateAtomic(paths.Latest, []byte(snapshot.ScanID+"\n")); err != nil {
			return "", fmt.Errorf("update latest audit pointer: %w", err)
		}
	}
	return target, nil
}

func StorePlan(paths Paths, plan *accessplan.Plan) (string, error) {
	if err := accessplan.Validate(plan, time.Time{}); err != nil {
		return "", err
	}
	if err := ensurePrivateDirectory(paths.Plans); err != nil {
		return "", err
	}
	target := filepath.Join(paths.Plans, plan.PlanID+".json")
	if existing, err := accessplan.Read(target); err == nil {
		if existing.Digest != plan.Digest {
			return "", errors.New("immutable plan ID already exists with different content")
		}
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := accessplan.Write(target, plan); err != nil {
		return "", err
	}
	return target, nil
}

func StoreReceipt(paths Paths, receipt *provision.Receipt) (string, error) {
	if receipt == nil || receipt.PlanID == "" || receipt.PlanDigest == "" || receipt.CompletedAt == "" {
		return "", errors.New("provisioning receipt is incomplete")
	}
	if err := ensurePrivateDirectory(paths.Receipts); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	digest := sha256.Sum256(data)
	target := filepath.Join(paths.Receipts, receipt.PlanID+"-"+hex.EncodeToString(digest[:6])+".json")
	if existing, err := os.ReadFile(target); err == nil {
		if !bytes.Equal(existing, data) {
			return "", errors.New("immutable receipt path already exists with different content")
		}
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := writePrivateAtomic(target, data); err != nil {
		return "", err
	}
	return target, nil
}

// LatestAudit returns the path named by the private latest pointer.
func LatestAudit(paths Paths) (string, error) {
	data, err := readPrivateFile(paths.Latest, 256)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("no audit exists for the active project; run `sshmgr audit` first")
		}
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !regexp.MustCompile(`^scan_[A-Za-z0-9._-]+$`).MatchString(id) {
		return "", errors.New("latest audit pointer is invalid")
	}
	path := filepath.Join(paths.Audits, id+".json")
	if _, err := access.ReadSnapshot(path); err != nil {
		return "", fmt.Errorf("read latest audit: %w", err)
	}
	return path, nil
}

// RecentAudits returns newest-first immutable audit paths. Snapshot completion
// time is authoritative; file mtimes are not part of the audit model.
func RecentAudits(paths Paths) ([]string, error) {
	entries, err := os.ReadDir(paths.Audits)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list project audits: %w", err)
	}
	items := make([]auditItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "scan_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(paths.Audits, entry.Name())
		snapshot, readErr := access.ReadSnapshot(path)
		if readErr != nil {
			return nil, readErr
		}
		items = append(items, auditItem{path: path, completed: snapshot.CompletedAt})
	}
	sortItems(items)
	result := make([]string, len(items))
	for index := range items {
		result[index] = items[index].path
	}
	return result, nil
}

func sortItems(items []auditItem) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && (items[j].completed > items[j-1].completed || items[j].completed == items[j-1].completed && items[j].path > items[j-1].path); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func renderSnapshot(snapshot *access.Snapshot) ([]byte, error) {
	if err := access.ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private project state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("project state directory must be private and must not be a symlink")
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, ".sshmgr-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > limit {
		return nil, errors.New("project state file is not a bounded private regular file")
	}
	return os.ReadFile(path)
}
