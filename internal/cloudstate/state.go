// Package cloudstate manages private, per-project evidence state used by the
// one-command Cloud push workflow. It never stores bearer tokens or SSH
// connection credentials.
package cloudstate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/internal/access"
	"golang.org/x/sys/unix"
)

const defaultLockTimeout = 5 * time.Second

var (
	slugPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	artifactPattern = regexp.MustCompile(`^(?:plan|bundle)_[a-f0-9]{24}$`)
)

// Context identifies one isolated local history. Scope is normally a Cloud
// profile name; manual CLI uploads use a stable endpoint-derived scope.
type Context struct {
	Scope        string
	Organization string
	Project      string
	Workspace    string
}

type Paths struct {
	Root    string
	Plans   string
	History string
	Bundles string
	Lock    string
	Context Context
}

type ArtifactPaths struct {
	Plan    string
	History string
	Bundle  string
}

type Lock struct {
	file *os.File
}

// ManualScope prevents two manual endpoints with identical tenant slugs from
// sharing local history while keeping endpoint text out of directory names.
func ManualScope(endpoint string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(endpoint)))
	return "manual-" + hex.EncodeToString(digest[:6])
}

// Resolve returns deterministic paths without creating anything.
func Resolve(context Context) (Paths, error) {
	context.Scope = strings.TrimSpace(context.Scope)
	context.Organization = strings.TrimSpace(context.Organization)
	context.Project = strings.TrimSpace(context.Project)
	context.Workspace = strings.TrimSpace(context.Workspace)
	if !slugPattern.MatchString(context.Scope) {
		return Paths{}, errors.New("Cloud state scope must be a lowercase slug of at most 64 characters")
	}
	projectContext := context.Organization != "" || context.Project != ""
	if (context.Organization == "") != (context.Project == "") {
		return Paths{}, errors.New("Cloud state organization and project are required together")
	}
	if projectContext == (context.Workspace != "") {
		return Paths{}, errors.New("Cloud state requires either organization/project or a legacy workspace")
	}
	for label, value := range map[string]string{"organization": context.Organization, "project": context.Project, "workspace": context.Workspace} {
		if value != "" && !slugPattern.MatchString(value) {
			return Paths{}, fmt.Errorf("Cloud state %s is not a valid lowercase slug", label)
		}
	}
	base, err := baseDirectory()
	if err != nil {
		return Paths{}, err
	}
	parts := []string{base, context.Scope}
	if projectContext {
		parts = append(parts, context.Organization, context.Project)
	} else {
		parts = append(parts, "legacy", context.Workspace)
	}
	root := filepath.Join(parts...)
	return Paths{
		Root: root, Plans: filepath.Join(root, "upload-plans"), History: filepath.Join(root, "history.json"),
		Bundles: filepath.Join(root, "bundles"), Lock: filepath.Join(root, ".push.lock"), Context: context,
	}, nil
}

func baseDirectory() (string, error) {
	var base string
	if value := strings.TrimSpace(os.Getenv("SSHMGR_CLOUD_STATE")); value != "" {
		base = expandHome(value)
	} else if value := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); value != "" {
		base = filepath.Join(value, "sshmgr", "cloud")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory for Cloud state: %w", err)
		}
		base = filepath.Join(home, ".local", "state", "sshmgr", "cloud")
	}
	absolute, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolve Cloud state directory: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

// Acquire serializes pushes for one local project state. The lock may be held
// across the bounded upload so two processes cannot publish divergent local
// histories.
func Acquire(paths Paths) (*Lock, error) {
	if err := ensurePrivateDirectory(paths.Root); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(paths.Lock); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("Cloud state lock must be a private regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Cloud state lock: %w", err)
	}
	file, err := os.OpenFile(paths.Lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open Cloud state lock: %w", err)
	}
	deadline := time.Now().Add(defaultLockTimeout)
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &Lock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire Cloud project state lock: %w", err)
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, errors.New("timed out waiting for Cloud project state lock; another push may still be running")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

// LoadHistory returns nil for the first push and fails closed on an unsafe or
// corrupted state file.
func LoadHistory(paths Paths) (*access.WorkspaceHistory, error) {
	info, err := os.Lstat(paths.History)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Cloud project history: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Cloud project history must be a private regular non-symlink file")
	}
	history, err := access.ReadWorkspaceHistory(paths.History)
	if err != nil {
		return nil, err
	}
	if history.Workspace != contextProject(paths.Context) {
		return nil, fmt.Errorf("Cloud project history workspace %q does not match state context %q", history.Workspace, contextProject(paths.Context))
	}
	return history, nil
}

// Commit publishes content-addressed artifacts first and history last. If a
// process stops between writes, the previous history remains valid and the
// same push can be retried idempotently.
func Commit(paths Paths, plan *access.UploadPlan, history *access.WorkspaceHistory, bundle *access.WorkspaceBundle) (ArtifactPaths, error) {
	if err := access.ValidateUploadPlan(plan); err != nil {
		return ArtifactPaths{}, err
	}
	if err := access.ValidateWorkspaceHistory(history); err != nil {
		return ArtifactPaths{}, err
	}
	if err := access.ValidateWorkspaceBundle(bundle); err != nil {
		return ArtifactPaths{}, err
	}
	workspace := contextProject(paths.Context)
	if plan.Workspace != workspace || history.Workspace != workspace || bundle.Workspace != workspace {
		return ArtifactPaths{}, errors.New("Cloud push artifacts do not match the project state context")
	}
	if !reflect.DeepEqual(bundle.Payload.WorkspaceHistory, *history) {
		return ArtifactPaths{}, errors.New("Cloud push bundle does not embed the candidate project history")
	}
	foundPlan := false
	for index := range history.Plans {
		if reflect.DeepEqual(&history.Plans[index], plan) {
			foundPlan = true
			break
		}
	}
	if !foundPlan {
		return ArtifactPaths{}, errors.New("Cloud push history does not contain the candidate upload plan")
	}
	if !artifactPattern.MatchString(plan.PlanID) || !artifactPattern.MatchString(bundle.BundleID) {
		return ArtifactPaths{}, errors.New("Cloud push artifact ID is unsafe for local state")
	}
	if err := ensurePrivateDirectory(paths.Plans); err != nil {
		return ArtifactPaths{}, err
	}
	if err := ensurePrivateDirectory(paths.Bundles); err != nil {
		return ArtifactPaths{}, err
	}
	result := ArtifactPaths{
		Plan: filepath.Join(paths.Plans, plan.PlanID+".json"), History: paths.History,
		Bundle: filepath.Join(paths.Bundles, bundle.BundleID+".json"),
	}
	if err := access.WriteUploadPlan(result.Plan, plan); err != nil {
		return ArtifactPaths{}, fmt.Errorf("commit Cloud upload plan: %w", err)
	}
	if err := access.WriteWorkspaceBundle(result.Bundle, bundle); err != nil {
		return ArtifactPaths{}, fmt.Errorf("commit Cloud ingestion bundle: %w", err)
	}
	if err := access.WriteWorkspaceHistory(result.History, history); err != nil {
		return ArtifactPaths{}, fmt.Errorf("commit Cloud project history: %w", err)
	}
	return result, nil
}

func contextProject(context Context) string {
	if context.Project != "" {
		return context.Project
	}
	return context.Workspace
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private Cloud state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Cloud state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Cloud state directory must be a private non-symlink directory")
	}
	return nil
}
