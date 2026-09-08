// Package cloudprofile stores non-secret sshmgr Cloud profile metadata.
// Bearer tokens remain exclusively in the OS keyring referenced by each
// profile; this file never contains token values.
package cloudprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/systeampl/sshmgr/internal/cloudclient"
	"golang.org/x/sys/unix"
)

const (
	SchemaVersion      = "1"
	maxConfigFileBytes = 1 << 20
)

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type Config struct {
	SchemaVersion string             `json:"schema_version"`
	ActiveProfile string             `json:"active_profile,omitempty"`
	Profiles      map[string]Profile `json:"profiles"`
}

type Profile struct {
	Endpoint              string `json:"endpoint"`
	Workspace             string `json:"workspace,omitempty"`
	Organization          string `json:"organization,omitempty"`
	Project               string `json:"project,omitempty"`
	TokenKeyring          string `json:"token_keyring"`
	AllowInsecureLoopback bool   `json:"allow_insecure_loopback,omitempty"`
}

// UsesProjectContext reports whether the profile addresses the v2 runner API
// through explicit organization/project fields instead of the legacy
// workspace field.
func (p Profile) UsesProjectContext() bool {
	return p.Organization != "" && p.Project != ""
}

func NewConfig() *Config {
	return &Config{SchemaVersion: SchemaVersion, Profiles: map[string]Profile{}}
}

// Path resolves the Cloud profile file independently from the SSH inventory.
func Path() (string, error) {
	if value := strings.TrimSpace(os.Getenv("SSHMGR_CLOUD_CONFIG")); value != "" {
		return expandHome(value), nil
	}
	if base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); base != "" {
		return filepath.Join(base, "sshmgr", "cloud.json"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(base, "sshmgr", "cloud.json"), nil
}

func Load() (*Config, string, error) {
	path, err := Path()
	if err != nil {
		return nil, "", err
	}
	config, err := read(path)
	return config, path, err
}

// Update serializes profile mutations across processes and atomically writes
// a mode-0600 JSON file after full validation.
func Update(mutate func(*Config) error) (string, error) {
	return UpdateWithRollback(mutate, nil)
}

// UpdateWithRollback coordinates a profile write with an external operation
// such as storing a credential. prepare runs after validation, under the profile
// lock. Its rollback runs under the same lock if publishing the file fails.
// This handles returned errors, not process crashes or power loss.
func UpdateWithRollback(mutate func(*Config) error, prepare func() (rollback func() error, err error)) (string, error) {
	if mutate == nil {
		return "", errors.New("Cloud profile update is nil")
	}
	path, err := Path()
	if err != nil {
		return "", err
	}
	err = withFileLock(path, func() error {
		config, readErr := read(path)
		if readErr != nil {
			return readErr
		}
		if mutateErr := mutate(config); mutateErr != nil {
			return mutateErr
		}
		if validateErr := Validate(config); validateErr != nil {
			return validateErr
		}
		var rollback func() error
		if prepare != nil {
			var prepareErr error
			rollback, prepareErr = prepare()
			if prepareErr != nil {
				return prepareErr
			}
		}
		if writeErr := write(path, config); writeErr != nil {
			if rollback != nil {
				if rollbackErr := rollback(); rollbackErr != nil {
					return errors.Join(writeErr, fmt.Errorf("credential rollback failed: %w", rollbackErr))
				}
			}
			return writeErr
		}
		return nil
	})
	return path, err
}

func Resolve(config *Config, requested string) (string, Profile, error) {
	if err := Validate(config); err != nil {
		return "", Profile{}, err
	}
	name := strings.TrimSpace(requested)
	if name == "" {
		name = config.ActiveProfile
	}
	if name == "" {
		return "", Profile{}, errors.New("no active Cloud profile; run `sshmgr cloud login PROFILE ...`")
	}
	profile, ok := config.Profiles[name]
	if !ok {
		return "", Profile{}, fmt.Errorf("Cloud profile %q does not exist", name)
	}
	return name, profile, nil
}

func Upsert(config *Config, name string, profile Profile, activate bool) error {
	name = strings.TrimSpace(name)
	if !namePattern.MatchString(name) {
		return errors.New("Cloud profile name must be a lowercase slug of at most 64 characters")
	}
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}
	config.Profiles[name] = profile
	if activate || config.ActiveProfile == "" {
		config.ActiveProfile = name
	}
	return Validate(config)
}

func SetActive(config *Config, name string) error {
	name = strings.TrimSpace(name)
	if _, ok := config.Profiles[name]; !ok {
		return fmt.Errorf("Cloud profile %q does not exist", name)
	}
	config.ActiveProfile = name
	return Validate(config)
}

func SetWorkspace(config *Config, name, workspace string) error {
	name, profile, err := Resolve(config, name)
	if err != nil {
		return err
	}
	if profile.UsesProjectContext() {
		return fmt.Errorf("Cloud profile %q uses organization/project context; run `sshmgr cloud project set` instead", name)
	}
	profile.Workspace = strings.TrimSpace(workspace)
	config.Profiles[name] = profile
	return Validate(config)
}

// SetProject migrates the selected profile to explicit organization/project
// context; the legacy workspace field is cleared so exactly one context
// remains.
func SetProject(config *Config, name, organization, project string) error {
	name, profile, err := Resolve(config, name)
	if err != nil {
		return err
	}
	profile.Organization = strings.TrimSpace(organization)
	profile.Project = strings.TrimSpace(project)
	profile.Workspace = ""
	config.Profiles[name] = profile
	return Validate(config)
}

func TokenKey(profileName string) string {
	return "sshmgr-cloud:" + strings.TrimSpace(profileName)
}

func Validate(config *Config) error {
	if config == nil {
		return errors.New("Cloud profile config is nil")
	}
	if config.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported Cloud profile schema_version %q", config.SchemaVersion)
	}
	if config.Profiles == nil {
		return errors.New("Cloud profile config requires a profiles object")
	}
	if len(config.Profiles) == 0 {
		if config.ActiveProfile != "" {
			return errors.New("active Cloud profile exists without profiles")
		}
		return nil
	}
	if !namePattern.MatchString(config.ActiveProfile) {
		return errors.New("active Cloud profile is invalid")
	}
	if _, ok := config.Profiles[config.ActiveProfile]; !ok {
		return errors.New("active Cloud profile does not exist")
	}
	for name, profile := range config.Profiles {
		if !namePattern.MatchString(name) {
			return fmt.Errorf("Cloud profile name %q is invalid", name)
		}
		normalized, err := cloudclient.NormalizeEndpoint(profile.Endpoint, profile.AllowInsecureLoopback)
		if err != nil {
			return fmt.Errorf("Cloud profile %q endpoint: %w", name, err)
		}
		if normalized != profile.Endpoint {
			return fmt.Errorf("Cloud profile %q endpoint is not canonical", name)
		}
		hasWorkspace := profile.Workspace != ""
		hasOrganization := profile.Organization != ""
		hasProject := profile.Project != ""
		switch {
		case hasOrganization != hasProject:
			return fmt.Errorf("Cloud profile %q requires organization and project together", name)
		case hasWorkspace && hasOrganization:
			return fmt.Errorf("Cloud profile %q must use either the legacy workspace or organization/project, not both", name)
		case !hasWorkspace && !hasOrganization:
			return fmt.Errorf("Cloud profile %q requires a workspace or organization/project", name)
		case hasWorkspace && !namePattern.MatchString(profile.Workspace):
			return fmt.Errorf("Cloud profile %q workspace is invalid", name)
		case hasOrganization && !namePattern.MatchString(profile.Organization):
			return fmt.Errorf("Cloud profile %q organization is invalid", name)
		case hasProject && !namePattern.MatchString(profile.Project):
			return fmt.Errorf("Cloud profile %q project is invalid", name)
		}
		if !validKeyringName(profile.TokenKeyring) {
			return fmt.Errorf("Cloud profile %q token_keyring is invalid", name)
		}
	}
	return nil
}

func read(path string) (*Config, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Cloud profile config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxConfigFileBytes {
		return nil, errors.New("Cloud profile config must be a private regular non-symlink file of at most 1 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Cloud profile config: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Cloud profile config changed during open or is not private")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Cloud profile config: %w", err)
	}
	if len(data) > maxConfigFileBytes {
		return nil, errors.New("Cloud profile config exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse Cloud profile config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("Cloud profile config contains trailing JSON")
	}
	if err := Validate(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func write(path string, config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Cloud profile config: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxConfigFileBytes {
		return errors.New("Cloud profile config exceeds 1 MiB")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Cloud profile config directory: %w", err)
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("Cloud profile config target must be a regular non-symlink file")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect Cloud profile config target: %w", statErr)
	}
	temporary, err := os.CreateTemp(directory, ".sshmgr-cloud-profile-*")
	if err != nil {
		return fmt.Errorf("create Cloud profile config: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("publish Cloud profile config: %w", err)
	}
	if handle, err := os.Open(directory); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

func withFileLock(path string, operation func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open Cloud profile lock: %w", err)
	}
	defer lock.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
			return operation()
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("acquire Cloud profile lock: %w", err)
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for Cloud profile lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func validKeyringName(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) }) < 0
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
