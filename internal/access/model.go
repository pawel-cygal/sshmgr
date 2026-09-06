// Package access implements read-only SSH access inventory snapshots.
package access

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

const SchemaVersion = "1"

const (
	CoverageFull    = "full"
	CoveragePartial = "partial"
	CoverageFailed  = "failed"
)

// Snapshot is the versioned, local audit artifact produced by access scan.
// It intentionally contains no SSH credentials or private-key material.
type Snapshot struct {
	SchemaVersion  string         `json:"schema_version"`
	ScanID         string         `json:"scan_id"`
	SourceScanIDs  []string       `json:"source_scan_ids,omitempty"`
	ScannerVersion string         `json:"scanner_version,omitempty"`
	StartedAt      string         `json:"started_at"`
	CompletedAt    string         `json:"completed_at"`
	Scope          Scope          `json:"scope"`
	Summary        Summary        `json:"summary"`
	Findings       []Finding      `json:"findings,omitempty"`
	Hosts          []HostSnapshot `json:"hosts"`
}

type Scope struct {
	Mode                 string   `json:"mode"`
	Selector             string   `json:"selector"`
	RequestedHosts       int      `json:"requested_hosts"`
	AccountMode          string   `json:"account_mode,omitempty"`
	RequestedAccounts    []string `json:"requested_accounts,omitempty"`
	MaxAccounts          int      `json:"max_accounts,omitempty"`
	MaxSourceBytes       int64    `json:"max_source_bytes,omitempty"`
	MaxTotalSourceBytes  int64    `json:"max_total_source_bytes,omitempty"`
	HostExclusions       []string `json:"host_exclusions,omitempty"`
	TagExclusions        []string `json:"tag_exclusions,omitempty"`
	ExcludedMatchedHosts []string `json:"excluded_matched_hosts,omitempty"`
	Preflight            bool     `json:"preflight,omitempty"`
	IncludePublicKeys    bool     `json:"include_public_keys"`
}

type Summary struct {
	HostsRequested       int   `json:"hosts_requested"`
	HostsFull            int   `json:"hosts_full"`
	HostsPartial         int   `json:"hosts_partial"`
	HostsFailed          int   `json:"hosts_failed"`
	AccountsObserved     int   `json:"accounts_observed"`
	KeySourcesFound      int   `json:"key_sources_found"`
	AuthorizedKeyEntries int   `json:"authorized_key_entries"`
	MalformedEntries     int   `json:"malformed_entries"`
	KeyBytesInspected    int64 `json:"key_bytes_inspected"`
	UniqueFingerprints   int   `json:"unique_fingerprints"`
	FindingsTotal        int   `json:"findings_total"`
	FindingsCritical     int   `json:"findings_critical"`
	FindingsHigh         int   `json:"findings_high"`
	FindingsMedium       int   `json:"findings_medium"`
	FindingsLow          int   `json:"findings_low"`
	FindingsInfo         int   `json:"findings_info"`
}

type HostSnapshot struct {
	Alias       string            `json:"alias"`
	Groups      []string          `json:"groups,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Coverage    string            `json:"coverage"`
	Limitations []string          `json:"limitations,omitempty"`
	System      *SystemSnapshot   `json:"system,omitempty"`
	Accounts    []AccountSnapshot `json:"accounts,omitempty"`
	Errors      []ScanError       `json:"errors,omitempty"`
	DurationMS  int64             `json:"duration_ms"`
}

// SystemSnapshot records non-secret host capabilities and effective OpenSSH
// authentication sources discovered during a privileged system preflight.
// It contains no key contents, credentials, or executed script text.
type SystemSnapshot struct {
	PrivilegeMode      string             `json:"privilege_mode"`
	Root               bool               `json:"root"`
	SudoNonInteractive bool               `json:"sudo_non_interactive,omitempty"`
	OS                 string             `json:"os,omitempty"`
	AccountDatabase    string             `json:"account_database,omitempty"`
	AccountMode        string             `json:"account_mode,omitempty"`
	AccountsEnumerated bool               `json:"accounts_enumerated"`
	AccountsTruncated  bool               `json:"accounts_truncated"`
	AccountLimit       int                `json:"account_limit,omitempty"`
	MissingAccounts    []string           `json:"missing_accounts,omitempty"`
	SourcesRequested   int                `json:"sources_requested,omitempty"`
	SourcesInspected   int                `json:"sources_inspected,omitempty"`
	SourceBytesRead    int64              `json:"source_bytes_read,omitempty"`
	SourcesTruncated   bool               `json:"sources_truncated,omitempty"`
	ContentBudgetHit   bool               `json:"content_budget_hit,omitempty"`
	SSHD               SSHDConfigSnapshot `json:"sshd"`
}

type SSHDConfigSnapshot struct {
	Present                     bool     `json:"present"`
	Path                        string   `json:"path,omitempty"`
	ConfigValid                 bool     `json:"config_valid"`
	EffectiveConfig             bool     `json:"effective_config"`
	EffectiveUser               string   `json:"effective_user,omitempty"`
	MatchHost                   string   `json:"match_host,omitempty"`
	MatchAddress                string   `json:"match_address,omitempty"`
	PubkeyAuthentication        string   `json:"pubkey_authentication,omitempty"`
	StrictModes                 string   `json:"strict_modes,omitempty"`
	AuthorizedKeysFiles         []string `json:"authorized_keys_files,omitempty"`
	AuthorizedKeysCommand       string   `json:"authorized_keys_command,omitempty"`
	AuthorizedKeysCommandUser   string   `json:"authorized_keys_command_user,omitempty"`
	TrustedUserCAKeys           string   `json:"trusted_user_ca_keys,omitempty"`
	AuthorizedPrincipalsFile    string   `json:"authorized_principals_file,omitempty"`
	AuthorizedPrincipalsCommand string   `json:"authorized_principals_command,omitempty"`
}

type AccountSnapshot struct {
	Username    string               `json:"username"`
	UID         *uint64              `json:"uid,omitempty"`
	GID         *uint64              `json:"gid,omitempty"`
	Home        string               `json:"home,omitempty"`
	Shell       string               `json:"shell,omitempty"`
	Auth        *AccountAuthSnapshot `json:"auth,omitempty"`
	Limitations []string             `json:"limitations,omitempty"`
	Sources     []KeySource          `json:"sources,omitempty"`
}

// AccountAuthSnapshot records the effective sshd authentication configuration
// for one OS account. Paths are configured templates; AccountSnapshot.Sources
// contains their safely expanded absolute forms.
type AccountAuthSnapshot struct {
	EffectiveConfig             bool     `json:"effective_config"`
	PubkeyAuthentication        string   `json:"pubkey_authentication,omitempty"`
	StrictModes                 string   `json:"strict_modes,omitempty"`
	AuthorizedKeysFiles         []string `json:"authorized_keys_files,omitempty"`
	AuthorizedKeysCommand       string   `json:"authorized_keys_command,omitempty"`
	AuthorizedKeysCommandUser   string   `json:"authorized_keys_command_user,omitempty"`
	TrustedUserCAKeys           string   `json:"trusted_user_ca_keys,omitempty"`
	AuthorizedPrincipalsFile    string   `json:"authorized_principals_file,omitempty"`
	AuthorizedPrincipalsCommand string   `json:"authorized_principals_command,omitempty"`
}

type KeySource struct {
	Type             string `json:"type"`
	Path             string `json:"path"`
	ConfiguredPath   string `json:"configured_path,omitempty"`
	Exists           bool   `json:"exists"`
	Symlink          bool   `json:"symlink,omitempty"`
	ContentInspected bool   `json:"content_inspected"`
	// ContentSHA256 binds deployment plans to the exact bytes observed by the
	// read-only scan. Raw key contents remain omitted unless explicitly asked.
	ContentSHA256   string           `json:"content_sha256,omitempty"`
	Mode            string           `json:"mode,omitempty"`
	Size            int64            `json:"size,omitempty"`
	OwnerUID        *uint64          `json:"owner_uid,omitempty"`
	OwnerGID        *uint64          `json:"owner_gid,omitempty"`
	ParentPath      string           `json:"parent_path,omitempty"`
	ParentMode      string           `json:"parent_mode,omitempty"`
	ParentOwnerUID  *uint64          `json:"parent_owner_uid,omitempty"`
	ParentOwnerGID  *uint64          `json:"parent_owner_gid,omitempty"`
	AncestorSymlink bool             `json:"ancestor_symlink,omitempty"`
	Entries         []KeyObservation `json:"entries,omitempty"`
	Error           string           `json:"error,omitempty"`
}

func ContentDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "SHA256:" + hex.EncodeToString(digest[:])
}

type KeyObservation struct {
	Line        int      `json:"line"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Algorithm   string   `json:"algorithm,omitempty"`
	Bits        int      `json:"bits,omitempty"`
	Options     []string `json:"options,omitempty"`
	Comment     string   `json:"comment,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ParseError  string   `json:"parse_error,omitempty"`
}

type ScanError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// NewSnapshot creates a scan envelope. Call Finalize after all host results
// have been populated.
func NewSnapshot(scannerVersion string, scope Scope, started time.Time) *Snapshot {
	return &Snapshot{
		SchemaVersion:  SchemaVersion,
		ScanID:         newScanID(),
		ScannerVersion: scannerVersion,
		StartedAt:      started.UTC().Format(time.RFC3339Nano),
		Scope:          scope,
	}
}

func newScanID() string {
	var random [12]byte
	if _, err := rand.Read(random[:]); err == nil {
		return "scan_" + hex.EncodeToString(random[:])
	}
	// crypto/rand failure is extraordinarily rare. A timestamp still leaves a
	// useful local identifier without turning scan creation into a mutation.
	return "scan_" + time.Now().UTC().Format("20060102T150405.000000000")
}

// Finalize sorts the normalized snapshot and derives all summary counters.
func (s *Snapshot) Finalize(completed time.Time) {
	s.CompletedAt = completed.UTC().Format(time.RFC3339Nano)
	s.Scope.RequestedHosts = len(s.Hosts)
	s.Summary = Summary{HostsRequested: len(s.Hosts)}
	fingerprints := map[string]struct{}{}

	sort.Slice(s.Hosts, func(i, j int) bool { return s.Hosts[i].Alias < s.Hosts[j].Alias })
	for hi := range s.Hosts {
		h := &s.Hosts[hi]
		sort.Strings(h.Groups)
		sort.Strings(h.Tags)
		sort.Strings(h.Limitations)
		sort.Slice(h.Accounts, func(i, j int) bool { return h.Accounts[i].Username < h.Accounts[j].Username })
		switch h.Coverage {
		case CoverageFull:
			s.Summary.HostsFull++
		case CoverageFailed:
			s.Summary.HostsFailed++
		default:
			s.Summary.HostsPartial++
		}
		for ai := range h.Accounts {
			a := &h.Accounts[ai]
			s.Summary.AccountsObserved++
			sort.Strings(a.Limitations)
			sort.Slice(a.Sources, func(i, j int) bool { return a.Sources[i].Path < a.Sources[j].Path })
			for si := range a.Sources {
				source := &a.Sources[si]
				if source.Exists {
					s.Summary.KeySourcesFound++
				}
				if source.ContentInspected {
					s.Summary.KeyBytesInspected += source.Size
				}
				sort.Slice(source.Entries, func(i, j int) bool { return source.Entries[i].Line < source.Entries[j].Line })
				for _, entry := range source.Entries {
					if entry.ParseError != "" {
						s.Summary.MalformedEntries++
						continue
					}
					s.Summary.AuthorizedKeyEntries++
					if entry.Fingerprint != "" {
						fingerprints[entry.Fingerprint] = struct{}{}
					}
				}
			}
		}
	}
	s.Summary.UniqueFingerprints = len(fingerprints)
	s.Findings = Analyze(s)
	for _, finding := range s.Findings {
		s.Summary.FindingsTotal++
		switch finding.Severity {
		case SeverityCritical:
			s.Summary.FindingsCritical++
		case SeverityHigh:
			s.Summary.FindingsHigh++
		case SeverityMedium:
			s.Summary.FindingsMedium++
		case SeverityLow:
			s.Summary.FindingsLow++
		default:
			s.Summary.FindingsInfo++
		}
	}
}
