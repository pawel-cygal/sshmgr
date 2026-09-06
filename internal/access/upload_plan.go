package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	UploadPlanSchemaVersion = "1"
	UploadArtifactType      = "access_snapshot"
	UploadPrivacyStandard   = "standard"
	maxUploadPayloadBytes   = 32 << 20
	maxUploadPlanBytes      = 40 << 20
)

var (
	workspaceSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	rawPublicKeyPattern  = regexp.MustCompile(`(?i)(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[a-z0-9@._+-]+|sk-(?:ssh-ed25519|ecdsa-sha2-[a-z0-9._+-]+)@openssh\.com)[[:space:]]+[a-z0-9+/]{16,}={0,3}`)
	credentialPattern    = regexp.MustCompile(`(?i)(password|passwd|passphrase|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)[[:space:]]*[:=][[:space:]]*['"]?[^,;[:space:]'"]{4,}`)
)

// UploadPlan is a deterministic, offline transport candidate. Creating or
// reading one performs no network operation. A later Cloud client may upload
// only an artifact that passes this validator.
type UploadPlan struct {
	SchemaVersion  string             `json:"schema_version"`
	PlanID         string             `json:"plan_id"`
	Workspace      string             `json:"workspace"`
	ArtifactType   string             `json:"artifact_type"`
	ArtifactID     string             `json:"artifact_id"`
	IdempotencyKey string             `json:"idempotency_key"`
	PayloadSHA256  string             `json:"payload_sha256"`
	PayloadBytes   int                `json:"payload_bytes"`
	Privacy        UploadPrivacy      `json:"privacy"`
	Preview        UploadFieldPreview `json:"preview"`
	Snapshot       Snapshot           `json:"snapshot"`
}

type UploadPrivacy struct {
	Profile               string `json:"profile"`
	HostAliasesIncluded   bool   `json:"host_aliases_included"`
	AccountNamesIncluded  bool   `json:"account_names_included"`
	SourcePathsIncluded   bool   `json:"source_paths_included"`
	IdentityHintsIncluded bool   `json:"identity_hints_included"`
	PublicKeysIncluded    bool   `json:"public_keys_included"`
	CredentialsIncluded   bool   `json:"credentials_included"`
}

// UploadFieldPreview is a count of potentially sensitive field values that
// are actually present in the embedded payload. It lets a human review the
// transport surface without inspecting raw public keys or credentials.
type UploadFieldPreview struct {
	Hosts              int `json:"hosts"`
	Accounts           int `json:"accounts"`
	AccessEntries      int `json:"access_entries"`
	UniqueFingerprints int `json:"unique_fingerprints"`
	Findings           int `json:"findings"`
	SelectorValues     int `json:"selector_values"`
	HostAliasRefs      int `json:"host_alias_references"`
	GroupNameRefs      int `json:"group_name_references"`
	TagNameRefs        int `json:"tag_name_references"`
	AccountNameRefs    int `json:"account_name_references"`
	FingerprintRefs    int `json:"fingerprint_references"`
	FilesystemPaths    int `json:"filesystem_paths"`
	ConfiguredCommands int `json:"configured_commands"`
	NetworkMatchValues int `json:"network_match_values"`
	AuthorizedKeyOpts  int `json:"authorized_key_options"`
	IdentityHints      int `json:"identity_hints"`
	DiagnosticTexts    int `json:"diagnostic_texts"`
	RawPublicKeys      int `json:"raw_public_keys"`
}

// BuildUploadPlan validates and clones a local snapshot, strips raw public-key
// material unconditionally, and strips unverified comments unless the caller
// explicitly opts in. It never mutates the input snapshot and never connects
// to a host or network service.
func BuildUploadPlan(snapshot *Snapshot, workspace string, includeIdentityHints bool) (*UploadPlan, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	workspace = strings.TrimSpace(workspace)
	if err := validateWorkspaceSlug(workspace); err != nil {
		return nil, err
	}
	clone, err := cloneSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	clone.Scope.IncludePublicKeys = false
	for hostIndex := range clone.Hosts {
		for accountIndex := range clone.Hosts[hostIndex].Accounts {
			for sourceIndex := range clone.Hosts[hostIndex].Accounts[accountIndex].Sources {
				entries := clone.Hosts[hostIndex].Accounts[accountIndex].Sources[sourceIndex].Entries
				for entryIndex := range entries {
					entries[entryIndex].PublicKey = ""
					if !includeIdentityHints {
						entries[entryIndex].Comment = ""
					}
				}
			}
		}
	}
	// Findings may quote evidence derived from comments (for example an
	// ambiguous_identity_hint). Recalculate the entire derived layer after
	// redaction so removed hints cannot survive indirectly in finding text.
	completedAt, err := time.Parse(time.RFC3339Nano, clone.CompletedAt)
	if err != nil {
		return nil, fmt.Errorf("build upload plan payload: parse completed_at: %w", err)
	}
	clone.Finalize(completedAt)
	if err := ValidateSnapshot(clone); err != nil {
		return nil, fmt.Errorf("build upload plan payload: %w", err)
	}
	payload, err := canonicalUploadPayload(clone)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxUploadPayloadBytes {
		return nil, fmt.Errorf("upload payload is %d bytes; offline plan limit is %d", len(payload), maxUploadPayloadBytes)
	}
	if err := rejectForbiddenUploadMaterial(payload); err != nil {
		return nil, err
	}
	payloadHash := sha256.Sum256(payload)
	payloadDigest := "SHA256:" + hex.EncodeToString(payloadHash[:])
	plan := &UploadPlan{
		SchemaVersion: UploadPlanSchemaVersion,
		Workspace:     workspace,
		ArtifactType:  UploadArtifactType,
		ArtifactID:    clone.ScanID,
		PayloadSHA256: payloadDigest,
		PayloadBytes:  len(payload),
		Privacy: UploadPrivacy{
			Profile: UploadPrivacyStandard, HostAliasesIncluded: true,
			AccountNamesIncluded: true, SourcePathsIncluded: true,
			IdentityHintsIncluded: includeIdentityHints,
			PublicKeysIncluded:    false, CredentialsIncluded: false,
		},
		Preview:  previewUploadFields(clone),
		Snapshot: *clone,
	}
	plan.IdempotencyKey = uploadIdempotencyKey(workspace, clone.ScanID)
	plan.PlanID = uploadPlanID(workspace, clone.ScanID, payloadDigest)
	if err := ValidateUploadPlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func ValidateUploadPlan(plan *UploadPlan) error {
	if plan == nil {
		return invalidUploadPlan("plan is nil")
	}
	if plan.SchemaVersion != UploadPlanSchemaVersion {
		return invalidUploadPlan("unsupported schema_version %q", plan.SchemaVersion)
	}
	if err := validateWorkspaceSlug(plan.Workspace); err != nil {
		return invalidUploadPlan("%v", err)
	}
	if plan.ArtifactType != UploadArtifactType || plan.ArtifactID == "" {
		return invalidUploadPlan("artifact_type must be %q and artifact_id is required", UploadArtifactType)
	}
	if err := ValidateSnapshot(&plan.Snapshot); err != nil {
		return invalidUploadPlan("snapshot: %v", err)
	}
	canonicalSnapshot, err := cloneSnapshot(&plan.Snapshot)
	if err != nil {
		return invalidUploadPlan("snapshot clone: %v", err)
	}
	completedAt, err := time.Parse(time.RFC3339Nano, canonicalSnapshot.CompletedAt)
	if err != nil {
		return invalidUploadPlan("snapshot completed_at: %v", err)
	}
	canonicalSnapshot.Finalize(completedAt)
	if !reflect.DeepEqual(canonicalSnapshot, &plan.Snapshot) {
		return invalidUploadPlan("embedded snapshot is not canonical or has stale derived findings")
	}
	if plan.ArtifactID != plan.Snapshot.ScanID {
		return invalidUploadPlan("artifact_id does not match snapshot scan_id")
	}
	if plan.Snapshot.Scope.IncludePublicKeys {
		return invalidUploadPlan("snapshot privacy flag permits public keys")
	}
	privacy := plan.Privacy
	if privacy.Profile != UploadPrivacyStandard || !privacy.HostAliasesIncluded || !privacy.AccountNamesIncluded || !privacy.SourcePathsIncluded || privacy.PublicKeysIncluded || privacy.CredentialsIncluded {
		return invalidUploadPlan("privacy contract is invalid")
	}
	payload, err := canonicalUploadPayload(&plan.Snapshot)
	if err != nil {
		return invalidUploadPlan("payload: %v", err)
	}
	if len(payload) > maxUploadPayloadBytes || plan.PayloadBytes != len(payload) {
		return invalidUploadPlan("payload_bytes does not reconcile or exceeds %d", maxUploadPayloadBytes)
	}
	if err := rejectForbiddenUploadMaterial(payload); err != nil {
		return invalidUploadPlan("%v", err)
	}
	payloadHash := sha256.Sum256(payload)
	digest := "SHA256:" + hex.EncodeToString(payloadHash[:])
	if plan.PayloadSHA256 != digest {
		return invalidUploadPlan("payload_sha256 does not match embedded snapshot")
	}
	if plan.IdempotencyKey != uploadIdempotencyKey(plan.Workspace, plan.ArtifactID) {
		return invalidUploadPlan("idempotency_key does not match workspace and artifact")
	}
	if plan.PlanID != uploadPlanID(plan.Workspace, plan.ArtifactID, digest) {
		return invalidUploadPlan("plan_id does not match its inputs")
	}
	preview := previewUploadFields(&plan.Snapshot)
	if plan.Preview != preview {
		return invalidUploadPlan("preview does not reconcile: got %+v, derived %+v", plan.Preview, preview)
	}
	if preview.RawPublicKeys != 0 {
		return invalidUploadPlan("raw public keys are forbidden in offline upload plans")
	}
	if !privacy.IdentityHintsIncluded && preview.IdentityHints != 0 {
		return invalidUploadPlan("identity hints are present without explicit opt-in")
	}
	return nil
}

func RenderUploadPlanJSON(plan *UploadPlan) ([]byte, error) {
	if err := ValidateUploadPlan(plan); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal upload plan: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxUploadPlanBytes {
		return nil, fmt.Errorf("upload plan is %d bytes; limit is %d", len(data), maxUploadPlanBytes)
	}
	return data, nil
}

func WriteUploadPlan(path string, plan *UploadPlan) error {
	data, err := RenderUploadPlanJSON(plan)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadUploadPlan(path string) (*UploadPlan, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open upload plan %s: %w", path, err)
	}
	defer file.Close()
	if stat, err := file.Stat(); err == nil && stat.Size() > maxUploadPlanBytes {
		return nil, fmt.Errorf("upload plan is %d bytes; limit is %d", stat.Size(), maxUploadPlanBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxUploadPlanBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read upload plan: %w", err)
	}
	if len(data) > maxUploadPlanBytes {
		return nil, fmt.Errorf("upload plan exceeds %d bytes", maxUploadPlanBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan UploadPlan
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("parse upload plan: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("upload plan contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing upload plan data: %w", err)
	}
	if err := ValidateUploadPlan(&plan); err != nil {
		return nil, err
	}
	return &plan, nil
}

func RenderUploadPlanText(plan *UploadPlan) string {
	if plan == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Offline Cloud upload plan  %s\n\n", plan.PlanID)
	fmt.Fprintf(&output, "Workspace:                 %s\n", plan.Workspace)
	fmt.Fprintf(&output, "Artifact:                  %s / %s\n", plan.ArtifactType, plan.ArtifactID)
	fmt.Fprintf(&output, "Idempotency key:           %s\n", plan.IdempotencyKey)
	fmt.Fprintf(&output, "Payload:                   %d bytes / %s\n", plan.PayloadBytes, plan.PayloadSHA256)
	fmt.Fprintln(&output, "Network activity:          none")
	fmt.Fprintln(&output, "\nFields in the candidate payload")
	fmt.Fprintf(&output, "  hosts / accounts / keys: %d / %d / %d\n", plan.Preview.Hosts, plan.Preview.Accounts, plan.Preview.UniqueFingerprints)
	fmt.Fprintf(&output, "  alias / account refs:    %d / %d\n", plan.Preview.HostAliasRefs, plan.Preview.AccountNameRefs)
	fmt.Fprintf(&output, "  selectors / key refs:    %d / %d\n", plan.Preview.SelectorValues, plan.Preview.FingerprintRefs)
	fmt.Fprintf(&output, "  paths / commands:        %d / %d\n", plan.Preview.FilesystemPaths, plan.Preview.ConfiguredCommands)
	fmt.Fprintf(&output, "  key options / diagnostics: %d / %d\n", plan.Preview.AuthorizedKeyOpts, plan.Preview.DiagnosticTexts)
	fmt.Fprintf(&output, "  unverified hints:        %d (explicitly included: %t)\n", plan.Preview.IdentityHints, plan.Privacy.IdentityHintsIncluded)
	fmt.Fprintf(&output, "  raw public keys:         %d\n", plan.Preview.RawPublicKeys)
	fmt.Fprintln(&output, "\nPrivate keys, SSH passwords, keyring values and connection credentials are not represented.")
	fmt.Fprintln(&output, "This artifact is local-only; upload requires a separately built and validated workspace bundle.")
	return output.String()
}

func cloneSnapshot(snapshot *Snapshot) (*Snapshot, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("clone upload snapshot: %w", err)
	}
	var clone Snapshot
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, fmt.Errorf("clone upload snapshot: %w", err)
	}
	return &clone, nil
}

func canonicalUploadPayload(snapshot *Snapshot) ([]byte, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal upload payload: %w", err)
	}
	return data, nil
}

func validateWorkspaceSlug(workspace string) error {
	if !workspaceSlugPattern.MatchString(workspace) {
		return errors.New("workspace must be a lowercase slug of 1-64 letters, digits, or internal hyphens")
	}
	return nil
}

func uploadIdempotencyKey(workspace, artifactID string) string {
	digest := sha256.Sum256([]byte(workspace + "\x00" + artifactID))
	return "upload_" + hex.EncodeToString(digest[:12])
}

func uploadPlanID(workspace, artifactID, payloadDigest string) string {
	digest := sha256.Sum256([]byte(workspace + "\x00" + artifactID + "\x00" + payloadDigest))
	return "plan_" + hex.EncodeToString(digest[:12])
}

func previewUploadFields(snapshot *Snapshot) UploadFieldPreview {
	preview := UploadFieldPreview{
		Hosts: len(snapshot.Hosts), AccessEntries: snapshot.Summary.AuthorizedKeyEntries,
		UniqueFingerprints: snapshot.Summary.UniqueFingerprints, Findings: len(snapshot.Findings),
		SelectorValues:  countPresent(snapshot.Scope.Selector),
		HostAliasRefs:   len(snapshot.Scope.HostExclusions) + len(snapshot.Scope.ExcludedMatchedHosts),
		TagNameRefs:     len(snapshot.Scope.TagExclusions),
		AccountNameRefs: len(snapshot.Scope.RequestedAccounts),
	}
	for _, host := range snapshot.Hosts {
		preview.HostAliasRefs++
		preview.GroupNameRefs += len(host.Groups)
		preview.TagNameRefs += len(host.Tags)
		preview.DiagnosticTexts += len(host.Limitations)
		preview.DiagnosticTexts += len(host.Errors) * 2
		if host.System != nil {
			sshd := host.System.SSHD
			preview.AccountNameRefs += len(host.System.MissingAccounts)
			preview.AccountNameRefs += countPresent(sshd.EffectiveUser, sshd.AuthorizedKeysCommandUser)
			preview.FilesystemPaths += countPresent(sshd.Path, sshd.TrustedUserCAKeys, sshd.AuthorizedPrincipalsFile)
			preview.FilesystemPaths += len(sshd.AuthorizedKeysFiles)
			preview.ConfiguredCommands += countPresent(host.System.SSHD.AuthorizedKeysCommand, host.System.SSHD.AuthorizedPrincipalsCommand)
			preview.NetworkMatchValues += countPresent(sshd.MatchHost, sshd.MatchAddress)
		}
		for _, account := range host.Accounts {
			preview.Accounts++
			preview.AccountNameRefs++
			preview.FilesystemPaths += countPresent(account.Home, account.Shell)
			preview.DiagnosticTexts += len(account.Limitations)
			if account.Auth != nil {
				preview.AccountNameRefs += countPresent(account.Auth.AuthorizedKeysCommandUser)
				preview.FilesystemPaths += countPresent(account.Auth.TrustedUserCAKeys, account.Auth.AuthorizedPrincipalsFile)
				preview.FilesystemPaths += len(account.Auth.AuthorizedKeysFiles)
				preview.ConfiguredCommands += countPresent(account.Auth.AuthorizedKeysCommand, account.Auth.AuthorizedPrincipalsCommand)
			}
			for _, source := range account.Sources {
				preview.FilesystemPaths += countPresent(source.Path, source.ConfiguredPath, source.ParentPath)
				preview.DiagnosticTexts += countPresent(source.Error)
				for _, entry := range source.Entries {
					preview.FingerprintRefs += countPresent(entry.Fingerprint)
					preview.AuthorizedKeyOpts += len(entry.Options)
					preview.DiagnosticTexts += countPresent(entry.ParseError)
					if entry.Comment != "" {
						preview.IdentityHints++
					}
					if entry.PublicKey != "" {
						preview.RawPublicKeys++
					}
				}
			}
		}
	}
	for _, finding := range snapshot.Findings {
		preview.HostAliasRefs += countPresent(finding.Host) + len(finding.Hosts)
		preview.AccountNameRefs += countPresent(finding.Account)
		preview.FingerprintRefs += countPresent(finding.Fingerprint)
		preview.DiagnosticTexts += countPresent(finding.Title, finding.CoverageCaveat, finding.RecommendedAction)
		preview.DiagnosticTexts += len(finding.Evidence)
	}
	return preview
}

func countPresent(values ...string) int {
	count := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "none" {
			count++
		}
	}
	return count
}

func rejectForbiddenUploadMaterial(payload []byte) error {
	lower := bytes.ToLower(payload)
	for _, marker := range [][]byte{
		[]byte("-----begin openssh private key-----"), []byte("-----begin private key-----"),
		[]byte("-----begin rsa private key-----"), []byte("-----begin ec private key-----"),
		[]byte("-----begin dsa private key-----"), []byte("-----begin encrypted private key-----"),
		[]byte("-----begin public key-----"),
	} {
		if bytes.Contains(lower, marker) {
			return errors.New("upload payload contains forbidden key material")
		}
	}
	if rawPublicKeyPattern.Match(payload) {
		return errors.New("upload payload contains a raw SSH public key outside the redacted field")
	}
	if credentialPattern.Match(payload) {
		return errors.New("upload payload contains a credential-like assignment")
	}
	return nil
}

func invalidUploadPlan(format string, args ...any) error {
	return fmt.Errorf("invalid offline upload plan v%s: %s", UploadPlanSchemaVersion, fmt.Sprintf(format, args...))
}
