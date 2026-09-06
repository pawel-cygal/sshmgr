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
	"strings"
)

const (
	WorkspaceBundleSchemaVersion = "1"
	WorkspaceBundleArtifactType  = "workspace_access_review"
	MaxWorkspaceBundleBytes      = 512 << 20
)

// WorkspaceBundle is the single deterministic ingestion candidate for the
// Cloud API. It contains only artifacts that already passed the local
// privacy boundary and strict workspace evidence joins. Building, reading, or
// inspecting it performs no network operation.
type WorkspaceBundle struct {
	SchemaVersion  string                 `json:"schema_version"`
	BundleID       string                 `json:"bundle_id"`
	Workspace      string                 `json:"workspace"`
	ArtifactType   string                 `json:"artifact_type"`
	IdempotencyKey string                 `json:"idempotency_key"`
	PayloadSHA256  string                 `json:"payload_sha256"`
	PayloadBytes   int                    `json:"payload_bytes"`
	Digests        WorkspaceBundleDigests `json:"digests"`
	Privacy        UploadPrivacy          `json:"privacy"`
	Preview        WorkspaceBundlePreview `json:"preview"`
	Payload        WorkspaceBundlePayload `json:"payload"`
}

type WorkspaceBundlePayload struct {
	WorkspaceHistory   WorkspaceHistory             `json:"workspace_history"`
	OwnershipReview    *OwnershipReview             `json:"ownership_review,omitempty"`
	OwnershipHistory   *WorkspaceOwnershipHistory   `json:"ownership_history,omitempty"`
	OffboardingHistory *WorkspaceOffboardingHistory `json:"offboarding_history,omitempty"`
}

type WorkspaceBundleDigests struct {
	WorkspaceHistory      string `json:"workspace_history_sha256"`
	OwnershipReview       string `json:"ownership_review_sha256,omitempty"`
	OwnershipReviewSource string `json:"ownership_review_source_sha256,omitempty"`
	OwnershipHistory      string `json:"ownership_history_sha256,omitempty"`
	OffboardingHistory    string `json:"offboarding_history_sha256,omitempty"`
}

// WorkspaceBundlePreview summarizes both the latest review surface and the
// amount of timeline evidence carried by the payload.
type WorkspaceBundlePreview struct {
	Snapshots                    int  `json:"snapshots"`
	LatestHosts                  int  `json:"latest_hosts"`
	LatestAccounts               int  `json:"latest_accounts"`
	LatestAccessEntries          int  `json:"latest_access_entries"`
	LatestUniqueFingerprints     int  `json:"latest_unique_fingerprints"`
	LatestFindings               int  `json:"latest_findings"`
	TimelineHostObservations     int  `json:"timeline_host_observations"`
	TimelineAccessEntries        int  `json:"timeline_access_entries"`
	OwnershipReviewAttached      bool `json:"ownership_review_attached"`
	OwnershipReviews             int  `json:"ownership_reviews"`
	OwnershipFindings            int  `json:"ownership_findings"`
	OffboardingChecks            int  `json:"offboarding_checks"`
	TrackedOffboardingIdentities int  `json:"tracked_offboarding_identities"`
	IdentityHints                int  `json:"identity_hints"`
	RawPublicKeys                int  `json:"raw_public_keys"`
}

// BuildWorkspaceBundle validates the exact evidence set used by the local
// dashboard, privacy-normalizes the standalone ownership review, and freezes
// everything into one content-addressed transport envelope.
func BuildWorkspaceBundle(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) (*WorkspaceBundle, error) {
	if _, err := buildWorkspaceDashboardData(history, ownership, ownershipHistory, offboardingHistory); err != nil {
		return nil, fmt.Errorf("workspace bundle evidence: %w", err)
	}

	var normalizedOwnership *OwnershipReview
	var sourceOwnershipDigest string
	var err error
	if ownership != nil {
		sourceOwnershipDigest, err = offboardingDigest(ownership)
		if err != nil {
			return nil, fmt.Errorf("digest source ownership review: %w", err)
		}
		normalizedOwnership, err = privacyNormalizeWorkspaceOwnershipReview(ownership)
		if err != nil {
			return nil, fmt.Errorf("normalize ownership review: %w", err)
		}
	}

	payload := WorkspaceBundlePayload{
		WorkspaceHistory:   *history,
		OwnershipReview:    normalizedOwnership,
		OwnershipHistory:   ownershipHistory,
		OffboardingHistory: offboardingHistory,
	}
	// Clone the entire payload in one canonical round trip so the returned
	// bundle never aliases input slices or pointers owned by the caller.
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal workspace bundle payload: %w", err)
	}
	var clonedPayload WorkspaceBundlePayload
	if err := json.Unmarshal(payloadJSON, &clonedPayload); err != nil {
		return nil, fmt.Errorf("clone workspace bundle payload: %w", err)
	}
	payload = clonedPayload

	bundle := &WorkspaceBundle{
		SchemaVersion: WorkspaceBundleSchemaVersion,
		Workspace:     history.Workspace,
		ArtifactType:  WorkspaceBundleArtifactType,
		Payload:       payload,
	}
	bundle.Digests, err = workspaceBundleDigests(&bundle.Payload, sourceOwnershipDigest)
	if err != nil {
		return nil, err
	}
	bundle.Privacy = workspaceBundlePrivacy(&bundle.Payload)
	bundle.Preview = workspaceBundlePreview(&bundle.Payload)
	payloadJSON, err = canonicalWorkspaceBundlePayload(&bundle.Payload)
	if err != nil {
		return nil, err
	}
	if len(payloadJSON) > MaxWorkspaceBundleBytes {
		return nil, fmt.Errorf("workspace bundle payload is %d bytes; limit is %d", len(payloadJSON), MaxWorkspaceBundleBytes)
	}
	if err := rejectForbiddenUploadMaterial(payloadJSON); err != nil {
		return nil, fmt.Errorf("workspace bundle privacy boundary: %w", err)
	}
	bundle.PayloadBytes = len(payloadJSON)
	bundle.PayloadSHA256 = digestBytes(payloadJSON)
	bundle.BundleID = workspaceBundleID(bundle.Workspace, bundle.PayloadSHA256, bundle.Digests.OwnershipReviewSource)
	bundle.IdempotencyKey = workspaceBundleIdempotencyKey(bundle.Workspace, bundle.BundleID)
	if err := ValidateWorkspaceBundle(bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

func ValidateWorkspaceBundle(bundle *WorkspaceBundle) error {
	if bundle == nil {
		return invalidWorkspaceBundle("bundle is nil")
	}
	if bundle.SchemaVersion != WorkspaceBundleSchemaVersion {
		return invalidWorkspaceBundle("unsupported schema_version %q", bundle.SchemaVersion)
	}
	if err := validateWorkspaceSlug(bundle.Workspace); err != nil {
		return invalidWorkspaceBundle("%v", err)
	}
	if bundle.ArtifactType != WorkspaceBundleArtifactType {
		return invalidWorkspaceBundle("artifact_type must be %q", WorkspaceBundleArtifactType)
	}
	if bundle.Payload.WorkspaceHistory.Workspace != bundle.Workspace {
		return invalidWorkspaceBundle("workspace does not match embedded history")
	}
	if err := validateWorkspaceBundleEvidence(&bundle.Payload, bundle.Digests.OwnershipReviewSource); err != nil {
		return invalidWorkspaceBundle("evidence: %v", err)
	}

	payloadJSON, err := canonicalWorkspaceBundlePayload(&bundle.Payload)
	if err != nil {
		return invalidWorkspaceBundle("payload: %v", err)
	}
	if len(payloadJSON) > MaxWorkspaceBundleBytes || bundle.PayloadBytes != len(payloadJSON) {
		return invalidWorkspaceBundle("payload_bytes does not reconcile or exceeds %d", MaxWorkspaceBundleBytes)
	}
	if err := rejectForbiddenUploadMaterial(payloadJSON); err != nil {
		return invalidWorkspaceBundle("privacy boundary: %v", err)
	}
	payloadDigest := digestBytes(payloadJSON)
	if bundle.PayloadSHA256 != payloadDigest {
		return invalidWorkspaceBundle("payload_sha256 does not match embedded payload")
	}
	expectedDigests, err := workspaceBundleDigests(&bundle.Payload, bundle.Digests.OwnershipReviewSource)
	if err != nil {
		return invalidWorkspaceBundle("digests: %v", err)
	}
	if bundle.Digests != expectedDigests {
		return invalidWorkspaceBundle("artifact digests do not reconcile")
	}
	expectedPrivacy := workspaceBundlePrivacy(&bundle.Payload)
	if bundle.Privacy != expectedPrivacy {
		return invalidWorkspaceBundle("privacy contract does not reconcile")
	}
	expectedPreview := workspaceBundlePreview(&bundle.Payload)
	if bundle.Preview != expectedPreview {
		return invalidWorkspaceBundle("preview does not reconcile")
	}
	if expectedPreview.RawPublicKeys != 0 || bundle.Privacy.PublicKeysIncluded || bundle.Privacy.CredentialsIncluded {
		return invalidWorkspaceBundle("raw public keys and credentials are forbidden")
	}
	expectedBundleID := workspaceBundleID(bundle.Workspace, payloadDigest, bundle.Digests.OwnershipReviewSource)
	if bundle.BundleID != expectedBundleID {
		return invalidWorkspaceBundle("bundle_id does not match content")
	}
	if bundle.IdempotencyKey != workspaceBundleIdempotencyKey(bundle.Workspace, bundle.BundleID) {
		return invalidWorkspaceBundle("idempotency_key does not match workspace and bundle")
	}
	return nil
}

func validateWorkspaceBundleEvidence(payload *WorkspaceBundlePayload, sourceOwnershipDigest string) error {
	history := &payload.WorkspaceHistory
	if err := ValidateWorkspaceHistory(history); err != nil {
		return err
	}
	// Validate the companion histories and their mutual joins without using
	// the privacy-normalized standalone review's different source digest.
	if _, err := buildWorkspaceDashboardData(history, nil, payload.OwnershipHistory, payload.OffboardingHistory); err != nil {
		return err
	}
	if payload.OwnershipReview == nil {
		if sourceOwnershipDigest != "" {
			return errors.New("ownership review source digest exists without an ownership review")
		}
		return nil
	}
	if !validOffboardingDigest(sourceOwnershipDigest) {
		return errors.New("ownership review source digest is invalid")
	}
	for _, key := range payload.OwnershipReview.Keys {
		if len(key.IdentityHints) != 0 {
			return errors.New("standalone ownership review contains unverified identity hints")
		}
	}
	latest := &history.Plans[len(history.Plans)-1].Snapshot
	if err := ValidateOwnershipReviewAgainstSnapshot(payload.OwnershipReview, latest); err != nil {
		return fmt.Errorf("ownership review: %w", err)
	}
	if payload.OwnershipHistory != nil {
		var scan *WorkspaceOwnershipScan
		var embedded *OwnershipReview
		for index := range payload.OwnershipHistory.Scans {
			if payload.OwnershipHistory.Scans[index].ScanID == history.LatestScanID {
				scan = &payload.OwnershipHistory.Scans[index]
				break
			}
		}
		for index := range payload.OwnershipHistory.Reviews {
			if payload.OwnershipHistory.Reviews[index].ScanID == history.LatestScanID {
				embedded = &payload.OwnershipHistory.Reviews[index]
				break
			}
		}
		if scan == nil || embedded == nil || !scan.Reviewed || scan.ReviewID != payload.OwnershipReview.ReviewID || scan.ReviewSHA256 != sourceOwnershipDigest || !reflect.DeepEqual(embedded, payload.OwnershipReview) {
			return errors.New("ownership review does not match the latest ownership-history evidence")
		}
	}
	if payload.OffboardingHistory != nil {
		for _, check := range payload.OffboardingHistory.Checks {
			if check.AfterScanID == history.LatestScanID && (check.AfterReviewID != payload.OwnershipReview.ReviewID || check.AfterReviewSHA256 != sourceOwnershipDigest) {
				return errors.New("latest offboarding check does not match the ownership review source digest")
			}
		}
	}
	return nil
}

func workspaceBundleDigests(payload *WorkspaceBundlePayload, sourceOwnershipDigest string) (WorkspaceBundleDigests, error) {
	var result WorkspaceBundleDigests
	var err error
	result.WorkspaceHistory, err = offboardingDigest(&payload.WorkspaceHistory)
	if err != nil {
		return result, fmt.Errorf("digest workspace history: %w", err)
	}
	if payload.OwnershipReview != nil {
		result.OwnershipReview, err = offboardingDigest(payload.OwnershipReview)
		if err != nil {
			return result, fmt.Errorf("digest ownership review: %w", err)
		}
		result.OwnershipReviewSource = sourceOwnershipDigest
	}
	if payload.OwnershipHistory != nil {
		result.OwnershipHistory, err = offboardingDigest(payload.OwnershipHistory)
		if err != nil {
			return result, fmt.Errorf("digest ownership history: %w", err)
		}
	}
	if payload.OffboardingHistory != nil {
		result.OffboardingHistory, err = offboardingDigest(payload.OffboardingHistory)
		if err != nil {
			return result, fmt.Errorf("digest offboarding history: %w", err)
		}
	}
	return result, nil
}

func workspaceBundlePrivacy(payload *WorkspaceBundlePayload) UploadPrivacy {
	identityHintsIncluded := false
	for _, plan := range payload.WorkspaceHistory.Plans {
		identityHintsIncluded = identityHintsIncluded || plan.Privacy.IdentityHintsIncluded
	}
	return UploadPrivacy{
		Profile: UploadPrivacyStandard, HostAliasesIncluded: true,
		AccountNamesIncluded: true, SourcePathsIncluded: true,
		IdentityHintsIncluded: identityHintsIncluded,
		PublicKeysIncluded:    false, CredentialsIncluded: false,
	}
}

func workspaceBundlePreview(payload *WorkspaceBundlePayload) WorkspaceBundlePreview {
	history := &payload.WorkspaceHistory
	result := WorkspaceBundlePreview{Snapshots: len(history.Plans)}
	for _, artifact := range history.Artifacts {
		result.TimelineHostObservations += artifact.Preview.Hosts
		result.TimelineAccessEntries += artifact.Preview.AccessEntries
		result.IdentityHints += artifact.Preview.IdentityHints
		result.RawPublicKeys += artifact.Preview.RawPublicKeys
	}
	if len(history.Artifacts) > 0 {
		latest := history.Artifacts[len(history.Artifacts)-1].Preview
		result.LatestHosts = latest.Hosts
		result.LatestAccounts = latest.Accounts
		result.LatestAccessEntries = latest.AccessEntries
		result.LatestUniqueFingerprints = latest.UniqueFingerprints
		result.LatestFindings = latest.Findings
	}
	if payload.OwnershipReview != nil {
		result.OwnershipReviewAttached = true
		result.OwnershipFindings = len(payload.OwnershipReview.Findings)
	}
	if payload.OwnershipHistory != nil {
		result.OwnershipReviews = len(payload.OwnershipHistory.Reviews)
	}
	if payload.OffboardingHistory != nil {
		result.OffboardingChecks = len(payload.OffboardingHistory.Checks)
		result.TrackedOffboardingIdentities = payload.OffboardingHistory.Summary.Identities
	}
	return result
}

func RenderWorkspaceBundleJSON(bundle *WorkspaceBundle) ([]byte, error) {
	if err := ValidateWorkspaceBundle(bundle); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal workspace bundle: %w", err)
	}
	data = append(data, '\n')
	if len(data) > MaxWorkspaceBundleBytes {
		return nil, fmt.Errorf("workspace bundle is %d bytes; limit is %d", len(data), MaxWorkspaceBundleBytes)
	}
	return data, nil
}

func WriteWorkspaceBundle(path string, bundle *WorkspaceBundle) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("workspace bundle output path is empty")
	}
	data, err := RenderWorkspaceBundleJSON(bundle)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadWorkspaceBundle(path string) (*WorkspaceBundle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace bundle %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > MaxWorkspaceBundleBytes {
		return nil, fmt.Errorf("workspace bundle is %d bytes; limit is %d", stat.Size(), MaxWorkspaceBundleBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxWorkspaceBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read workspace bundle: %w", err)
	}
	if len(data) > MaxWorkspaceBundleBytes {
		return nil, fmt.Errorf("workspace bundle exceeds %d bytes", MaxWorkspaceBundleBytes)
	}
	return ParseWorkspaceBundleJSON(data)
}

// ParseWorkspaceBundleJSON strictly decodes one bounded JSON bundle. It is
// shared by the local reader and the HTTPS ingestion boundary.
func ParseWorkspaceBundleJSON(data []byte) (*WorkspaceBundle, error) {
	if len(data) > MaxWorkspaceBundleBytes {
		return nil, fmt.Errorf("workspace bundle exceeds %d bytes", MaxWorkspaceBundleBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle WorkspaceBundle
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("parse workspace bundle: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("workspace bundle contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing workspace bundle data: %w", err)
	}
	if err := ValidateWorkspaceBundle(&bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func RenderWorkspaceBundleText(bundle *WorkspaceBundle) string {
	if bundle == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Offline Cloud ingestion bundle  %s\n\n", bundle.BundleID)
	fmt.Fprintf(&output, "Workspace:                  %s\n", bundle.Workspace)
	fmt.Fprintf(&output, "Latest scan:                %s\n", bundle.Payload.WorkspaceHistory.LatestScanID)
	fmt.Fprintf(&output, "Snapshots:                  %d\n", bundle.Preview.Snapshots)
	fmt.Fprintf(&output, "Latest hosts / accounts:    %d / %d\n", bundle.Preview.LatestHosts, bundle.Preview.LatestAccounts)
	fmt.Fprintf(&output, "Latest access / findings:   %d / %d\n", bundle.Preview.LatestAccessEntries, bundle.Preview.LatestFindings)
	fmt.Fprintf(&output, "Ownership review / history: %t / %d review(s)\n", bundle.Preview.OwnershipReviewAttached, bundle.Preview.OwnershipReviews)
	fmt.Fprintf(&output, "Offboarding checks:         %d (%d identities)\n", bundle.Preview.OffboardingChecks, bundle.Preview.TrackedOffboardingIdentities)
	fmt.Fprintf(&output, "Payload:                    %d bytes  %s\n", bundle.PayloadBytes, bundle.PayloadSHA256)
	fmt.Fprintf(&output, "Idempotency key:            %s\n", bundle.IdempotencyKey)
	fmt.Fprintf(&output, "Identity hints / raw keys:  %d / %d\n", bundle.Preview.IdentityHints, bundle.Preview.RawPublicKeys)
	fmt.Fprintln(&output, "Network activity:           none")
	fmt.Fprintln(&output, "\nReady for explicit `sshmgr cloud upload`; this command made no network request.")
	return output.String()
}

func canonicalWorkspaceBundlePayload(payload *WorkspaceBundlePayload) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal workspace bundle payload: %w", err)
	}
	return data, nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "SHA256:" + hex.EncodeToString(digest[:])
}

func workspaceBundleID(workspace, payloadDigest, sourceOwnershipDigest string) string {
	digest := sha256.Sum256([]byte(workspace + "\x00" + payloadDigest + "\x00" + sourceOwnershipDigest))
	return "bundle_" + hex.EncodeToString(digest[:12])
}

func workspaceBundleIdempotencyKey(workspace, bundleID string) string {
	digest := sha256.Sum256([]byte(workspace + "\x00" + bundleID))
	return "bundle_upload_" + hex.EncodeToString(digest[:12])
}

func invalidWorkspaceBundle(format string, args ...any) error {
	return fmt.Errorf("invalid workspace bundle v%s: %s", WorkspaceBundleSchemaVersion, fmt.Sprintf(format, args...))
}
