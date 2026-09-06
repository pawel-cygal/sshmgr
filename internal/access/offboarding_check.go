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
	"sort"
	"strings"
	"time"
)

const (
	OffboardingCheckSchemaVersion = "1"
	OffboardingOutcomeComplete    = "complete"
	OffboardingOutcomePresent     = "still_present"
	OffboardingOutcomeUnknown     = "inconclusive"
	maxOffboardingCheckBytes      = 96 << 20
)

type OffboardingCheck struct {
	SchemaVersion        string                     `json:"schema_version"`
	CheckID              string                     `json:"check_id"`
	BaselineReportID     string                     `json:"baseline_report_id"`
	BaselineReportSHA256 string                     `json:"baseline_report_sha256"`
	BeforeScanID         string                     `json:"before_scan_id"`
	BeforeReviewID       string                     `json:"before_review_id"`
	AfterScanID          string                     `json:"after_scan_id"`
	AfterReviewID        string                     `json:"after_review_id"`
	BeforeSnapshotSHA256 string                     `json:"before_snapshot_sha256"`
	BeforeReviewSHA256   string                     `json:"before_review_sha256"`
	AfterSnapshotSHA256  string                     `json:"after_snapshot_sha256"`
	AfterReviewSHA256    string                     `json:"after_review_sha256"`
	Identity             Identity                   `json:"identity"`
	Safety               OffboardingSafety          `json:"safety"`
	Outcome              string                     `json:"outcome"`
	Comparison           OffboardingCheckComparison `json:"comparison"`
	BeforeCoverage       OffboardingCoverage        `json:"before_coverage"`
	AfterCoverage        OffboardingCoverage        `json:"after_coverage"`
	Summary              OffboardingCheckSummary    `json:"summary"`
	BaselineKeys         []string                   `json:"baseline_keys"`
	CurrentKeys          []string                   `json:"current_keys"`
	BaselineAccess       []OffboardingCheckEdge     `json:"baseline_access"`
	StillObserved        []OffboardingCheckEdge     `json:"still_observed,omitempty"`
	NotObserved          []OffboardingCheckEdge     `json:"not_observed,omitempty"`
	NewlyObserved        []OffboardingCheckEdge     `json:"newly_observed,omitempty"`
	Reasons              []OffboardingCheckReason   `json:"reasons"`
}

type OffboardingCheckComparison struct {
	Comparable         bool     `json:"comparable"`
	IncomparableReason string   `json:"incomparable_reason,omitempty"`
	UnsafeHosts        []string `json:"unsafe_hosts,omitempty"`
	DynamicSourceHosts []string `json:"dynamic_source_hosts,omitempty"`
	IdentityPresent    bool     `json:"identity_present_after"`
	IdentityOffboarded bool     `json:"identity_offboarded_after"`
	ClaimsUnchanged    bool     `json:"claims_unchanged"`
	FreshAfterSnapshot bool     `json:"fresh_after_snapshot"`
}

type OffboardingCheckSummary struct {
	BaselineKeys    int `json:"baseline_keys"`
	CurrentKeys     int `json:"current_keys"`
	BaselineAccess  int `json:"baseline_access_edges"`
	StillObserved   int `json:"still_observed_edges"`
	NotObserved     int `json:"not_observed_edges"`
	NewlyObserved   int `json:"newly_observed_edges"`
	BlockingReasons int `json:"blocking_reasons"`
}

type OffboardingCheckEdge struct {
	Fingerprint string              `json:"fingerprint"`
	Host        string              `json:"host"`
	Account     string              `json:"account"`
	Evidence    []OffboardingAccess `json:"evidence"`
}

type OffboardingCheckReason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func BuildOffboardingCheck(baseline *OffboardingReport, beforeSnapshot *Snapshot, beforeReview *OwnershipReview, afterSnapshot *Snapshot, afterReview *OwnershipReview) (*OffboardingCheck, error) {
	if err := ValidateOffboardingReportAgainstInputs(baseline, beforeSnapshot, beforeReview); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	if err := ValidateOwnershipReviewAgainstSnapshot(afterReview, afterSnapshot); err != nil {
		return nil, fmt.Errorf("after ownership review: %w", err)
	}

	check := &OffboardingCheck{
		SchemaVersion:    OffboardingCheckSchemaVersion,
		BaselineReportID: baseline.ReportID,
		BeforeScanID:     beforeSnapshot.ScanID, BeforeReviewID: beforeReview.ReviewID,
		AfterScanID: afterSnapshot.ScanID, AfterReviewID: afterReview.ReviewID,
		Identity:       baseline.Identity,
		Safety:         OffboardingSafety{Mode: OffboardingReportMode, RequiresFreshScan: true},
		BeforeCoverage: buildOffboardingCoverage(beforeSnapshot),
		AfterCoverage:  buildOffboardingCoverage(afterSnapshot),
		BaselineKeys:   offboardingReportFingerprints(baseline),
		CurrentKeys:    ownershipFingerprintsForIdentity(afterReview, baseline.Identity.ID),
	}
	var err error
	if check.BaselineReportSHA256, err = offboardingDigest(baseline); err != nil {
		return nil, err
	}
	if check.BeforeSnapshotSHA256, err = offboardingDigest(beforeSnapshot); err != nil {
		return nil, err
	}
	if check.BeforeReviewSHA256, err = offboardingDigest(beforeReview); err != nil {
		return nil, err
	}
	if check.AfterSnapshotSHA256, err = offboardingDigest(afterSnapshot); err != nil {
		return nil, err
	}
	if check.AfterReviewSHA256, err = offboardingDigest(afterReview); err != nil {
		return nil, err
	}

	check.Comparison.IncomparableReason = incomparableSnapshotReason(beforeSnapshot, afterSnapshot)
	check.Comparison.Comparable = check.Comparison.IncomparableReason == ""
	check.Comparison.UnsafeHosts = unsafeTransitionHosts(beforeSnapshot, afterSnapshot)
	check.Comparison.DynamicSourceHosts = sortedUnion(check.BeforeCoverage.DynamicSourceHosts, check.AfterCoverage.DynamicSourceHosts)
	afterIdentity, identityPresent := ownershipIdentity(afterReview, baseline.Identity.ID)
	check.Comparison.IdentityPresent = identityPresent
	check.Comparison.IdentityOffboarded = identityPresent && afterIdentity.Status == IdentityStatusOffboarded
	check.Comparison.ClaimsUnchanged = offboardingClaimsUnchanged(baseline, afterReview)
	beforeCompleted, _ := time.Parse(time.RFC3339Nano, beforeSnapshot.CompletedAt)
	afterCompleted, _ := time.Parse(time.RFC3339Nano, afterSnapshot.CompletedAt)
	check.Comparison.FreshAfterSnapshot = beforeSnapshot.ScanID != afterSnapshot.ScanID && afterCompleted.After(beforeCompleted)

	check.BaselineAccess = offboardingCheckEdgesFromReport(baseline)
	allFingerprints := sortedUnion(check.BaselineKeys, check.CurrentKeys)
	currentAccess := offboardingCheckEdgesFromSnapshot(afterSnapshot, allFingerprints)
	baselineByID := indexOffboardingCheckEdges(check.BaselineAccess)
	currentByID := indexOffboardingCheckEdges(currentAccess)
	for _, edge := range check.BaselineAccess {
		if current, present := currentByID[offboardingCheckEdgeID(edge)]; present {
			check.StillObserved = append(check.StillObserved, current)
		} else {
			check.NotObserved = append(check.NotObserved, edge)
		}
	}
	for _, edge := range currentAccess {
		if _, existed := baselineByID[offboardingCheckEdgeID(edge)]; !existed {
			check.NewlyObserved = append(check.NewlyObserved, edge)
		}
	}
	check.Reasons = deriveOffboardingCheckReasons(check)
	check.Outcome = deriveOffboardingOutcome(check)
	check.Summary = deriveOffboardingCheckSummary(check)
	check.CheckID, err = offboardingCheckID(check)
	if err != nil {
		return nil, err
	}
	if err := ValidateOffboardingCheck(check); err != nil {
		return nil, err
	}
	return check, nil
}

func ValidateOffboardingReportAgainstInputs(report *OffboardingReport, snapshot *Snapshot, review *OwnershipReview) error {
	if err := ValidateOffboardingReport(report); err != nil {
		return err
	}
	if err := ValidateOwnershipReviewAgainstSnapshot(review, snapshot); err != nil {
		return err
	}
	expected, err := BuildOffboardingReport(snapshot, review, report.Identity.ID)
	if err != nil {
		return err
	}
	// A strict JSON round trip may normalize omitted empty slices from [] to
	// nil. ReportID binds the complete validated semantic content and both
	// canonical input digests, without treating that encoding detail as drift.
	if expected.ReportID != report.ReportID || expected.SnapshotSHA256 != report.SnapshotSHA256 || expected.ReviewSHA256 != report.ReviewSHA256 {
		return errors.New("offboarding report does not reconcile with the selected snapshot and ownership review")
	}
	return nil
}

func ValidateOffboardingCheck(check *OffboardingCheck) error {
	if check == nil {
		return invalidOffboardingCheck("check is nil")
	}
	if check.SchemaVersion != OffboardingCheckSchemaVersion {
		return invalidOffboardingCheck("unsupported schema_version %q", check.SchemaVersion)
	}
	for label, value := range map[string]string{
		"check_id": check.CheckID, "baseline_report_id": check.BaselineReportID,
		"before_scan_id": check.BeforeScanID, "before_review_id": check.BeforeReviewID,
		"after_scan_id": check.AfterScanID, "after_review_id": check.AfterReviewID,
	} {
		if err := validIdentityText(value, false); err != nil || hasUnsafeOffboardingRune(value) {
			return invalidOffboardingCheck("%s is invalid", label)
		}
	}
	for label, value := range map[string]string{
		"baseline_report_sha256": check.BaselineReportSHA256,
		"before_snapshot_sha256": check.BeforeSnapshotSHA256, "before_review_sha256": check.BeforeReviewSHA256,
		"after_snapshot_sha256": check.AfterSnapshotSHA256, "after_review_sha256": check.AfterReviewSHA256,
	} {
		if !validOffboardingDigest(value) {
			return invalidOffboardingCheck("%s is invalid", label)
		}
	}
	if err := validateOffboardingIdentity(check.Identity); err != nil {
		return invalidOffboardingCheck("identity: %v", err)
	}
	if check.Safety != (OffboardingSafety{Mode: OffboardingReportMode, RequiresFreshScan: true}) {
		return invalidOffboardingCheck("safety contract must remain report-only and non-executable")
	}
	if err := validateOffboardingCoverage(check.BeforeCoverage); err != nil {
		return invalidOffboardingCheck("before coverage: %v", err)
	}
	if err := validateOffboardingCoverage(check.AfterCoverage); err != nil {
		return invalidOffboardingCheck("after coverage: %v", err)
	}
	if check.Comparison.Comparable != (check.Comparison.IncomparableReason == "") {
		return invalidOffboardingCheck("comparison reason does not reconcile")
	}
	if check.Comparison.IncomparableReason != "" {
		if err := validOffboardingEvidenceText(check.Comparison.IncomparableReason, false); err != nil {
			return invalidOffboardingCheck("comparison reason: %v", err)
		}
	}
	if !strictlySortedUnique(check.Comparison.UnsafeHosts) || !strictlySortedUnique(check.Comparison.DynamicSourceHosts) {
		return invalidOffboardingCheck("comparison host lists must be sorted and unique")
	}
	for _, host := range append(append([]string(nil), check.Comparison.UnsafeHosts...), check.Comparison.DynamicSourceHosts...) {
		if err := validOffboardingEvidenceText(host, false); err != nil {
			return invalidOffboardingCheck("comparison host: %v", err)
		}
	}
	if !strictOffboardingFingerprints(check.BaselineKeys) || !strictOffboardingFingerprints(check.CurrentKeys) {
		return invalidOffboardingCheck("key lists must contain sorted unique SHA256 fingerprints")
	}
	for label, edges := range map[string][]OffboardingCheckEdge{
		"baseline_access": check.BaselineAccess, "still_observed": check.StillObserved,
		"not_observed": check.NotObserved, "newly_observed": check.NewlyObserved,
	} {
		if err := validateOffboardingCheckEdges(edges); err != nil {
			return invalidOffboardingCheck("%s: %v", label, err)
		}
	}
	baseline := edgeIDSet(check.BaselineAccess)
	still, absent, newly := edgeIDSet(check.StillObserved), edgeIDSet(check.NotObserved), edgeIDSet(check.NewlyObserved)
	if setsOverlap(still, absent) || setsOverlap(baseline, newly) || len(still)+len(absent) != len(baseline) {
		return invalidOffboardingCheck("edge classifications overlap or do not partition baseline access")
	}
	for id := range baseline {
		if _, ok := still[id]; !ok {
			if _, ok = absent[id]; !ok {
				return invalidOffboardingCheck("baseline edge %q is unclassified", id)
			}
		}
	}
	if expected := deriveOffboardingCheckReasons(check); !reflect.DeepEqual(check.Reasons, expected) {
		return invalidOffboardingCheck("reasons do not reconcile")
	}
	if expected := deriveOffboardingOutcome(check); check.Outcome != expected {
		return invalidOffboardingCheck("outcome %q does not reconcile; expected %q", check.Outcome, expected)
	}
	if expected := deriveOffboardingCheckSummary(check); check.Summary != expected {
		return invalidOffboardingCheck("summary does not reconcile")
	}
	expectedID, err := offboardingCheckID(check)
	if err != nil || check.CheckID != expectedID {
		return invalidOffboardingCheck("check_id does not match check content")
	}
	return nil
}

func ValidateOffboardingCheckAgainstInputs(check *OffboardingCheck, baseline *OffboardingReport, beforeSnapshot *Snapshot, beforeReview *OwnershipReview, afterSnapshot *Snapshot, afterReview *OwnershipReview) error {
	if err := ValidateOffboardingCheck(check); err != nil {
		return err
	}
	expected, err := BuildOffboardingCheck(baseline, beforeSnapshot, beforeReview, afterSnapshot, afterReview)
	if err != nil {
		return err
	}
	// The content-derived ID is calculated from the complete normalized check.
	// Comparing it avoids treating JSON's equivalent nil and empty slices as a
	// mismatch after a strict artifact round trip.
	if expected.CheckID != check.CheckID ||
		expected.BaselineReportSHA256 != check.BaselineReportSHA256 ||
		expected.BeforeSnapshotSHA256 != check.BeforeSnapshotSHA256 ||
		expected.BeforeReviewSHA256 != check.BeforeReviewSHA256 ||
		expected.AfterSnapshotSHA256 != check.AfterSnapshotSHA256 ||
		expected.AfterReviewSHA256 != check.AfterReviewSHA256 {
		return errors.New("offboarding check does not reconcile with the selected baseline and after-scan inputs")
	}
	return nil
}

func RenderOffboardingCheckJSON(check *OffboardingCheck) ([]byte, error) {
	if err := ValidateOffboardingCheck(check); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(check, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal offboarding check: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxOffboardingCheckBytes {
		return nil, fmt.Errorf("offboarding check is %d bytes; limit is %d", len(data), maxOffboardingCheckBytes)
	}
	return data, nil
}

func WriteOffboardingCheckJSON(path string, check *OffboardingCheck) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("offboarding check JSON output path is empty")
	}
	data, err := RenderOffboardingCheckJSON(check)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadOffboardingCheck(path string) (*OffboardingCheck, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open offboarding check %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > maxOffboardingCheckBytes {
		return nil, fmt.Errorf("offboarding check is %d bytes; limit is %d", stat.Size(), maxOffboardingCheckBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxOffboardingCheckBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read offboarding check: %w", err)
	}
	if len(data) > maxOffboardingCheckBytes {
		return nil, fmt.Errorf("offboarding check exceeds %d bytes", maxOffboardingCheckBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var check OffboardingCheck
	if err := decoder.Decode(&check); err != nil {
		return nil, fmt.Errorf("parse offboarding check: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("offboarding check contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing offboarding check data: %w", err)
	}
	if err := ValidateOffboardingCheck(&check); err != nil {
		return nil, err
	}
	return &check, nil
}

func RenderOffboardingCheckText(check *OffboardingCheck) string {
	if check == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "SSH Offboarding Check  %s\n\n", check.CheckID)
	fmt.Fprintf(&output, "Identity:        %s\n", check.Identity.ID)
	fmt.Fprintf(&output, "Outcome:         %s\n", check.Outcome)
	fmt.Fprintf(&output, "Before / after:  %s / %s\n", check.BeforeScanID, check.AfterScanID)
	fmt.Fprintf(&output, "Access:          %d baseline / %d still observed / %d not observed / %d new\n",
		check.Summary.BaselineAccess, check.Summary.StillObserved, check.Summary.NotObserved, check.Summary.NewlyObserved)
	fmt.Fprintf(&output, "Coverage before: %d full / %d partial / %d failed\n", check.BeforeCoverage.HostsFull, check.BeforeCoverage.HostsPartial, check.BeforeCoverage.HostsFailed)
	fmt.Fprintf(&output, "Coverage after:  %d full / %d partial / %d failed\n", check.AfterCoverage.HostsFull, check.AfterCoverage.HostsPartial, check.AfterCoverage.HostsFailed)
	fmt.Fprintln(&output, "Mode:            report_only; remote changes: false; executable: false")
	fmt.Fprintln(&output, "\nReasons")
	for _, reason := range check.Reasons {
		fmt.Fprintf(&output, "  %s: %s\n", reason.Code, reason.Message)
	}
	if len(check.StillObserved) > 0 {
		fmt.Fprintln(&output, "\nStill observed")
		for _, edge := range check.StillObserved {
			fmt.Fprintf(&output, "  %s@%s  %s\n", edge.Account, edge.Host, edge.Fingerprint)
		}
	}
	if len(check.NewlyObserved) > 0 {
		fmt.Fprintln(&output, "\nNewly observed")
		for _, edge := range check.NewlyObserved {
			fmt.Fprintf(&output, "  %s@%s  %s\n", edge.Account, edge.Host, edge.Fingerprint)
		}
	}
	fmt.Fprintln(&output, "\nThis is a read-only evidence comparison. It performed no remediation and does not prove absence from unscanned, incomplete, dynamic, or certificate-backed sources.")
	return output.String()
}

func deriveOffboardingCheckReasons(check *OffboardingCheck) []OffboardingCheckReason {
	var reasons []OffboardingCheckReason
	if len(check.StillObserved)+len(check.NewlyObserved) > 0 {
		reasons = append(reasons, OffboardingCheckReason{Code: "access_still_observed", Message: "One or more mapped SSH access edges are still observed in the after snapshot."})
	}
	if !check.Comparison.Comparable {
		reasons = append(reasons, OffboardingCheckReason{Code: "scope_not_comparable", Message: check.Comparison.IncomparableReason})
	}
	if !check.Comparison.FreshAfterSnapshot {
		reasons = append(reasons, OffboardingCheckReason{Code: "after_snapshot_not_fresh", Message: "The after snapshot must have a different scan ID and a later completion time than the baseline snapshot."})
	}
	if len(check.BaselineAccess) == 0 {
		reasons = append(reasons, OffboardingCheckReason{Code: "baseline_has_no_observed_access", Message: "The baseline report has no observed access edge to verify as removed."})
	}
	if check.BeforeCoverage.HostsFull != check.BeforeCoverage.HostsRequested {
		reasons = append(reasons, OffboardingCheckReason{Code: "before_coverage_incomplete", Message: "The baseline scan did not have full coverage for every requested host."})
	}
	if check.AfterCoverage.HostsFull != check.AfterCoverage.HostsRequested {
		reasons = append(reasons, OffboardingCheckReason{Code: "after_coverage_incomplete", Message: "The after scan does not have full coverage for every requested host."})
	}
	if len(check.Comparison.UnsafeHosts) > 0 {
		reasons = append(reasons, OffboardingCheckReason{Code: "unsafe_hosts_excluded", Message: "One or more hosts contain collection errors, truncation, unread sources, malformed entries, or changed missing-account evidence."})
	}
	if len(check.Comparison.DynamicSourceHosts) > 0 {
		reasons = append(reasons, OffboardingCheckReason{Code: "dynamic_or_certificate_sources", Message: "Dynamic key, principal, or SSH certificate sources require a separate upstream policy review."})
	}
	if !check.Comparison.IdentityPresent {
		reasons = append(reasons, OffboardingCheckReason{Code: "identity_missing_after", Message: "The identity is absent from the after ownership review, so ownership continuity cannot be proved."})
	} else if !check.Comparison.IdentityOffboarded {
		reasons = append(reasons, OffboardingCheckReason{Code: "identity_not_offboarded", Message: "The identity is not marked offboarded in the after ownership review."})
	}
	if !check.Comparison.ClaimsUnchanged {
		reasons = append(reasons, OffboardingCheckReason{Code: "ownership_claims_changed", Message: "The identity's fingerprint claims changed between the baseline report and after ownership review."})
	}
	if len(reasons) == 0 {
		reasons = append(reasons, OffboardingCheckReason{Code: "mapped_access_not_observed", Message: "No mapped SSH access edge is observed after a comparable, full-coverage rescan with unchanged ownership claims."})
	}
	return reasons
}

func deriveOffboardingOutcome(check *OffboardingCheck) string {
	if len(check.StillObserved)+len(check.NewlyObserved) > 0 {
		return OffboardingOutcomePresent
	}
	if len(check.Reasons) == 1 && check.Reasons[0].Code == "mapped_access_not_observed" {
		return OffboardingOutcomeComplete
	}
	return OffboardingOutcomeUnknown
}

func deriveOffboardingCheckSummary(check *OffboardingCheck) OffboardingCheckSummary {
	blocking := len(check.Reasons)
	if blocking == 1 && check.Reasons[0].Code == "mapped_access_not_observed" {
		blocking = 0
	}
	return OffboardingCheckSummary{
		BaselineKeys: len(check.BaselineKeys), CurrentKeys: len(check.CurrentKeys),
		BaselineAccess: len(check.BaselineAccess), StillObserved: len(check.StillObserved),
		NotObserved: len(check.NotObserved), NewlyObserved: len(check.NewlyObserved), BlockingReasons: blocking,
	}
}

func offboardingReportFingerprints(report *OffboardingReport) []string {
	values := make([]string, 0, len(report.Keys))
	for _, key := range report.Keys {
		values = append(values, key.Fingerprint)
	}
	return values
}

func ownershipFingerprintsForIdentity(review *OwnershipReview, identityID string) []string {
	values := make([]string, 0)
	for _, key := range review.Keys {
		for _, claim := range key.Claims {
			if claim.IdentityID == identityID {
				values = append(values, key.Fingerprint)
				break
			}
		}
	}
	sort.Strings(values)
	return values
}

func ownershipIdentity(review *OwnershipReview, identityID string) (Identity, bool) {
	for _, identity := range review.Identities {
		if identity.ID == identityID {
			return identity, true
		}
	}
	return Identity{}, false
}

func offboardingClaimsUnchanged(baseline *OffboardingReport, after *OwnershipReview) bool {
	type claimState struct {
		Fingerprint string
		Claim       ResolvedOwnershipClaim
	}
	baselineClaims := make([]claimState, 0, len(baseline.Keys))
	for _, key := range baseline.Keys {
		baselineClaims = append(baselineClaims, claimState{Fingerprint: key.Fingerprint, Claim: key.SelectedClaim})
	}
	var afterClaims []claimState
	for _, key := range after.Keys {
		for _, claim := range key.Claims {
			if claim.IdentityID == baseline.Identity.ID {
				afterClaims = append(afterClaims, claimState{Fingerprint: key.Fingerprint, Claim: claim})
			}
		}
	}
	return reflect.DeepEqual(baselineClaims, afterClaims)
}

func offboardingCheckEdgesFromReport(report *OffboardingReport) []OffboardingCheckEdge {
	byID := map[string]*OffboardingCheckEdge{}
	for _, key := range report.Keys {
		for _, evidence := range key.Access {
			id := key.Fingerprint + "\x00" + evidence.Host + "\x00" + evidence.Account
			if byID[id] == nil {
				byID[id] = &OffboardingCheckEdge{Fingerprint: key.Fingerprint, Host: evidence.Host, Account: evidence.Account}
			}
			byID[id].Evidence = append(byID[id].Evidence, evidence)
		}
	}
	return normalizedOffboardingCheckEdges(byID)
}

func offboardingCheckEdgesFromSnapshot(snapshot *Snapshot, fingerprints []string) []OffboardingCheckEdge {
	wanted := make(map[string]bool, len(fingerprints))
	for _, fingerprint := range fingerprints {
		wanted[fingerprint] = true
	}
	byID := map[string]*OffboardingCheckEdge{}
	for fingerprint, accessRows := range offboardingAccessByFingerprint(snapshot) {
		if !wanted[fingerprint] {
			continue
		}
		for _, evidence := range accessRows {
			id := fingerprint + "\x00" + evidence.Host + "\x00" + evidence.Account
			if byID[id] == nil {
				byID[id] = &OffboardingCheckEdge{Fingerprint: fingerprint, Host: evidence.Host, Account: evidence.Account}
			}
			byID[id].Evidence = append(byID[id].Evidence, evidence)
		}
	}
	return normalizedOffboardingCheckEdges(byID)
}

func normalizedOffboardingCheckEdges(byID map[string]*OffboardingCheckEdge) []OffboardingCheckEdge {
	values := make([]OffboardingCheckEdge, 0, len(byID))
	for _, edge := range byID {
		sort.Slice(edge.Evidence, func(i, j int) bool {
			return offboardingAccessID(edge.Evidence[i]) < offboardingAccessID(edge.Evidence[j])
		})
		values = append(values, *edge)
	}
	sort.Slice(values, func(i, j int) bool { return offboardingCheckEdgeID(values[i]) < offboardingCheckEdgeID(values[j]) })
	return values
}

func validateOffboardingCheckEdges(edges []OffboardingCheckEdge) error {
	previous := ""
	for index, edge := range edges {
		if !validSHA256Fingerprint(edge.Fingerprint) {
			return fmt.Errorf("edges[%d] has invalid fingerprint", index)
		}
		if err := validOffboardingEvidenceText(edge.Host, false); err != nil {
			return fmt.Errorf("edges[%d] host: %w", index, err)
		}
		if err := validOffboardingEvidenceText(edge.Account, false); err != nil {
			return fmt.Errorf("edges[%d] account: %w", index, err)
		}
		id := offboardingCheckEdgeID(edge)
		if previous != "" && id <= previous {
			return errors.New("edges are duplicate or unsorted")
		}
		previous = id
		if len(edge.Evidence) == 0 {
			return fmt.Errorf("edges[%d] has no source evidence", index)
		}
		previousEvidence := ""
		for evidenceIndex, evidence := range edge.Evidence {
			if evidence.Host != edge.Host || evidence.Account != edge.Account {
				return fmt.Errorf("edges[%d] evidence[%d] does not match edge", index, evidenceIndex)
			}
			if err := validateOffboardingAccess(evidence); err != nil {
				return fmt.Errorf("edges[%d] evidence[%d]: %w", index, evidenceIndex, err)
			}
			evidenceID := offboardingAccessID(evidence)
			if previousEvidence != "" && evidenceID <= previousEvidence {
				return fmt.Errorf("edges[%d] evidence is duplicate or unsorted", index)
			}
			previousEvidence = evidenceID
		}
	}
	return nil
}

func strictOffboardingFingerprints(values []string) bool {
	if values == nil {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validSHA256Fingerprint(value) || previous != "" && value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func sortedUnion(left, right []string) []string {
	set := make(map[string]bool, len(left)+len(right))
	for _, value := range append(append([]string(nil), left...), right...) {
		set[value] = true
	}
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func indexOffboardingCheckEdges(edges []OffboardingCheckEdge) map[string]OffboardingCheckEdge {
	values := make(map[string]OffboardingCheckEdge, len(edges))
	for _, edge := range edges {
		values[offboardingCheckEdgeID(edge)] = edge
	}
	return values
}

func edgeIDSet(edges []OffboardingCheckEdge) map[string]bool {
	values := make(map[string]bool, len(edges))
	for _, edge := range edges {
		values[offboardingCheckEdgeID(edge)] = true
	}
	return values
}

func setsOverlap(left, right map[string]bool) bool {
	for value := range left {
		if right[value] {
			return true
		}
	}
	return false
}

func offboardingCheckEdgeID(edge OffboardingCheckEdge) string {
	return edge.Host + "\x00" + edge.Account + "\x00" + edge.Fingerprint
}

func offboardingCheckID(check *OffboardingCheck) (string, error) {
	clone := *check
	clone.CheckID = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return "offboarding_check_" + hex.EncodeToString(hash[:12]), nil
}

func invalidOffboardingCheck(format string, args ...any) error {
	return fmt.Errorf("invalid offboarding check v%s: %s", OffboardingCheckSchemaVersion, fmt.Sprintf(format, args...))
}
