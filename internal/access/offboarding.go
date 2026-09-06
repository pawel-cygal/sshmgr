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
	"unicode"
	"unicode/utf8"
)

const (
	OffboardingReportSchemaVersion = "1"
	OffboardingReportMode          = "report_only"
	maxOffboardingReportBytes      = 64 << 20
	offboardingCoverageCaveat      = "Absence from observed static authorized-key files is not proof that this identity has no SSH access; review incomplete hosts and dynamic or certificate-backed sources."
)

type OffboardingReport struct {
	SchemaVersion  string               `json:"schema_version"`
	ReportID       string               `json:"report_id"`
	ScanID         string               `json:"scan_id"`
	ReviewID       string               `json:"review_id"`
	SnapshotSHA256 string               `json:"snapshot_sha256"`
	ReviewSHA256   string               `json:"review_sha256"`
	Identity       Identity             `json:"identity"`
	Safety         OffboardingSafety    `json:"safety"`
	Coverage       OffboardingCoverage  `json:"coverage"`
	Summary        OffboardingSummary   `json:"summary"`
	Keys           []OffboardingKey     `json:"keys"`
	Warnings       []OffboardingWarning `json:"warnings,omitempty"`
}

type OffboardingSafety struct {
	Mode                  string `json:"mode"`
	RemoteChanges         bool   `json:"remote_changes"`
	Executable            bool   `json:"executable"`
	SourceDigestsIncluded bool   `json:"source_digests_included"`
	RequiresFreshScan     bool   `json:"requires_fresh_scan_before_remediation"`
}

type OffboardingCoverage struct {
	HostsRequested     int      `json:"hosts_requested"`
	HostsFull          int      `json:"hosts_full"`
	HostsPartial       int      `json:"hosts_partial"`
	HostsFailed        int      `json:"hosts_failed"`
	IncompleteHosts    []string `json:"incomplete_hosts,omitempty"`
	DynamicSourceHosts []string `json:"dynamic_source_hosts,omitempty"`
	Caveat             string   `json:"caveat,omitempty"`
}

type OffboardingSummary struct {
	ClaimedKeys            int `json:"claimed_keys"`
	ObservedKeys           int `json:"observed_keys"`
	MappedKeysNotObserved  int `json:"mapped_keys_not_observed"`
	AccessEdges            int `json:"access_edges"`
	Hosts                  int `json:"hosts"`
	Accounts               int `json:"accounts"`
	SharedKeys             int `json:"shared_keys"`
	PossessionVerifiedKeys int `json:"possession_verified_keys"`
	UnverifiedClaimKeys    int `json:"unverified_claim_keys"`
	WarningsTotal          int `json:"warnings_total"`
	WarningsHigh           int `json:"warnings_high"`
	WarningsMedium         int `json:"warnings_medium"`
	WarningsInfo           int `json:"warnings_info"`
}

type OffboardingKey struct {
	Fingerprint   string                   `json:"fingerprint"`
	Observed      bool                     `json:"observed"`
	Algorithm     string                   `json:"algorithm,omitempty"`
	Bits          int                      `json:"bits,omitempty"`
	SelectedClaim ResolvedOwnershipClaim   `json:"selected_claim"`
	OtherClaims   []ResolvedOwnershipClaim `json:"other_claims,omitempty"`
	Shared        bool                     `json:"shared"`
	Access        []OffboardingAccess      `json:"access,omitempty"`
}

type OffboardingAccess struct {
	Host     string   `json:"host"`
	Account  string   `json:"account"`
	Source   string   `json:"source"`
	Line     int      `json:"line"`
	Coverage string   `json:"coverage"`
	Options  []string `json:"authorized_key_options,omitempty"`
}

type OffboardingWarning struct {
	Code        string   `json:"code"`
	Severity    string   `json:"severity"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Message     string   `json:"message"`
	Action      string   `json:"action"`
}

func BuildOffboardingReport(snapshot *Snapshot, review *OwnershipReview, identityID string) (*OffboardingReport, error) {
	if err := ValidateOwnershipReviewAgainstSnapshot(review, snapshot); err != nil {
		return nil, err
	}
	identityID = strings.TrimSpace(identityID)
	var selected Identity
	found := false
	for _, identity := range review.Identities {
		if identity.ID == identityID {
			selected, found = identity, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("identity %q is not present in ownership review", identityID)
	}
	snapshotDigest, err := offboardingDigest(snapshot)
	if err != nil {
		return nil, err
	}
	reviewDigest, err := offboardingDigest(review)
	if err != nil {
		return nil, err
	}
	report := &OffboardingReport{
		SchemaVersion: OffboardingReportSchemaVersion,
		ScanID:        snapshot.ScanID, ReviewID: review.ReviewID,
		SnapshotSHA256: snapshotDigest, ReviewSHA256: reviewDigest,
		Identity: selected,
		Safety: OffboardingSafety{
			Mode: OffboardingReportMode, RequiresFreshScan: true,
		},
		Coverage: buildOffboardingCoverage(snapshot),
		Keys:     []OffboardingKey{},
	}
	accessByKey := offboardingAccessByFingerprint(snapshot)
	for _, reviewedKey := range review.Keys {
		for _, claim := range reviewedKey.Claims {
			if claim.IdentityID != identityID {
				continue
			}
			key := OffboardingKey{
				Fingerprint: reviewedKey.Fingerprint, Observed: reviewedKey.Observed,
				Algorithm: reviewedKey.Algorithm, Bits: reviewedKey.Bits,
				SelectedClaim: claim, Shared: len(reviewedKey.Claims) > 1,
				Access: append([]OffboardingAccess(nil), accessByKey[reviewedKey.Fingerprint]...),
			}
			for _, other := range reviewedKey.Claims {
				if other.IdentityID != identityID {
					key.OtherClaims = append(key.OtherClaims, other)
				}
			}
			report.Keys = append(report.Keys, key)
		}
	}
	normalizeOffboardingReport(report)
	report.Summary = deriveOffboardingSummary(report.Keys, nil)
	report.Warnings = deriveOffboardingWarnings(report)
	report.Summary = deriveOffboardingSummary(report.Keys, report.Warnings)
	report.ReportID, err = offboardingReportID(report)
	if err != nil {
		return nil, err
	}
	if err := ValidateOffboardingReport(report); err != nil {
		return nil, err
	}
	return report, nil
}

func ValidateOffboardingReport(report *OffboardingReport) error {
	if report == nil {
		return invalidOffboardingReport("report is nil")
	}
	if report.SchemaVersion != OffboardingReportSchemaVersion {
		return invalidOffboardingReport("unsupported schema_version %q", report.SchemaVersion)
	}
	if report.ReportID == "" || strings.TrimSpace(report.ScanID) == "" || strings.TrimSpace(report.ReviewID) == "" {
		return invalidOffboardingReport("report_id, scan_id, and review_id are required")
	}
	if err := validIdentityText(report.ScanID, false); err != nil {
		return invalidOffboardingReport("scan_id: %v", err)
	}
	if hasUnsafeOffboardingRune(report.ScanID) {
		return invalidOffboardingReport("scan_id contains control or formatting characters")
	}
	if err := validIdentityText(report.ReviewID, false); err != nil {
		return invalidOffboardingReport("review_id: %v", err)
	}
	if hasUnsafeOffboardingRune(report.ReviewID) {
		return invalidOffboardingReport("review_id contains control or formatting characters")
	}
	if !validOffboardingDigest(report.SnapshotSHA256) || !validOffboardingDigest(report.ReviewSHA256) {
		return invalidOffboardingReport("input SHA256 digests are invalid")
	}
	if err := validateOffboardingIdentity(report.Identity); err != nil {
		return invalidOffboardingReport("identity: %v", err)
	}
	if report.Safety != (OffboardingSafety{Mode: OffboardingReportMode, RequiresFreshScan: true}) {
		return invalidOffboardingReport("safety contract must remain report-only, non-executable, and require a fresh scan")
	}
	if report.Keys == nil {
		return invalidOffboardingReport("keys must be present (use an empty array when the identity has no claims)")
	}
	if err := validateOffboardingCoverage(report.Coverage); err != nil {
		return err
	}
	previousFingerprint := ""
	for keyIndex, key := range report.Keys {
		if !validSHA256Fingerprint(key.Fingerprint) || previousFingerprint != "" && key.Fingerprint <= previousFingerprint {
			return invalidOffboardingReport("keys[%d] has an invalid, duplicate, or unsorted fingerprint", keyIndex)
		}
		previousFingerprint = key.Fingerprint
		if err := validateResolvedClaim(key.SelectedClaim, report.Identity.ID); err != nil {
			return invalidOffboardingReport("key %q selected claim: %v", key.Fingerprint, err)
		}
		if key.SelectedClaim.DisplayName != report.Identity.DisplayName || key.SelectedClaim.Kind != report.Identity.Kind || key.SelectedClaim.IdentityStatus != report.Identity.Status {
			return invalidOffboardingReport("key %q selected claim does not match identity record", key.Fingerprint)
		}
		previousClaim := ""
		for claimIndex, claim := range key.OtherClaims {
			if claim.IdentityID == report.Identity.ID || previousClaim != "" && claim.IdentityID <= previousClaim {
				return invalidOffboardingReport("key %q other_claims[%d] is selected, duplicate, or unsorted", key.Fingerprint, claimIndex)
			}
			if err := validateResolvedClaim(claim, ""); err != nil {
				return invalidOffboardingReport("key %q other_claims[%d]: %v", key.Fingerprint, claimIndex, err)
			}
			previousClaim = claim.IdentityID
		}
		if key.Shared != (len(key.OtherClaims) > 0) {
			return invalidOffboardingReport("key %q shared flag does not reconcile", key.Fingerprint)
		}
		if key.Observed != (len(key.Access) > 0) {
			return invalidOffboardingReport("key %q observed flag does not reconcile with access evidence", key.Fingerprint)
		}
		if key.Observed && key.Algorithm == "" || key.Bits < 0 || !key.Observed && (key.Algorithm != "" || key.Bits != 0) {
			return invalidOffboardingReport("key %q algorithm metadata does not reconcile", key.Fingerprint)
		}
		if key.Algorithm != "" {
			if err := validOffboardingEvidenceText(key.Algorithm, false); err != nil {
				return invalidOffboardingReport("key %q algorithm: %v", key.Fingerprint, err)
			}
		}
		previousEdge := ""
		for edgeIndex, edge := range key.Access {
			if err := validateOffboardingAccess(edge); err != nil {
				return invalidOffboardingReport("key %q access[%d]: %v", key.Fingerprint, edgeIndex, err)
			}
			edgeID := offboardingAccessID(edge)
			if previousEdge != "" && edgeID <= previousEdge {
				return invalidOffboardingReport("key %q access edges are duplicate or unsorted", key.Fingerprint)
			}
			previousEdge = edgeID
		}
	}
	expectedSummary := deriveOffboardingSummary(report.Keys, report.Warnings)
	if report.Summary != expectedSummary {
		return invalidOffboardingReport("summary does not reconcile: got %+v, derived %+v", report.Summary, expectedSummary)
	}
	expectedWarnings := deriveOffboardingWarnings(report)
	if !reflect.DeepEqual(report.Warnings, expectedWarnings) {
		return invalidOffboardingReport("warnings do not match report evidence")
	}
	expectedID, err := offboardingReportID(report)
	if err != nil || report.ReportID != expectedID {
		return invalidOffboardingReport("report_id does not match report content")
	}
	return nil
}

func RenderOffboardingReportJSON(report *OffboardingReport) ([]byte, error) {
	if err := ValidateOffboardingReport(report); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal offboarding report: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxOffboardingReportBytes {
		return nil, fmt.Errorf("offboarding report is %d bytes; limit is %d", len(data), maxOffboardingReportBytes)
	}
	return data, nil
}

func WriteOffboardingReportJSON(path string, report *OffboardingReport) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("offboarding report JSON output path is empty")
	}
	data, err := RenderOffboardingReportJSON(report)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadOffboardingReport(path string) (*OffboardingReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open offboarding report %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > maxOffboardingReportBytes {
		return nil, fmt.Errorf("offboarding report is %d bytes; limit is %d", stat.Size(), maxOffboardingReportBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxOffboardingReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read offboarding report: %w", err)
	}
	if len(data) > maxOffboardingReportBytes {
		return nil, fmt.Errorf("offboarding report exceeds %d bytes", maxOffboardingReportBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report OffboardingReport
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("parse offboarding report: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("offboarding report contains more than one JSON value")
		}
		return nil, fmt.Errorf("parse trailing offboarding report data: %w", err)
	}
	if err := ValidateOffboardingReport(&report); err != nil {
		return nil, err
	}
	return &report, nil
}

func RenderOffboardingReportText(report *OffboardingReport) string {
	if report == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "SSH Offboarding Report  %s\n\n", report.ReportID)
	fmt.Fprintf(&output, "Identity:       %s", report.Identity.ID)
	if report.Identity.DisplayName != "" {
		fmt.Fprintf(&output, " (%s)", report.Identity.DisplayName)
	}
	fmt.Fprintf(&output, "\nLifecycle:      %s\n", report.Identity.Status)
	fmt.Fprintf(&output, "Scan / review:  %s / %s\n", report.ScanID, report.ReviewID)
	fmt.Fprintf(&output, "Keys / edges:   %d / %d\n", report.Summary.ClaimedKeys, report.Summary.AccessEdges)
	fmt.Fprintf(&output, "Hosts / accounts: %d / %d\n", report.Summary.Hosts, report.Summary.Accounts)
	fmt.Fprintf(&output, "Coverage:       %d full / %d partial / %d failed\n", report.Coverage.HostsFull, report.Coverage.HostsPartial, report.Coverage.HostsFailed)
	fmt.Fprintln(&output, "Mode:           report_only; remote changes: false; executable: false")
	if report.Coverage.Caveat != "" {
		fmt.Fprintf(&output, "Caution:        %s\n", report.Coverage.Caveat)
	}
	fmt.Fprintln(&output, "\nWarnings")
	if len(report.Warnings) == 0 {
		fmt.Fprintln(&output, "  none")
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(&output, "  [%s] %s: %s\n", warning.Severity, warning.Code, warning.Message)
	}
	fmt.Fprintln(&output, "\nObserved evidence")
	for _, key := range report.Keys {
		fmt.Fprintf(&output, "  %s  [%s", key.Fingerprint, key.SelectedClaim.Verification)
		if key.Shared {
			fmt.Fprint(&output, ", SHARED")
		}
		fmt.Fprintln(&output, "]")
		if len(key.Access) == 0 {
			fmt.Fprintln(&output, "    mapped but not observed in this snapshot")
		}
		for _, edge := range key.Access {
			fmt.Fprintf(&output, "    -> %s@%s  %s:%d  coverage=%s\n", edge.Account, edge.Host, edge.Source, edge.Line, edge.Coverage)
		}
	}
	fmt.Fprintln(&output, "\nThis report is read-only evidence, not an executable removal plan. A future remediation workflow must re-scan and bind source-file digests before changing access.")
	return output.String()
}

func buildOffboardingCoverage(snapshot *Snapshot) OffboardingCoverage {
	coverage := OffboardingCoverage{
		HostsRequested: snapshot.Summary.HostsRequested, HostsFull: snapshot.Summary.HostsFull,
		HostsPartial: snapshot.Summary.HostsPartial, HostsFailed: snapshot.Summary.HostsFailed,
	}
	for _, host := range snapshot.Hosts {
		if host.Coverage != CoverageFull {
			coverage.IncompleteHosts = append(coverage.IncompleteHosts, host.Alias)
		}
	}
	dynamic := map[string]bool{}
	for _, finding := range snapshot.Findings {
		switch finding.RuleID {
		case "external_key_source", "trusted_ssh_ca_detected", "external_principals_source":
			if finding.Host != "" {
				dynamic[finding.Host] = true
			}
		}
	}
	coverage.DynamicSourceHosts = sortedSet(dynamic)
	if coverage.HostsPartial > 0 || coverage.HostsFailed > 0 || len(coverage.DynamicSourceHosts) > 0 {
		coverage.Caveat = offboardingCoverageCaveat
	}
	return coverage
}

func offboardingAccessByFingerprint(snapshot *Snapshot) map[string][]OffboardingAccess {
	rows := map[string][]OffboardingAccess{}
	for _, host := range snapshot.Hosts {
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					if entry.ParseError != "" || entry.Fingerprint == "" {
						continue
					}
					rows[entry.Fingerprint] = append(rows[entry.Fingerprint], OffboardingAccess{
						Host: host.Alias, Account: account.Username, Source: source.Path,
						Line: entry.Line, Coverage: host.Coverage, Options: append([]string(nil), entry.Options...),
					})
				}
			}
		}
	}
	for fingerprint := range rows {
		sort.Slice(rows[fingerprint], func(i, j int) bool {
			return offboardingAccessID(rows[fingerprint][i]) < offboardingAccessID(rows[fingerprint][j])
		})
	}
	return rows
}

func deriveOffboardingSummary(keys []OffboardingKey, warnings []OffboardingWarning) OffboardingSummary {
	summary := OffboardingSummary{ClaimedKeys: len(keys)}
	hosts, accounts := map[string]bool{}, map[string]bool{}
	for _, key := range keys {
		if key.Observed {
			summary.ObservedKeys++
		} else {
			summary.MappedKeysNotObserved++
		}
		if key.Shared {
			summary.SharedKeys++
		}
		if key.SelectedClaim.Verification == ClaimStatusVerified {
			summary.PossessionVerifiedKeys++
		} else {
			summary.UnverifiedClaimKeys++
		}
		for _, edge := range key.Access {
			summary.AccessEdges++
			hosts[edge.Host] = true
			accounts[edge.Account+"\x00"+edge.Host] = true
		}
	}
	summary.Hosts, summary.Accounts = len(hosts), len(accounts)
	for _, warning := range warnings {
		summary.WarningsTotal++
		switch warning.Severity {
		case SeverityHigh:
			summary.WarningsHigh++
		case SeverityMedium:
			summary.WarningsMedium++
		default:
			summary.WarningsInfo++
		}
	}
	return summary
}

func deriveOffboardingWarnings(report *OffboardingReport) []OffboardingWarning {
	var warnings []OffboardingWarning
	if report.Identity.Status == IdentityStatusActive {
		warnings = append(warnings, OffboardingWarning{
			Code: "identity_still_active", Severity: SeverityInfo,
			Message: "The selected identity is still marked active in the reviewed identity map.",
			Action:  "Confirm lifecycle state before treating this report as offboarding evidence.",
		})
	}
	if len(report.Keys) == 0 {
		warnings = append(warnings, OffboardingWarning{
			Code: "identity_has_no_claimed_keys", Severity: SeverityMedium,
			Message: "The selected identity has no SSH key claim in this ownership review.",
			Action:  "Review identity mapping; this report cannot prove that the identity has no access.",
		})
	}
	if report.Identity.Status == IdentityStatusOffboarded && report.Summary.AccessEdges > 0 {
		warnings = append(warnings, OffboardingWarning{
			Code: "offboarded_access_observed", Severity: SeverityHigh,
			Message: fmt.Sprintf("An offboarded identity retains %d observed static SSH access edge(s).", report.Summary.AccessEdges),
			Action:  "Review every edge and prepare a separately preconditioned removal plan; do not delete from this report alone.",
		})
	}
	if report.Coverage.HostsPartial > 0 || report.Coverage.HostsFailed > 0 {
		warnings = append(warnings, OffboardingWarning{
			Code: "incomplete_coverage", Severity: SeverityInfo, Hosts: append([]string(nil), report.Coverage.IncompleteHosts...),
			Message: "One or more hosts have partial or failed scan coverage.",
			Action:  "Resolve coverage gaps before declaring offboarding complete.",
		})
	}
	if len(report.Coverage.DynamicSourceHosts) > 0 {
		warnings = append(warnings, OffboardingWarning{
			Code: "dynamic_or_certificate_sources", Severity: SeverityInfo, Hosts: append([]string(nil), report.Coverage.DynamicSourceHosts...),
			Message: "Dynamic key, principal, or SSH certificate sources require a separate identity-policy review.",
			Action:  "Review the upstream command or CA policy; static file evidence is insufficient.",
		})
	}
	for _, key := range report.Keys {
		if key.Shared {
			warnings = append(warnings, OffboardingWarning{
				Code: "shared_key_claim", Severity: SeverityMedium, Fingerprint: key.Fingerprint,
				Message: fmt.Sprintf("The fingerprint is also claimed by %d other identity or identities.", len(key.OtherClaims)),
				Action:  "Do not infer exclusive private-key ownership; coordinate replacement before removing shared access.",
			})
		}
		if !key.Observed {
			warnings = append(warnings, OffboardingWarning{
				Code: "mapped_key_not_observed", Severity: SeverityInfo, Fingerprint: key.Fingerprint,
				Message: "A mapped key was not observed in this snapshot.",
				Action:  "Treat this as an evidence gap, not proof that the key has no access elsewhere.",
			})
		}
		if key.SelectedClaim.Verification != ClaimStatusVerified {
			warnings = append(warnings, OffboardingWarning{
				Code: "claim_not_possession_verified", Severity: SeverityInfo, Fingerprint: key.Fingerprint,
				Message: "The ownership claim has not been possession-verified.",
				Action:  "Confirm the assignment with the owner or another authoritative source before remediation.",
			})
		}
	}
	sort.Slice(warnings, func(i, j int) bool {
		left, right := warnings[i], warnings[j]
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		return left.Fingerprint < right.Fingerprint
	})
	return warnings
}

func normalizeOffboardingReport(report *OffboardingReport) {
	sort.Strings(report.Coverage.IncompleteHosts)
	sort.Strings(report.Coverage.DynamicSourceHosts)
	for index := range report.Keys {
		sort.Slice(report.Keys[index].OtherClaims, func(i, j int) bool {
			return report.Keys[index].OtherClaims[i].IdentityID < report.Keys[index].OtherClaims[j].IdentityID
		})
		sort.Slice(report.Keys[index].Access, func(i, j int) bool {
			return offboardingAccessID(report.Keys[index].Access[i]) < offboardingAccessID(report.Keys[index].Access[j])
		})
	}
	sort.Slice(report.Keys, func(i, j int) bool { return report.Keys[i].Fingerprint < report.Keys[j].Fingerprint })
}

func validateOffboardingCoverage(coverage OffboardingCoverage) error {
	if coverage.HostsRequested < 0 || coverage.HostsFull < 0 || coverage.HostsPartial < 0 || coverage.HostsFailed < 0 || coverage.HostsFull+coverage.HostsPartial+coverage.HostsFailed != coverage.HostsRequested {
		return invalidOffboardingReport("coverage counters do not reconcile")
	}
	if len(coverage.IncompleteHosts) != coverage.HostsPartial+coverage.HostsFailed || !strictlySortedUnique(coverage.IncompleteHosts) || !strictlySortedUnique(coverage.DynamicSourceHosts) {
		return invalidOffboardingReport("coverage host lists do not reconcile or are not sorted and unique")
	}
	for _, host := range append(append([]string(nil), coverage.IncompleteHosts...), coverage.DynamicSourceHosts...) {
		if err := validOffboardingEvidenceText(host, false); err != nil {
			return invalidOffboardingReport("coverage host: %v", err)
		}
	}
	wantsCaveat := coverage.HostsPartial > 0 || coverage.HostsFailed > 0 || len(coverage.DynamicSourceHosts) > 0
	if (wantsCaveat && coverage.Caveat != offboardingCoverageCaveat) || (!wantsCaveat && coverage.Caveat != "") {
		return invalidOffboardingReport("coverage caveat does not reconcile")
	}
	return nil
}

func validateOffboardingIdentity(identity Identity) error {
	if err := validIdentityText(identity.ID, false); err != nil {
		return err
	}
	if err := validIdentityText(identity.DisplayName, true); err != nil {
		return err
	}
	if hasUnsafeOffboardingRune(identity.ID) || hasUnsafeOffboardingRune(identity.DisplayName) {
		return errors.New("identity text contains control or formatting characters")
	}
	if identity.Kind != IdentityKindHuman && identity.Kind != IdentityKindService {
		return errors.New("invalid kind")
	}
	if identity.Status != IdentityStatusActive && identity.Status != IdentityStatusOffboarded {
		return errors.New("invalid lifecycle status")
	}
	return nil
}

func validateResolvedClaim(claim ResolvedOwnershipClaim, expectedIdentity string) error {
	if err := validIdentityText(claim.IdentityID, false); err != nil {
		return err
	}
	if expectedIdentity != "" && claim.IdentityID != expectedIdentity {
		return errors.New("identity does not match selection")
	}
	if err := validIdentityText(claim.DisplayName, true); err != nil {
		return err
	}
	if hasUnsafeOffboardingRune(claim.IdentityID) || hasUnsafeOffboardingRune(claim.DisplayName) {
		return errors.New("claim identity text contains control or formatting characters")
	}
	if claim.Kind != IdentityKindHuman && claim.Kind != IdentityKindService || claim.IdentityStatus != IdentityStatusActive && claim.IdentityStatus != IdentityStatusOffboarded {
		return errors.New("invalid identity kind or status")
	}
	if claim.Verification != ClaimStatusClaimed && claim.Verification != ClaimStatusVerified {
		return errors.New("invalid verification state")
	}
	if err := validIdentityText(claim.Source, false); err != nil {
		return err
	}
	if hasUnsafeOffboardingRune(claim.Source) {
		return errors.New("claim source contains control or formatting characters")
	}
	if err := validOptionalRFC3339(claim.RecordedAt); err != nil {
		return err
	}
	if err := validOptionalRFC3339(claim.VerifiedAt); err != nil {
		return err
	}
	if claim.Verification == ClaimStatusVerified && claim.VerifiedAt == "" || claim.Verification == ClaimStatusClaimed && claim.VerifiedAt != "" {
		return errors.New("verification timestamp does not match status")
	}
	return nil
}

func validateOffboardingAccess(edge OffboardingAccess) error {
	for _, value := range []string{edge.Host, edge.Account, edge.Source} {
		if err := validOffboardingEvidenceText(value, false); err != nil {
			return err
		}
	}
	if edge.Line < 1 {
		return errors.New("line must be positive")
	}
	if edge.Coverage != CoverageFull && edge.Coverage != CoveragePartial && edge.Coverage != CoverageFailed {
		return errors.New("invalid coverage")
	}
	for _, option := range edge.Options {
		if err := validOffboardingEvidenceText(option, false); err != nil {
			return fmt.Errorf("authorized-key option: %w", err)
		}
	}
	return nil
}

// Evidence strings originate in a bounded snapshot, not in the smaller
// human-maintained identity map. Keep their original line budget so a valid
// long AuthorizedKeysFile path or authorized_keys option can still be
// represented without weakening the report's total-size bound.
func validOffboardingEvidenceText(value string, allowEmpty bool) error {
	if value == "" && allowEmpty {
		return nil
	}
	if value == "" {
		return errors.New("value is required")
	}
	if len(value) > maxAuthorizedKeyLineBytes {
		return fmt.Errorf("value exceeds %d bytes", maxAuthorizedKeyLineBytes)
	}
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("value contains invalid or multiline text")
	}
	if hasUnsafeOffboardingRune(value) {
		return errors.New("value contains control or formatting characters")
	}
	return nil
}

func hasUnsafeOffboardingRune(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0
}

func offboardingDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return "SHA256:" + hex.EncodeToString(hash[:]), nil
}

func validOffboardingDigest(value string) bool {
	if len(value) != len("SHA256:")+sha256.Size*2 || !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "SHA256:")
	decoded, err := hex.DecodeString(encoded)
	return err == nil && hex.EncodeToString(decoded) == encoded
}

func offboardingReportID(report *OffboardingReport) (string, error) {
	clone := *report
	clone.ReportID = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return "offboarding_" + hex.EncodeToString(hash[:12]), nil
}

func offboardingAccessID(edge OffboardingAccess) string {
	data, _ := json.Marshal(edge.Options)
	return edge.Host + "\x00" + edge.Account + "\x00" + edge.Source + fmt.Sprintf("\x00%012d\x00", edge.Line) + string(data)
}

func invalidOffboardingReport(format string, args ...any) error {
	return fmt.Errorf("invalid offboarding report v%s: %s", OffboardingReportSchemaVersion, fmt.Sprintf(format, args...))
}
