package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const OwnershipReviewSchemaVersion = "1"

const (
	OwnershipUnknown = "unknown"
	OwnershipOwned   = "owned"
	OwnershipShared  = "shared"
)

type OwnershipReview struct {
	SchemaVersion     string           `json:"schema_version"`
	ReviewID          string           `json:"review_id"`
	ScanID            string           `json:"scan_id"`
	IdentityMapDigest string           `json:"identity_map_digest"`
	Summary           OwnershipSummary `json:"summary"`
	Identities        []Identity       `json:"identities"`
	Keys              []ReviewedKey    `json:"keys"`
	Findings          []Finding        `json:"findings,omitempty"`
}

type OwnershipSummary struct {
	ObservedKeys           int `json:"observed_keys"`
	OwnedKeys              int `json:"owned_keys"`
	UnknownKeys            int `json:"unknown_keys"`
	SharedKeys             int `json:"shared_keys"`
	OffboardedAccessKeys   int `json:"offboarded_access_keys"`
	PossessionVerifiedKeys int `json:"possession_verified_keys"`
	MappedKeysNotObserved  int `json:"mapped_keys_not_observed"`
	ActiveIdentities       int `json:"active_identities"`
	OffboardedIdentities   int `json:"offboarded_identities"`
	FindingsTotal          int `json:"findings_total"`
	FindingsCritical       int `json:"findings_critical"`
	FindingsHigh           int `json:"findings_high"`
	FindingsMedium         int `json:"findings_medium"`
	FindingsLow            int `json:"findings_low"`
	FindingsInfo           int `json:"findings_info"`
}

type ReviewedKey struct {
	Fingerprint        string                   `json:"fingerprint"`
	Observed           bool                     `json:"observed"`
	IdentityMapEntry   bool                     `json:"identity_map_entry"`
	OwnershipStatus    string                   `json:"ownership_status"`
	OffboardedAccess   bool                     `json:"offboarded_access"`
	PossessionVerified bool                     `json:"possession_verified"`
	Algorithm          string                   `json:"algorithm,omitempty"`
	Bits               int                      `json:"bits,omitempty"`
	Occurrences        int                      `json:"occurrences"`
	Hosts              []string                 `json:"hosts,omitempty"`
	Accounts           []string                 `json:"accounts,omitempty"`
	IdentityHints      []string                 `json:"identity_hints,omitempty"`
	Claims             []ResolvedOwnershipClaim `json:"claims"`
}

type ResolvedOwnershipClaim struct {
	IdentityID     string `json:"identity"`
	DisplayName    string `json:"display_name,omitempty"`
	Kind           string `json:"kind"`
	IdentityStatus string `json:"identity_status"`
	Verification   string `json:"verification"`
	Source         string `json:"source"`
	RecordedAt     string `json:"recorded_at,omitempty"`
	VerifiedAt     string `json:"verified_at,omitempty"`
}

func BuildOwnershipReview(snapshot *Snapshot, identityMap *IdentityMap) (*OwnershipReview, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	if identityMap == nil {
		return nil, invalidIdentityMap("identity map is nil")
	}
	normalizedMap := *identityMap
	normalizedMap.Identities = append([]Identity(nil), identityMap.Identities...)
	normalizedMap.Keys = cloneIdentityKeys(identityMap.Keys)
	normalizeIdentityMap(&normalizedMap)
	identityMap = &normalizedMap
	if err := ValidateIdentityMap(identityMap); err != nil {
		return nil, err
	}
	digest, err := IdentityMapDigest(identityMap)
	if err != nil {
		return nil, err
	}
	review := &OwnershipReview{
		SchemaVersion: OwnershipReviewSchemaVersion,
		ScanID:        snapshot.ScanID, IdentityMapDigest: digest,
		ReviewID:   ownershipReviewID(snapshot.ScanID, digest),
		Identities: append([]Identity(nil), identityMap.Identities...),
	}
	identities := make(map[string]Identity, len(identityMap.Identities))
	for _, identity := range identityMap.Identities {
		identities[identity.ID] = identity
		if identity.Status == IdentityStatusOffboarded {
			review.Summary.OffboardedIdentities++
		} else {
			review.Summary.ActiveIdentities++
		}
	}
	mapped := make(map[string]IdentityKeyOwnership, len(identityMap.Keys))
	allFingerprints := map[string]bool{}
	for _, key := range identityMap.Keys {
		mapped[key.Fingerprint] = key
		allFingerprints[key.Fingerprint] = true
	}
	observed := observedKeyOccurrences(snapshot)
	for fingerprint := range observed {
		allFingerprints[fingerprint] = true
	}

	for _, fingerprint := range sortedSet(allFingerprints) {
		occurrences := observed[fingerprint]
		key := ReviewedKey{Fingerprint: fingerprint, Observed: len(occurrences) > 0, Claims: []ResolvedOwnershipClaim{}}
		if len(occurrences) > 0 {
			key.Algorithm = occurrences[0].algorithm
			for _, occurrence := range occurrences {
				if key.Algorithm == "" || (occurrence.algorithm != "" && occurrence.algorithm < key.Algorithm) {
					key.Algorithm = occurrence.algorithm
				}
				if occurrence.bits > key.Bits {
					key.Bits = occurrence.bits
				}
			}
			key.Occurrences = len(occurrences)
			key.Hosts = distinctOccurrenceHosts(occurrences)
			key.Accounts = distinctOccurrenceAccounts(occurrences)
			key.IdentityHints = distinctOccurrenceComments(occurrences)
		}
		mappedKey, inIdentityMap := mapped[fingerprint]
		key.IdentityMapEntry = inIdentityMap
		for _, claim := range mappedKey.Claims {
			identity := identities[claim.IdentityID]
			key.Claims = append(key.Claims, ResolvedOwnershipClaim{
				IdentityID: claim.IdentityID, DisplayName: identity.DisplayName,
				Kind: identity.Kind, IdentityStatus: identity.Status,
				Verification: claim.Status, Source: claim.Source,
				RecordedAt: claim.RecordedAt, VerifiedAt: claim.VerifiedAt,
			})
			// Lifecycle is an access finding only when this key was actually
			// observed in the scanned fleet. A stale map entry can still carry an
			// offboarded claim, but it is not evidence of remaining access.
			key.OffboardedAccess = key.OffboardedAccess || key.Observed && identity.Status == IdentityStatusOffboarded
			key.PossessionVerified = key.PossessionVerified || claim.Status == ClaimStatusVerified
		}
		switch len(key.Claims) {
		case 0:
			key.OwnershipStatus = OwnershipUnknown
		case 1:
			key.OwnershipStatus = OwnershipOwned
		default:
			key.OwnershipStatus = OwnershipShared
		}
		review.Keys = append(review.Keys, key)
		appendOwnershipFindings(review, key)
	}
	finalizeOwnershipSummary(review)
	if err := ValidateOwnershipReview(review); err != nil {
		return nil, err
	}
	return review, nil
}

func observedKeyOccurrences(snapshot *Snapshot) map[string][]keyOccurrence {
	observed := map[string][]keyOccurrence{}
	for _, host := range snapshot.Hosts {
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					if entry.ParseError != "" || entry.Fingerprint == "" {
						continue
					}
					observed[entry.Fingerprint] = append(observed[entry.Fingerprint], keyOccurrence{
						host: host.Alias, account: account.Username, source: source.Path,
						line: entry.Line, algorithm: entry.Algorithm, bits: entry.Bits, comment: entry.Comment,
					})
				}
			}
		}
	}
	return observed
}

func appendOwnershipFindings(review *OwnershipReview, key ReviewedKey) {
	if !key.Observed {
		if key.IdentityMapEntry {
			review.Findings = append(review.Findings, Finding{
				RuleID: "identity_map_key_not_observed", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
				Title: "Mapped SSH key is not present in this snapshot", Fingerprint: key.Fingerprint,
				Evidence:          []string{fmt.Sprintf("identity-map entry has %d ownership claim(s), but no access edge was observed", len(key.Claims))},
				CoverageCaveat:    "Absence from one snapshot is not proof that the key has no access elsewhere.",
				RecommendedAction: "Retain the mapping if it applies to another inventory, or review whether it is stale.",
			})
		}
		return
	}
	if key.OwnershipStatus == OwnershipUnknown {
		review.Findings = append(review.Findings, Finding{
			RuleID: "unknown_key", RuleVersion: FindingRuleVersion, Severity: SeverityMedium,
			Title: "Observed SSH key has no assigned identity", Fingerprint: key.Fingerprint,
			Occurrences: key.Occurrences, Hosts: key.Hosts,
			Evidence:          []string{fmt.Sprintf("fingerprint grants %d access edge(s) across %d host(s)", key.Occurrences, len(key.Hosts))},
			CoverageCaveat:    "authorized_keys comments are unverified hints and were not treated as owners.",
			RecommendedAction: "Ask the suspected owner to claim the fingerprint before changing access.",
		})
	}
	if key.OwnershipStatus == OwnershipShared {
		owners := make([]string, 0, len(key.Claims))
		for _, claim := range key.Claims {
			owners = append(owners, claim.IdentityID)
		}
		review.Findings = append(review.Findings, Finding{
			RuleID: "shared_key", RuleVersion: FindingRuleVersion, Severity: SeverityMedium,
			Title: "One SSH key is assigned to multiple identities", Fingerprint: key.Fingerprint,
			Occurrences: key.Occurrences, Hosts: key.Hosts,
			Evidence:          []string{"assigned identities: " + strings.Join(owners, ", ")},
			CoverageCaveat:    "Claims can be mistaken; this finding does not prove that private-key material was shared.",
			RecommendedAction: "Verify each claimant and replace shared private keys with individual credentials.",
		})
	}
	if key.OffboardedAccess {
		owners := []string{}
		for _, claim := range key.Claims {
			if claim.IdentityStatus == IdentityStatusOffboarded {
				owners = append(owners, claim.IdentityID)
			}
		}
		review.Findings = append(review.Findings, Finding{
			RuleID: "offboarded_identity_access", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
			Title: "Offboarded identity still has observed SSH access", Fingerprint: key.Fingerprint,
			Occurrences: key.Occurrences, Hosts: key.Hosts,
			Evidence:          []string{"offboarded identities: " + strings.Join(owners, ", ")},
			CoverageCaveat:    "This is a read-only observation; no access has been removed.",
			RecommendedAction: "Confirm the offboarding record and prepare a reviewed removal plan for every observed access edge.",
		})
	}
}

func finalizeOwnershipSummary(review *OwnershipReview) {
	for _, key := range review.Keys {
		if !key.Observed {
			if key.IdentityMapEntry {
				review.Summary.MappedKeysNotObserved++
			}
			continue
		}
		review.Summary.ObservedKeys++
		if len(key.Claims) > 0 {
			review.Summary.OwnedKeys++
		}
		if key.OwnershipStatus == OwnershipUnknown {
			review.Summary.UnknownKeys++
		}
		if key.OwnershipStatus == OwnershipShared {
			review.Summary.SharedKeys++
		}
		if key.OffboardedAccess {
			review.Summary.OffboardedAccessKeys++
		}
		if key.PossessionVerified {
			review.Summary.PossessionVerifiedKeys++
		}
	}
	sortOwnershipFindings(review.Findings)
	for _, finding := range review.Findings {
		review.Summary.FindingsTotal++
		switch finding.Severity {
		case SeverityCritical:
			review.Summary.FindingsCritical++
		case SeverityHigh:
			review.Summary.FindingsHigh++
		case SeverityMedium:
			review.Summary.FindingsMedium++
		case SeverityLow:
			review.Summary.FindingsLow++
		default:
			review.Summary.FindingsInfo++
		}
	}
}

func sortOwnershipFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}

func ValidateOwnershipReview(review *OwnershipReview) error {
	if review == nil {
		return errors.New("invalid ownership review v1: review is nil")
	}
	if review.SchemaVersion != OwnershipReviewSchemaVersion || review.ReviewID == "" || review.ScanID == "" {
		return errors.New("invalid ownership review v1: schema_version, review_id, and scan_id are required")
	}
	if len(review.IdentityMapDigest) != len("SHA256:")+sha256.Size*2 || !strings.HasPrefix(review.IdentityMapDigest, "SHA256:") {
		return errors.New("invalid ownership review v1: identity_map_digest is invalid")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(review.IdentityMapDigest, "SHA256:")); err != nil {
		return errors.New("invalid ownership review v1: identity_map_digest is invalid")
	}
	if review.ReviewID != ownershipReviewID(review.ScanID, review.IdentityMapDigest) {
		return errors.New("invalid ownership review v1: review_id does not match its inputs")
	}
	derived := OwnershipSummary{}
	identityIndex := map[string]Identity{}
	identityEnvelope := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities:    append([]Identity(nil), review.Identities...),
		Keys:          []IdentityKeyOwnership{},
	}
	if err := ValidateIdentityMap(identityEnvelope); err != nil {
		return fmt.Errorf("invalid ownership review v1: identities: %w", err)
	}
	previousIdentity := ""
	for _, identity := range review.Identities {
		if previousIdentity != "" && identity.ID <= previousIdentity {
			return errors.New("invalid ownership review v1: identities are not sorted by id")
		}
		previousIdentity = identity.ID
		identityIndex[identity.ID] = identity
		if identity.Status == IdentityStatusOffboarded {
			derived.OffboardedIdentities++
		} else {
			derived.ActiveIdentities++
		}
	}
	seen := map[string]bool{}
	previousFingerprint := ""
	reconstructedMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities:    append([]Identity(nil), review.Identities...),
	}
	for index, key := range review.Keys {
		if !validSHA256Fingerprint(key.Fingerprint) || seen[key.Fingerprint] {
			return fmt.Errorf("invalid ownership review v1: keys[%d] has invalid or duplicate fingerprint", index)
		}
		if previousFingerprint != "" && key.Fingerprint <= previousFingerprint {
			return errors.New("invalid ownership review v1: keys are not sorted by fingerprint")
		}
		previousFingerprint = key.Fingerprint
		seen[key.Fingerprint] = true
		if key.OwnershipStatus != OwnershipUnknown && key.OwnershipStatus != OwnershipOwned && key.OwnershipStatus != OwnershipShared {
			return fmt.Errorf("invalid ownership review v1: key %q has invalid ownership_status", key.Fingerprint)
		}
		if !key.Observed && !key.IdentityMapEntry {
			return fmt.Errorf("invalid ownership review v1: key %q is neither observed nor present in the identity map", key.Fingerprint)
		}
		if key.OwnershipStatus == OwnershipUnknown && len(key.Claims) != 0 || key.OwnershipStatus == OwnershipOwned && len(key.Claims) != 1 || key.OwnershipStatus == OwnershipShared && len(key.Claims) < 2 {
			return fmt.Errorf("invalid ownership review v1: key %q ownership status does not match claims", key.Fingerprint)
		}
		claimIDs := map[string]bool{}
		offboarded, verified := false, false
		previousClaim := ""
		mapKey := IdentityKeyOwnership{Fingerprint: key.Fingerprint, Claims: []OwnershipClaim{}}
		for claimIndex, claim := range key.Claims {
			if err := validIdentityText(claim.IdentityID, false); err != nil || claimIDs[claim.IdentityID] {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] has invalid or duplicate identity", key.Fingerprint, claimIndex)
			}
			if previousClaim != "" && claim.IdentityID <= previousClaim {
				return fmt.Errorf("invalid ownership review v1: key %q claims are not sorted", key.Fingerprint)
			}
			previousClaim = claim.IdentityID
			claimIDs[claim.IdentityID] = true
			identity, exists := identityIndex[claim.IdentityID]
			if !exists || identity.DisplayName != claim.DisplayName || identity.Kind != claim.Kind || identity.Status != claim.IdentityStatus {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] does not match identity record", key.Fingerprint, claimIndex)
			}
			if err := validIdentityText(claim.DisplayName, true); err != nil {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] display_name: %v", key.Fingerprint, claimIndex, err)
			}
			if claim.Kind != IdentityKindHuman && claim.Kind != IdentityKindService {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] has invalid identity kind", key.Fingerprint, claimIndex)
			}
			if claim.IdentityStatus != IdentityStatusActive && claim.IdentityStatus != IdentityStatusOffboarded {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] has invalid identity status", key.Fingerprint, claimIndex)
			}
			if claim.Verification != ClaimStatusClaimed && claim.Verification != ClaimStatusVerified {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] has invalid verification", key.Fingerprint, claimIndex)
			}
			if err := validIdentityText(claim.Source, false); err != nil {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] source: %v", key.Fingerprint, claimIndex, err)
			}
			if err := validOptionalRFC3339(claim.RecordedAt); err != nil {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] recorded_at: %v", key.Fingerprint, claimIndex, err)
			}
			if err := validOptionalRFC3339(claim.VerifiedAt); err != nil {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] verified_at: %v", key.Fingerprint, claimIndex, err)
			}
			if claim.Verification == ClaimStatusVerified && claim.VerifiedAt == "" || claim.Verification == ClaimStatusClaimed && claim.VerifiedAt != "" {
				return fmt.Errorf("invalid ownership review v1: key %q claim[%d] verification timestamp does not match status", key.Fingerprint, claimIndex)
			}
			offboarded = offboarded || key.Observed && claim.IdentityStatus == IdentityStatusOffboarded
			verified = verified || claim.Verification == ClaimStatusVerified
			mapKey.Claims = append(mapKey.Claims, OwnershipClaim{
				IdentityID: claim.IdentityID, Status: claim.Verification, Source: claim.Source,
				RecordedAt: claim.RecordedAt, VerifiedAt: claim.VerifiedAt,
			})
		}
		if !key.IdentityMapEntry && len(key.Claims) > 0 {
			return fmt.Errorf("invalid ownership review v1: key %q has claims without an identity-map entry", key.Fingerprint)
		}
		if key.IdentityMapEntry {
			reconstructedMap.Keys = append(reconstructedMap.Keys, mapKey)
		}
		if key.OffboardedAccess != offboarded || key.PossessionVerified != verified {
			return fmt.Errorf("invalid ownership review v1: key %q claim flags do not reconcile", key.Fingerprint)
		}
		if !strictlySortedUnique(key.Hosts) || !strictlySortedUnique(key.Accounts) || !strictlySortedUnique(key.IdentityHints) {
			return fmt.Errorf("invalid ownership review v1: key %q evidence lists are not sorted and unique", key.Fingerprint)
		}
		if key.Observed {
			if key.Algorithm == "" || key.Bits < 0 || key.Occurrences < 1 || len(key.Hosts) == 0 || len(key.Accounts) == 0 || key.Occurrences < len(key.Hosts) || key.Occurrences < len(key.Accounts) || key.Occurrences < len(key.IdentityHints) {
				return fmt.Errorf("invalid ownership review v1: observed key %q lacks access evidence", key.Fingerprint)
			}
			derived.ObservedKeys++
			if len(key.Claims) > 0 {
				derived.OwnedKeys++
			}
			if key.OwnershipStatus == OwnershipUnknown {
				derived.UnknownKeys++
			}
			if key.OwnershipStatus == OwnershipShared {
				derived.SharedKeys++
			}
			if key.OffboardedAccess {
				derived.OffboardedAccessKeys++
			}
			if key.PossessionVerified {
				derived.PossessionVerifiedKeys++
			}
		} else {
			if key.Algorithm != "" || key.Bits != 0 || key.Occurrences != 0 || len(key.Hosts) != 0 || len(key.Accounts) != 0 || len(key.IdentityHints) != 0 {
				return fmt.Errorf("invalid ownership review v1: unobserved key %q carries access evidence", key.Fingerprint)
			}
			derived.MappedKeysNotObserved++
		}
	}
	if err := ValidateIdentityMap(reconstructedMap); err != nil {
		return fmt.Errorf("invalid ownership review v1: reconstructed identity map: %w", err)
	}
	reconstructedDigest, err := IdentityMapDigest(reconstructedMap)
	if err != nil || reconstructedDigest != review.IdentityMapDigest {
		return errors.New("invalid ownership review v1: identity-map content does not match identity_map_digest")
	}
	for _, finding := range review.Findings {
		derived.FindingsTotal++
		switch finding.Severity {
		case SeverityCritical:
			derived.FindingsCritical++
		case SeverityHigh:
			derived.FindingsHigh++
		case SeverityMedium:
			derived.FindingsMedium++
		case SeverityLow:
			derived.FindingsLow++
		case SeverityInfo:
			derived.FindingsInfo++
		default:
			return fmt.Errorf("invalid ownership review v1: invalid finding severity %q", finding.Severity)
		}
	}
	if review.Summary != derived {
		return fmt.Errorf("invalid ownership review v1: summary does not reconcile: got %+v, derived %+v", review.Summary, derived)
	}
	expected := &OwnershipReview{Keys: review.Keys}
	for _, key := range expected.Keys {
		appendOwnershipFindings(expected, key)
	}
	sortOwnershipFindings(expected.Findings)
	if !reflect.DeepEqual(review.Findings, expected.Findings) {
		return errors.New("invalid ownership review v1: findings do not match reviewed key evidence")
	}
	return nil
}

// ValidateOwnershipReviewAgainstSnapshot verifies that a standalone review is
// not merely internally consistent, but was derived from the selected
// snapshot and its embedded identity map. authorized_keys comments are
// deliberately excluded from this join: an upload plan may redact those
// unverified hints without changing ownership claims or observed access.
func ValidateOwnershipReviewAgainstSnapshot(review *OwnershipReview, snapshot *Snapshot) error {
	if err := ValidateOwnershipReview(review); err != nil {
		return err
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return err
	}
	if review.ScanID != snapshot.ScanID {
		return fmt.Errorf("ownership review scan_id %q does not match latest workspace scan %q", review.ScanID, snapshot.ScanID)
	}
	identityMap := identityMapFromOwnershipReview(review)
	expected, err := BuildOwnershipReview(snapshot, identityMap)
	if err != nil {
		return fmt.Errorf("rebuild ownership review against latest snapshot: %w", err)
	}
	actualComparable := ownershipReviewWithoutIdentityHints(review)
	expectedComparable := ownershipReviewWithoutIdentityHints(expected)
	if !reflect.DeepEqual(actualComparable, expectedComparable) {
		return errors.New("ownership review does not reconcile with the latest workspace snapshot")
	}
	return nil
}

func identityMapFromOwnershipReview(review *OwnershipReview) *IdentityMap {
	identityMap := &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities:    append([]Identity(nil), review.Identities...),
	}
	for _, key := range review.Keys {
		if !key.IdentityMapEntry {
			continue
		}
		mapped := IdentityKeyOwnership{Fingerprint: key.Fingerprint, Claims: []OwnershipClaim{}}
		for _, claim := range key.Claims {
			mapped.Claims = append(mapped.Claims, OwnershipClaim{
				IdentityID: claim.IdentityID, Status: claim.Verification, Source: claim.Source,
				RecordedAt: claim.RecordedAt, VerifiedAt: claim.VerifiedAt,
			})
		}
		identityMap.Keys = append(identityMap.Keys, mapped)
	}
	return identityMap
}

func ownershipReviewWithoutIdentityHints(review *OwnershipReview) *OwnershipReview {
	clone := *review
	clone.Identities = append([]Identity(nil), review.Identities...)
	clone.Keys = append([]ReviewedKey(nil), review.Keys...)
	for index := range clone.Keys {
		clone.Keys[index].Hosts = append([]string(nil), review.Keys[index].Hosts...)
		clone.Keys[index].Accounts = append([]string(nil), review.Keys[index].Accounts...)
		clone.Keys[index].IdentityHints = nil
		clone.Keys[index].Claims = append([]ResolvedOwnershipClaim(nil), review.Keys[index].Claims...)
	}
	clone.Findings = append([]Finding(nil), review.Findings...)
	return &clone
}

func RenderOwnershipReviewText(review *OwnershipReview) string {
	if review == nil {
		return ""
	}
	var output strings.Builder
	fmt.Fprintf(&output, "SSH Ownership Review  %s\n\n", review.ReviewID)
	fmt.Fprintf(&output, "Observed keys:              %d\n", review.Summary.ObservedKeys)
	fmt.Fprintf(&output, "Owned / unknown / shared:   %d / %d / %d\n", review.Summary.OwnedKeys, review.Summary.UnknownKeys, review.Summary.SharedKeys)
	fmt.Fprintf(&output, "Offboarded access keys:     %d\n", review.Summary.OffboardedAccessKeys)
	fmt.Fprintf(&output, "Possession-verified keys:   %d\n", review.Summary.PossessionVerifiedKeys)
	fmt.Fprintf(&output, "Mapped but not observed:    %d\n", review.Summary.MappedKeysNotObserved)
	fmt.Fprintf(&output, "Findings high / medium:     %d / %d\n", review.Summary.FindingsHigh, review.Summary.FindingsMedium)
	fmt.Fprintln(&output, "\nOwnership findings")
	if len(review.Findings) == 0 {
		fmt.Fprintln(&output, "  none")
	}
	for _, finding := range review.Findings {
		fmt.Fprintf(&output, "  [%s] %s: %s (%s)\n", finding.Severity, finding.RuleID, finding.Title, finding.Fingerprint)
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(&output, "    evidence: %s\n", evidence)
		}
	}
	fmt.Fprintln(&output, "\nKeys")
	for _, key := range review.Keys {
		observed := "mapped only"
		if key.Observed {
			observed = fmt.Sprintf("%d edge(s), %d host(s)", key.Occurrences, len(key.Hosts))
		}
		flags := []string{key.OwnershipStatus}
		if key.OffboardedAccess {
			flags = append(flags, "OFFBOARDED")
		}
		if key.PossessionVerified {
			flags = append(flags, "possession-verified")
		}
		fmt.Fprintf(&output, "  %s  [%s]  %s\n", key.Fingerprint, strings.Join(flags, ", "), observed)
		for _, claim := range key.Claims {
			fmt.Fprintf(&output, "    owner: %s (%s, %s) [%s]\n", claim.IdentityID, claim.Kind, claim.IdentityStatus, claim.Verification)
		}
	}
	return output.String()
}

func RenderOwnershipReviewJSON(review *OwnershipReview) ([]byte, error) {
	if err := ValidateOwnershipReview(review); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(review, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal ownership review: %w", err)
	}
	return append(data, '\n'), nil
}

func WriteOwnershipReviewJSON(path string, review *OwnershipReview) error {
	data, err := RenderOwnershipReviewJSON(review)
	if err != nil {
		return err
	}
	return writePrivateFile(path, data)
}

func ReadOwnershipReview(path string) (*OwnershipReview, error) {
	var review OwnershipReview
	if err := readBoundedJSON(path, "ownership review", &review); err != nil {
		return nil, err
	}
	if err := ValidateOwnershipReview(&review); err != nil {
		return nil, err
	}
	return &review, nil
}

func ownershipReviewID(scanID, digest string) string {
	hash := sha256.Sum256([]byte(scanID + "\x00" + digest))
	return "review_" + hex.EncodeToString(hash[:12])
}

func distinctOccurrenceAccounts(occurrences []keyOccurrence) []string {
	set := map[string]bool{}
	for _, occurrence := range occurrences {
		set[occurrence.account+"@"+occurrence.host] = true
	}
	return sortedSet(set)
}

func strictlySortedUnique(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] <= values[index-1] {
			return false
		}
	}
	return true
}
