package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	IdentityMapSchemaVersion = "1"
	IdentityKindHuman        = "human"
	IdentityKindService      = "service"
	IdentityStatusActive     = "active"
	IdentityStatusOffboarded = "offboarded"
	ClaimStatusClaimed       = "claimed_by_identity"
	ClaimStatusVerified      = "possession_verified"
	maxIdentityMapBytes      = 8 << 20
	maxIdentityTextBytes     = 1024
)

const identityMapEditingGuide = `# Editing guide (replace the fields below; do not add duplicate top-level keys):
#
# identities:
#   - id: alice@example.com
#     display_name: Alice
#     kind: human              # human | service
#     status: active           # active | offboarded
#
# For a key, replace its claims: [] with:
# claims:
#   - identity: alice@example.com
#     status: claimed_by_identity  # claimed_by_identity | possession_verified
#     source: manual
#
# possession_verified additionally requires verified_at in RFC3339 format.
# authorized_keys comments are hints only and never create ownership claims.

`

// IdentityMap is an explicit local ownership input. authorized_keys comments
// never populate Claims: they remain unverified hints in the scan evidence.
type IdentityMap struct {
	SchemaVersion string                 `yaml:"schema_version" json:"schema_version"`
	Identities    []Identity             `yaml:"identities" json:"identities"`
	Keys          []IdentityKeyOwnership `yaml:"keys" json:"keys"`
}

type Identity struct {
	ID          string `yaml:"id" json:"id"`
	DisplayName string `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Kind        string `yaml:"kind" json:"kind"`
	Status      string `yaml:"status" json:"status"`
}

type IdentityKeyOwnership struct {
	Fingerprint string           `yaml:"fingerprint" json:"fingerprint"`
	Claims      []OwnershipClaim `yaml:"claims" json:"claims"`
}

type OwnershipClaim struct {
	IdentityID string `yaml:"identity" json:"identity"`
	Status     string `yaml:"status" json:"status"`
	Source     string `yaml:"source" json:"source"`
	RecordedAt string `yaml:"recorded_at,omitempty" json:"recorded_at,omitempty"`
	VerifiedAt string `yaml:"verified_at,omitempty" json:"verified_at,omitempty"`
}

// BuildIdentityMapTemplate creates a safe, explicitly unassigned template for
// every key observed in a validated snapshot. Empty claims remain unknown.
func BuildIdentityMapTemplate(snapshot *Snapshot) (*IdentityMap, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	fingerprints := map[string]bool{}
	for _, host := range snapshot.Hosts {
		for _, account := range host.Accounts {
			for _, source := range account.Sources {
				for _, entry := range source.Entries {
					if entry.ParseError == "" && entry.Fingerprint != "" {
						fingerprints[entry.Fingerprint] = true
					}
				}
			}
		}
	}
	identityMap := &IdentityMap{SchemaVersion: IdentityMapSchemaVersion, Identities: []Identity{}}
	for _, fingerprint := range sortedSet(fingerprints) {
		identityMap.Keys = append(identityMap.Keys, IdentityKeyOwnership{Fingerprint: fingerprint, Claims: []OwnershipClaim{}})
	}
	return identityMap, nil
}

func ReadIdentityMap(path string) (*IdentityMap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity map %s: %w", path, err)
	}
	defer file.Close()
	if stat, statErr := file.Stat(); statErr == nil && stat.Size() > maxIdentityMapBytes {
		return nil, fmt.Errorf("identity map is %d bytes; limit is %d", stat.Size(), maxIdentityMapBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxIdentityMapBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read identity map: %w", err)
	}
	if len(data) > maxIdentityMapBytes {
		return nil, fmt.Errorf("identity map exceeds %d bytes", maxIdentityMapBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var identityMap IdentityMap
	if err := decoder.Decode(&identityMap); err != nil {
		var typeError *yaml.TypeError
		if errors.As(err, &typeError) && strings.Contains(err.Error(), "OwnershipClaim") {
			return nil, fmt.Errorf("parse identity map: %w; each claims item must be an object like {identity: alice@example.com, status: claimed_by_identity, source: manual}; declare that identity under identities first; valid claim statuses are %q and %q", err, ClaimStatusClaimed, ClaimStatusVerified)
		}
		return nil, fmt.Errorf("parse identity map: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("identity map contains more than one YAML document")
		}
		return nil, fmt.Errorf("parse trailing identity map data: %w", err)
	}
	normalizeIdentityMap(&identityMap)
	if err := ValidateIdentityMap(&identityMap); err != nil {
		return nil, err
	}
	return &identityMap, nil
}

func WriteIdentityMap(path string, identityMap *IdentityMap) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("identity map output path is empty")
	}
	if identityMap == nil {
		return errors.New("identity map is nil")
	}
	clone := *identityMap
	clone.Identities = append([]Identity(nil), identityMap.Identities...)
	clone.Keys = cloneIdentityKeys(identityMap.Keys)
	normalizeIdentityMap(&clone)
	if err := ValidateIdentityMap(&clone); err != nil {
		return err
	}
	encoded, err := yaml.Marshal(&clone)
	if err != nil {
		return fmt.Errorf("marshal identity map: %w", err)
	}
	data := append([]byte(identityMapEditingGuide), encoded...)
	if len(data) > maxIdentityMapBytes {
		return fmt.Errorf("identity map is %d bytes; limit is %d", len(data), maxIdentityMapBytes)
	}
	return writePrivateFile(path, data)
}

func ValidateIdentityMap(identityMap *IdentityMap) error {
	if identityMap == nil {
		return invalidIdentityMap("identity map is nil")
	}
	if identityMap.SchemaVersion != IdentityMapSchemaVersion {
		return invalidIdentityMap("unsupported schema_version %q (supported: %s)", identityMap.SchemaVersion, IdentityMapSchemaVersion)
	}
	identities := map[string]Identity{}
	for index, identity := range identityMap.Identities {
		if err := validIdentityText(identity.ID, false); err != nil {
			return invalidIdentityMap("identities[%d].id: %v", index, err)
		}
		if _, exists := identities[identity.ID]; exists {
			return invalidIdentityMap("duplicate identity id %q", identity.ID)
		}
		if err := validIdentityText(identity.DisplayName, true); err != nil {
			return invalidIdentityMap("identity %q display_name: %v", identity.ID, err)
		}
		if identity.Kind != IdentityKindHuman && identity.Kind != IdentityKindService {
			return invalidIdentityMap("identity %q has invalid kind %q", identity.ID, identity.Kind)
		}
		if identity.Status != IdentityStatusActive && identity.Status != IdentityStatusOffboarded {
			return invalidIdentityMap("identity %q has invalid status %q", identity.ID, identity.Status)
		}
		identities[identity.ID] = identity
	}
	keys := map[string]bool{}
	for keyIndex, key := range identityMap.Keys {
		if !validSHA256Fingerprint(key.Fingerprint) {
			return invalidIdentityMap("keys[%d] has invalid fingerprint %q", keyIndex, key.Fingerprint)
		}
		if keys[key.Fingerprint] {
			return invalidIdentityMap("duplicate fingerprint %q", key.Fingerprint)
		}
		keys[key.Fingerprint] = true
		claims := map[string]bool{}
		for claimIndex, claim := range key.Claims {
			if _, exists := identities[claim.IdentityID]; !exists {
				return invalidIdentityMap("key %q claims[%d] references unknown identity %q", key.Fingerprint, claimIndex, claim.IdentityID)
			}
			if claims[claim.IdentityID] {
				return invalidIdentityMap("key %q repeats claim for identity %q", key.Fingerprint, claim.IdentityID)
			}
			claims[claim.IdentityID] = true
			if claim.Status != ClaimStatusClaimed && claim.Status != ClaimStatusVerified {
				return invalidIdentityMap("key %q claim for %q has invalid status %q", key.Fingerprint, claim.IdentityID, claim.Status)
			}
			if err := validIdentityText(claim.Source, false); err != nil {
				return invalidIdentityMap("key %q claim for %q source: %v", key.Fingerprint, claim.IdentityID, err)
			}
			if err := validOptionalRFC3339(claim.RecordedAt); err != nil {
				return invalidIdentityMap("key %q claim for %q recorded_at: %v", key.Fingerprint, claim.IdentityID, err)
			}
			if err := validOptionalRFC3339(claim.VerifiedAt); err != nil {
				return invalidIdentityMap("key %q claim for %q verified_at: %v", key.Fingerprint, claim.IdentityID, err)
			}
			if claim.Status == ClaimStatusVerified && claim.VerifiedAt == "" {
				return invalidIdentityMap("key %q possession_verified claim for %q requires verified_at", key.Fingerprint, claim.IdentityID)
			}
			if claim.Status == ClaimStatusClaimed && claim.VerifiedAt != "" {
				return invalidIdentityMap("key %q unverified claim for %q must not set verified_at", key.Fingerprint, claim.IdentityID)
			}
		}
	}
	return nil
}

func IdentityMapDigest(identityMap *IdentityMap) (string, error) {
	if err := ValidateIdentityMap(identityMap); err != nil {
		return "", err
	}
	clone := *identityMap
	clone.Identities = append([]Identity(nil), identityMap.Identities...)
	clone.Keys = cloneIdentityKeys(identityMap.Keys)
	normalizeIdentityMap(&clone)
	data, err := yaml.Marshal(&clone)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "SHA256:" + hex.EncodeToString(digest[:]), nil
}

func normalizeIdentityMap(identityMap *IdentityMap) {
	for index := range identityMap.Identities {
		identityMap.Identities[index].ID = strings.TrimSpace(identityMap.Identities[index].ID)
		identityMap.Identities[index].DisplayName = strings.TrimSpace(identityMap.Identities[index].DisplayName)
		identityMap.Identities[index].Kind = strings.TrimSpace(identityMap.Identities[index].Kind)
		identityMap.Identities[index].Status = strings.TrimSpace(identityMap.Identities[index].Status)
	}
	for keyIndex := range identityMap.Keys {
		identityMap.Keys[keyIndex].Fingerprint = strings.TrimSpace(identityMap.Keys[keyIndex].Fingerprint)
		for claimIndex := range identityMap.Keys[keyIndex].Claims {
			claim := &identityMap.Keys[keyIndex].Claims[claimIndex]
			claim.IdentityID = strings.TrimSpace(claim.IdentityID)
			claim.Status = strings.TrimSpace(claim.Status)
			claim.Source = strings.TrimSpace(claim.Source)
			claim.RecordedAt = strings.TrimSpace(claim.RecordedAt)
			claim.VerifiedAt = strings.TrimSpace(claim.VerifiedAt)
		}
		sort.Slice(identityMap.Keys[keyIndex].Claims, func(i, j int) bool {
			return identityMap.Keys[keyIndex].Claims[i].IdentityID < identityMap.Keys[keyIndex].Claims[j].IdentityID
		})
	}
	sort.Slice(identityMap.Identities, func(i, j int) bool { return identityMap.Identities[i].ID < identityMap.Identities[j].ID })
	sort.Slice(identityMap.Keys, func(i, j int) bool { return identityMap.Keys[i].Fingerprint < identityMap.Keys[j].Fingerprint })
}

func cloneIdentityKeys(keys []IdentityKeyOwnership) []IdentityKeyOwnership {
	cloned := append([]IdentityKeyOwnership(nil), keys...)
	for index := range cloned {
		cloned[index].Claims = append([]OwnershipClaim(nil), keys[index].Claims...)
	}
	return cloned
}

func validIdentityText(value string, allowEmpty bool) error {
	if value == "" && allowEmpty {
		return nil
	}
	if value == "" {
		return errors.New("value is required")
	}
	if len(value) > maxIdentityTextBytes {
		return fmt.Errorf("value exceeds %d bytes", maxIdentityTextBytes)
	}
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("value contains invalid or multiline text")
	}
	return nil
}

func validOptionalRFC3339(value string) error {
	if value == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return fmt.Errorf("must be RFC3339: %w", err)
	}
	return nil
}

func validSHA256Fingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(decoded) == sha256.Size
}

func invalidIdentityMap(format string, args ...any) error {
	return fmt.Errorf("invalid identity map v%s: %s", IdentityMapSchemaVersion, fmt.Sprintf(format, args...))
}
