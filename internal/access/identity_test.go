package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testFingerprintA = "SHA256:4wyvq4+C9zfYxQLEtmV/iKvlJKIp7+g6ICK+2Qo2OzE"
	testFingerprintB = "SHA256:MRXjQ5h8KMsgJUqUmf/pzW4oLzOSMIMzWU2GfvogPH0"
	testFingerprintC = "SHA256:KHUW/L6W704MO7rdvH0j251Nk95rMMTYRJfwYqGZ7TM"
)

func validIdentityFixture() *IdentityMap {
	return &IdentityMap{
		SchemaVersion: IdentityMapSchemaVersion,
		Identities: []Identity{
			{ID: "alice@example.com", DisplayName: "Alice", Kind: IdentityKindHuman, Status: IdentityStatusActive},
			{ID: "deploy-service", Kind: IdentityKindService, Status: IdentityStatusActive},
		},
		Keys: []IdentityKeyOwnership{{
			Fingerprint: testFingerprintA,
			Claims: []OwnershipClaim{{
				IdentityID: "alice@example.com", Status: ClaimStatusVerified, Source: "manual",
				VerifiedAt: "2026-08-12T00:00:00Z",
			}},
		}},
	}
}

func TestIdentityMapTemplateIsExplicitlyUnassignedAndPrivate(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Hosts[0].Accounts[0].Sources[0].Entries[0].Fingerprint = testFingerprintA
	snapshot.Finalize(testTime.Add(2))
	identityMap, err := BuildIdentityMapTemplate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(identityMap.Identities) != 0 || len(identityMap.Keys) != 1 || len(identityMap.Keys[0].Claims) != 0 {
		t.Fatalf("unsafe identity template: %+v", identityMap)
	}
	path := filepath.Join(t.TempDir(), "identity-map.yaml")
	if err := WriteIdentityMap(path, identityMap); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity map mode = %04o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"replace its claims: []",
		"identity: alice@example.com",
		"claimed_by_identity | possession_verified",
		"authorized_keys comments are hints only",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("identity map editing guide is missing %q:\n%s", want, data)
		}
	}
	readBack, err := ReadIdentityMap(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(readBack.Keys) != 1 || readBack.Keys[0].Fingerprint != testFingerprintA {
		t.Fatalf("identity map round trip = %+v", readBack)
	}
}

func TestReadIdentityMapExplainsClaimObjectShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-map.yaml")
	data := `schema_version: "1"
identities:
  - id: alice@example.com
    kind: human
    status: active
keys:
  - fingerprint: "` + testFingerprintA + `"
    claims: ["alice@example.com"]
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadIdentityMap(path)
	if err == nil {
		t.Fatal("string ownership claim accepted")
	}
	for _, want := range []string{"each claims item must be an object", "identity: alice@example.com", ClaimStatusClaimed, ClaimStatusVerified, "declare that identity under identities first"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("claim parse error is missing %q: %v", want, err)
		}
	}
}

func TestIdentityMapDigestIgnoresInputOrdering(t *testing.T) {
	left := validIdentityFixture()
	left.Keys = append(left.Keys, IdentityKeyOwnership{Fingerprint: testFingerprintB, Claims: []OwnershipClaim{{
		IdentityID: "deploy-service", Status: ClaimStatusClaimed, Source: "manual",
	}}})
	right := *left
	right.Identities = []Identity{left.Identities[1], left.Identities[0]}
	right.Keys = []IdentityKeyOwnership{left.Keys[1], left.Keys[0]}
	leftDigest, err := IdentityMapDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := IdentityMapDigest(&right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("semantic identity map digest depends on ordering: %s != %s", leftDigest, rightDigest)
	}
}

func TestValidateIdentityMapRejectsInvalidClaims(t *testing.T) {
	tests := map[string]func(*IdentityMap){
		"unknown identity": func(identityMap *IdentityMap) { identityMap.Keys[0].Claims[0].IdentityID = "missing" },
		"bad fingerprint":  func(identityMap *IdentityMap) { identityMap.Keys[0].Fingerprint = "SHA256:not-a-digest" },
		"unverified timestamp": func(identityMap *IdentityMap) {
			identityMap.Keys[0].Claims[0].Status = ClaimStatusClaimed
		},
		"verified without timestamp": func(identityMap *IdentityMap) { identityMap.Keys[0].Claims[0].VerifiedAt = "" },
		"duplicate identity": func(identityMap *IdentityMap) {
			identityMap.Identities = append(identityMap.Identities, identityMap.Identities[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			identityMap := validIdentityFixture()
			mutate(identityMap)
			if err := ValidateIdentityMap(identityMap); err == nil {
				t.Fatal("invalid identity map accepted")
			}
		})
	}
}

func TestReadIdentityMapRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	for name, data := range map[string]string{
		"unknown field":      `schema_version: "1"\nidentities: []\nkeys: []\ntypo: true\n`,
		"multiple documents": `schema_version: "1"\nidentities: []\nkeys: []\n---\n{}\n`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity-map.yaml")
			data = strings.ReplaceAll(data, `\n`, "\n")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadIdentityMap(path); err == nil {
				t.Fatal("invalid identity map accepted")
			}
		})
	}
}
