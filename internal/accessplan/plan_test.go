package accessplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/config"
	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) (string, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), ssh.FingerprintSHA256(key)
}

func testPlanSnapshot(t *testing.T, content []byte) *access.Snapshot {
	t.Helper()
	entries, err := access.ParseAuthorizedKeys(content, false)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint64(1000), uint64(1000)
	snapshot := access.NewSnapshot("test", access.Scope{Mode: "system", Selector: "group:prod", AccountMode: access.AccountModeLocal, IncludePublicKeys: false}, time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC))
	snapshot.Hosts = []access.HostSnapshot{{Alias: "web", Groups: []string{"prod"}, Coverage: access.CoverageFull,
		Accounts: []access.AccountSnapshot{{Username: "deploy", UID: &uid, GID: &gid, Auth: &access.AccountAuthSnapshot{}, Sources: []access.KeySource{{
			Type: "authorized_keys_file", Path: "/home/deploy/.ssh/authorized_keys", Exists: true,
			ContentInspected: true, ContentSHA256: access.ContentDigest(content), Mode: "0600", OwnerUID: &uid, OwnerGID: &gid,
			Size: int64(len(content)), Entries: entries,
		}}}}}}
	snapshot.Finalize(time.Date(2026, 8, 28, 10, 0, 1, 0, time.UTC))
	if err := access.ValidateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestBuildAndApplyContentPreserveUnmanagedBytes(t *testing.T) {
	unmanagedKey, _ := testPublicKey(t)
	managedKey, managedFingerprint := testPublicKey(t)
	before := []byte("# exact header\r\n" + unmanagedKey + " owner@example.com\r\nmalformed stays byte-for-byte\n")
	snapshot := testPlanSnapshot(t, before)
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"web": {Host: "127.0.0.1", Groups: []string{"prod"}}}}
	grant := cloudcontract.DesiredGrant{ID: "grant_0123456789abcdef", IdentityRef: "alice@example.com", Fingerprint: managedFingerprint,
		PublicKey: managedKey, Status: cloudcontract.GrantStatusActive, Target: cloudcontract.OnboardingTarget{Kind: "group", Selector: "prod", Account: "deploy"}}
	now := time.Now().UTC()
	plan, err := Build(snapshot, cfg, []cloudcontract.DesiredGrant{grant}, BuildOptions{Organization: "acme", Project: "prod", Selector: "group:prod", Aliases: []string{"web"}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || len(plan.Changes[0].Operations) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	after, err := ApplyContent(before, plan.Changes[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(after), string(before)) {
		t.Fatalf("unmanaged prefix changed:\n%q\nwant prefix:\n%q", after, before)
	}
	if !strings.Contains(string(after), managedKey+" sshmgr:grant="+grant.ID+"\n") {
		t.Fatalf("managed line missing: %s", after)
	}
	if _, err := ApplyContent(append(before, 'x'), plan.Changes[0]); err == nil {
		t.Fatal("stale content was accepted")
	}
}

func TestRevocationRemovesOnlyOwnedGrantLine(t *testing.T) {
	key, fingerprint := testPublicKey(t)
	marker := "sshmgr:grant=grant_deadbeef01234567"
	before := []byte(key + " unmanaged-owner\n" + key + " " + marker + "\n# tail\n")
	snapshot := testPlanSnapshot(t, before)
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"web": {Host: "127.0.0.1", Groups: []string{"prod"}}}}
	grant := cloudcontract.DesiredGrant{ID: "grant_deadbeef01234567", IdentityRef: "alice@example.com", Fingerprint: fingerprint,
		PublicKey: key, Status: cloudcontract.GrantStatusRevoked, Target: cloudcontract.OnboardingTarget{Kind: "group", Selector: "prod", Account: "deploy"}}
	plan, err := Build(snapshot, cfg, []cloudcontract.DesiredGrant{grant}, BuildOptions{Organization: "acme", Project: "prod", Selector: "group:prod", Aliases: []string{"web"}, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	after, err := ApplyContent(before, plan.Changes[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), marker) || !strings.Contains(string(after), "unmanaged-owner") || !strings.Contains(string(after), "# tail\n") {
		t.Fatalf("revocation touched the wrong line: %q", after)
	}
}

func TestPlanDigestExpiryAndCustomerSignature(t *testing.T) {
	key, fingerprint := testPublicKey(t)
	snapshot := testPlanSnapshot(t, nil)
	snapshot.Hosts[0].Accounts[0].Sources[0].Exists = false
	snapshot.Hosts[0].Accounts[0].Sources[0].ContentInspected = false
	snapshot.Hosts[0].Accounts[0].Sources[0].ContentSHA256 = ""
	snapshot.Hosts[0].Accounts[0].Sources[0].Mode = ""
	snapshot.Finalize(time.Date(2026, 8, 28, 10, 0, 1, 0, time.UTC))
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"web": {Host: "127.0.0.1", Groups: []string{"prod"}}}}
	grant := cloudcontract.DesiredGrant{ID: "grant_0123456789abcdef", IdentityRef: "alice@example.com", Fingerprint: fingerprint,
		PublicKey: key, Status: cloudcontract.GrantStatusActive, Target: cloudcontract.OnboardingTarget{Kind: "group", Selector: "prod", Account: "deploy"}}
	now := time.Now().UTC()
	plan, err := Build(snapshot, cfg, []cloudcontract.DesiredGrant{grant}, BuildOptions{Organization: "acme", Project: "prod", Selector: "group:prod", Aliases: []string{"web"}, Now: now, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(plan, private); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(plan, public); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySignature(plan, other); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	tampered := *plan
	tampered.Project = "other"
	if err := Validate(&tampered, time.Time{}); err == nil {
		t.Fatal("tampered immutable content accepted")
	}
	// The human confirmation is the content-derived plan ID. Recomputing the
	// unkeyed digest must not let altered content retain the confirmed ID.
	tampered.Digest, err = digestPlan(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(&tampered, time.Time{}); err == nil {
		t.Fatal("tampered content with a recomputed digest retained the original plan ID")
	}
	tampered = *plan
	tampered.Changes = append([]FileChange(nil), plan.Changes...)
	tampered.Changes[0].Host = "not-selected"
	tampered.PlanID, err = planID(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Digest, err = digestPlan(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(&tampered, time.Time{}); err == nil {
		t.Fatal("file change outside the selected host set was accepted")
	}
	if err := Validate(plan, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired plan accepted")
	}
}

func TestRenderAnsibleCarriesPreconditionAndManagedMarker(t *testing.T) {
	key, fingerprint := testPublicKey(t)
	snapshot := testPlanSnapshot(t, nil)
	snapshot.Hosts[0].Accounts[0].Sources[0].Exists = false
	snapshot.Hosts[0].Accounts[0].Sources[0].ContentInspected = false
	snapshot.Hosts[0].Accounts[0].Sources[0].ContentSHA256 = ""
	snapshot.Finalize(time.Now())
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"web": {Host: "127.0.0.1", Groups: []string{"prod"}}}}
	grant := cloudcontract.DesiredGrant{ID: "grant_0123456789abcdef", IdentityRef: "alice@example.com", Fingerprint: fingerprint, PublicKey: key,
		Status: cloudcontract.GrantStatusActive, Target: cloudcontract.OnboardingTarget{Kind: "group", Selector: "prod", Account: "deploy"}}
	plan, err := Build(snapshot, cfg, []cloudcontract.DesiredGrant{grant}, BuildOptions{Organization: "acme", Project: "prod", Selector: "group:prod", Aliases: []string{"web"}, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	output, err := RenderAnsible(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{plan.Digest, plan.Changes[0].PreconditionSHA256, "sshmgr:grant=" + grant.ID, "lineinfile", "become: true"} {
		if !strings.Contains(output, want) {
			t.Fatalf("Ansible export missing %q:\n%s", want, output)
		}
	}
}
