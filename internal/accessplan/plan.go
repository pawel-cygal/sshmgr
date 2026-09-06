// Package accessplan builds and validates immutable authorized_keys plans.
package accessplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/access"
	"github.com/systeampl/sshmgr/internal/config"
	"golang.org/x/crypto/ssh"
)

const SchemaVersion = "1"

type Plan struct {
	SchemaVersion      string       `json:"schema_version"`
	PlanID             string       `json:"plan_id"`
	Digest             string       `json:"digest"`
	Organization       string       `json:"organization"`
	Project            string       `json:"project"`
	CreatedAt          string       `json:"created_at"`
	ExpiresAt          string       `json:"expires_at"`
	BaselineScanID     string       `json:"baseline_scan_id"`
	BaselineSHA256     string       `json:"baseline_sha256"`
	DesiredStateSHA256 string       `json:"desired_state_sha256"`
	Selector           string       `json:"selector"`
	Hosts              []string     `json:"hosts"`
	Changes            []FileChange `json:"changes"`
	Signature          *Signature   `json:"signature,omitempty"`
}

type FileChange struct {
	Host               string      `json:"host"`
	Account            string      `json:"account"`
	Path               string      `json:"path"`
	PreconditionSHA256 string      `json:"precondition_sha256"`
	Exists             bool        `json:"exists"`
	Mode               string      `json:"mode,omitempty"`
	OwnerUID           *uint64     `json:"owner_uid,omitempty"`
	OwnerGID           *uint64     `json:"owner_gid,omitempty"`
	Operations         []Operation `json:"operations"`
}

type Operation struct {
	GrantID     string `json:"grant_id"`
	Action      string `json:"action"` // add | remove
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key,omitempty"`
	Marker      string `json:"marker"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

type BuildOptions struct {
	Organization string
	Project      string
	Selector     string
	Aliases      []string
	Now          time.Time
	TTL          time.Duration
}

func Build(snapshot *access.Snapshot, cfg *config.Config, grants []cloudcontract.DesiredGrant, options BuildOptions) (*Plan, error) {
	if err := access.ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("access plan config is nil")
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.TTL == 0 {
		options.TTL = 30 * time.Minute
	}
	if options.TTL < time.Minute || options.TTL > 24*time.Hour {
		return nil, errors.New("access plan TTL must be between one minute and 24 hours")
	}
	selected := make(map[string]bool, len(options.Aliases))
	for _, alias := range options.Aliases {
		selected[alias] = true
	}
	hosts := map[string]access.HostSnapshot{}
	for _, host := range snapshot.Hosts {
		hosts[host.Alias] = host
	}
	changes := map[string]*FileChange{}
	relevantGrants := []cloudcontract.DesiredGrant{}
	relevantSeen := map[string]bool{}
	for _, grant := range grants {
		if grant.Status != cloudcontract.GrantStatusActive && grant.Status != cloudcontract.GrantStatusRevoked {
			continue
		}
		for _, alias := range matchingAliases(cfg, grant.Target) {
			if !selected[alias] {
				continue
			}
			if !relevantSeen[grant.ID] {
				relevantGrants = append(relevantGrants, grant)
				relevantSeen[grant.ID] = true
			}
			host, ok := hosts[alias]
			if !ok {
				return nil, fmt.Errorf("baseline audit does not contain selected host %q", alias)
			}
			account, source, err := planSource(host, grant.Target.Account)
			if err != nil {
				return nil, fmt.Errorf("grant %s on %s: %w", grant.ID, alias, err)
			}
			marker := "sshmgr:grant=" + grant.ID
			action := "add"
			if grant.Status == cloudcontract.GrantStatusRevoked {
				action = "remove"
			}
			if !operationNeeded(source, grant, marker, action) {
				continue
			}
			key := alias + "\x00" + account.Username + "\x00" + source.Path
			change := changes[key]
			if change == nil {
				precondition := source.ContentSHA256
				if !source.Exists {
					precondition = access.ContentDigest(nil)
				}
				if precondition == "" {
					return nil, fmt.Errorf("host %s account %s source %s lacks a byte-exact baseline digest; run a fresh full audit", alias, account.Username, source.Path)
				}
				change = &FileChange{Host: alias, Account: account.Username, Path: source.Path,
					PreconditionSHA256: precondition, Exists: source.Exists, Mode: source.Mode,
					OwnerUID: source.OwnerUID, OwnerGID: source.OwnerGID, Operations: []Operation{}}
				if change.OwnerUID == nil {
					change.OwnerUID = account.UID
				}
				if change.OwnerGID == nil {
					change.OwnerGID = account.GID
				}
				changes[key] = change
			}
			change.Operations = append(change.Operations, Operation{GrantID: grant.ID, Action: action,
				Identity: grant.IdentityRef, Fingerprint: grant.Fingerprint, PublicKey: grant.PublicKey, Marker: marker})
		}
	}
	orderedChanges := make([]FileChange, 0, len(changes))
	sort.Slice(relevantGrants, func(i, j int) bool { return relevantGrants[i].ID < relevantGrants[j].ID })
	for _, change := range changes {
		sort.Slice(change.Operations, func(i, j int) bool {
			if change.Operations[i].Action != change.Operations[j].Action {
				return change.Operations[i].Action < change.Operations[j].Action
			}
			return change.Operations[i].GrantID < change.Operations[j].GrantID
		})
		orderedChanges = append(orderedChanges, *change)
	}
	sort.Slice(orderedChanges, func(i, j int) bool {
		if orderedChanges[i].Host != orderedChanges[j].Host {
			return orderedChanges[i].Host < orderedChanges[j].Host
		}
		if orderedChanges[i].Account != orderedChanges[j].Account {
			return orderedChanges[i].Account < orderedChanges[j].Account
		}
		return orderedChanges[i].Path < orderedChanges[j].Path
	})
	baselineDigest, err := canonicalDigest(snapshot)
	if err != nil {
		return nil, err
	}
	desiredDigest, err := canonicalDigest(relevantGrants)
	if err != nil {
		return nil, err
	}
	hostList := append([]string(nil), options.Aliases...)
	sort.Strings(hostList)
	plan := &Plan{SchemaVersion: SchemaVersion, Organization: options.Organization, Project: options.Project,
		CreatedAt: options.Now.UTC().Format(time.RFC3339Nano), ExpiresAt: options.Now.Add(options.TTL).UTC().Format(time.RFC3339Nano),
		BaselineScanID: snapshot.ScanID, BaselineSHA256: baselineDigest, DesiredStateSHA256: desiredDigest,
		Selector: options.Selector, Hosts: hostList, Changes: orderedChanges}
	plan.PlanID, err = planID(plan)
	if err != nil {
		return nil, err
	}
	plan.Digest, err = digestPlan(plan)
	if err != nil {
		return nil, err
	}
	if err := Validate(plan, options.Now); err != nil {
		return nil, err
	}
	return plan, nil
}

func planSource(host access.HostSnapshot, username string) (access.AccountSnapshot, access.KeySource, error) {
	if host.Coverage != access.CoverageFull {
		return access.AccountSnapshot{}, access.KeySource{}, fmt.Errorf("coverage is %s; planning requires full coverage", host.Coverage)
	}
	for _, account := range host.Accounts {
		if account.Username != username {
			continue
		}
		if account.Auth != nil && account.Auth.AuthorizedKeysCommand != "" && account.Auth.AuthorizedKeysCommand != "none" {
			return account, access.KeySource{}, errors.New("dynamic AuthorizedKeysCommand is not safely provisionable")
		}
		var missing *access.KeySource
		for index := range account.Sources {
			source := &account.Sources[index]
			if source.Type != "authorized_keys_file" || source.Symlink || source.AncestorSymlink || source.Error != "" {
				continue
			}
			if source.Exists && source.ContentInspected {
				return account, *source, nil
			}
			if !source.Exists && missing == nil {
				copy := *source
				missing = &copy
			}
		}
		if missing != nil {
			return account, *missing, nil
		}
		return account, access.KeySource{}, errors.New("no safe static authorized_keys source is available")
	}
	return access.AccountSnapshot{}, access.KeySource{}, fmt.Errorf("account %q was not observed", username)
}

func matchingAliases(cfg *config.Config, target cloudcontract.OnboardingTarget) []string {
	result := []string{}
	for alias := range cfg.Hosts {
		host, ok := cfg.ResolveHost(alias)
		if !ok {
			continue
		}
		matched := target.Kind == "host" && alias == target.Selector
		for _, value := range host.Groups {
			matched = matched || target.Kind == "group" && value == target.Selector
		}
		for _, value := range host.Tags {
			matched = matched || target.Kind == "tag" && value == target.Selector
		}
		if matched {
			result = append(result, alias)
		}
	}
	sort.Strings(result)
	return result
}

func DesiredStateDigest(cfg *config.Config, grants []cloudcontract.DesiredGrant, aliases []string) (string, error) {
	selected := map[string]bool{}
	for _, alias := range aliases {
		selected[alias] = true
	}
	relevant := []cloudcontract.DesiredGrant{}
	seen := map[string]bool{}
	for _, grant := range grants {
		if grant.Status != cloudcontract.GrantStatusActive && grant.Status != cloudcontract.GrantStatusRevoked {
			continue
		}
		for _, alias := range matchingAliases(cfg, grant.Target) {
			if selected[alias] && !seen[grant.ID] {
				relevant = append(relevant, grant)
				seen[grant.ID] = true
			}
		}
	}
	sort.Slice(relevant, func(i, j int) bool { return relevant[i].ID < relevant[j].ID })
	return canonicalDigest(relevant)
}

func operationNeeded(source access.KeySource, grant cloudcontract.DesiredGrant, marker, action string) bool {
	for _, entry := range source.Entries {
		if entry.ParseError != "" {
			continue
		}
		marked := hasMarker(entry.Comment, marker)
		if action == "add" && entry.Fingerprint == grant.Fingerprint {
			return false
		}
		if action == "remove" && entry.Fingerprint == grant.Fingerprint && marked {
			return true
		}
	}
	return action == "add"
}

func hasMarker(comment, marker string) bool {
	for _, field := range strings.Fields(comment) {
		if field == marker {
			return true
		}
	}
	return false
}

func Validate(plan *Plan, now time.Time) error {
	if plan == nil || plan.SchemaVersion != SchemaVersion || !strings.HasPrefix(plan.PlanID, "accessplan_") {
		return errors.New("invalid access plan envelope")
	}
	expectedID, err := planID(plan)
	if err != nil || expectedID != plan.PlanID {
		return errors.New("access plan ID does not match its immutable content")
	}
	created, err := time.Parse(time.RFC3339Nano, plan.CreatedAt)
	if err != nil {
		return errors.New("access plan created_at is invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if err != nil || !expires.After(created) {
		return errors.New("access plan expires_at is invalid")
	}
	if !now.IsZero() && now.After(expires) {
		return errors.New("access plan has expired")
	}
	want, err := digestPlan(plan)
	if err != nil || want != plan.Digest {
		return errors.New("access plan digest does not match its immutable content")
	}
	seen := map[string]bool{}
	if len(plan.Hosts) == 0 {
		return errors.New("access plan has no selected hosts")
	}
	hosts := make(map[string]bool, len(plan.Hosts))
	for index, host := range plan.Hosts {
		if host == "" || index > 0 && plan.Hosts[index-1] >= host {
			return errors.New("access plan hosts must be unique and sorted")
		}
		hosts[host] = true
	}
	for _, change := range plan.Changes {
		key := change.Host + "\x00" + change.Account + "\x00" + change.Path
		if seen[key] || !hosts[change.Host] || change.Account == "" || !filepath.IsAbs(change.Path) || !validDigest(change.PreconditionSHA256) {
			return errors.New("access plan contains an invalid or duplicate file change")
		}
		seen[key] = true
		if len(change.Operations) == 0 {
			return errors.New("access plan file change has no operations")
		}
		for _, operation := range change.Operations {
			if operation.Action != "add" && operation.Action != "remove" || operation.Marker != "sshmgr:grant="+operation.GrantID || operation.Fingerprint == "" {
				return errors.New("access plan contains an invalid managed operation")
			}
			if operation.Action == "add" {
				key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(operation.PublicKey))
				if err != nil || ssh.FingerprintSHA256(key) != operation.Fingerprint {
					return errors.New("access plan addition public key does not match its fingerprint")
				}
			}
		}
	}
	return nil
}

func Sign(plan *Plan, privateKey ed25519.PrivateKey) error {
	if err := Validate(plan, time.Time{}); err != nil {
		return err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("plan signer must be an Ed25519 private key")
	}
	signature := ed25519.Sign(privateKey, []byte(plan.Digest))
	plan.Signature = &Signature{Algorithm: "ed25519", PublicKey: base64.RawStdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Value: base64.RawStdEncoding.EncodeToString(signature)}
	return nil
}

func VerifySignature(plan *Plan, trusted ed25519.PublicKey) error {
	if err := Validate(plan, time.Now()); err != nil {
		return err
	}
	if plan.Signature == nil || plan.Signature.Algorithm != "ed25519" || len(trusted) != ed25519.PublicKeySize {
		return errors.New("access plan does not have a trusted Ed25519 signature")
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(plan.Signature.PublicKey)
	if err != nil || !bytes.Equal(publicKey, trusted) {
		return errors.New("access plan signer is not the configured customer key")
	}
	value, err := base64.RawStdEncoding.DecodeString(plan.Signature.Value)
	if err != nil || !ed25519.Verify(trusted, []byte(plan.Digest), value) {
		return errors.New("access plan signature is invalid")
	}
	return nil
}

func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func Write(path string, plan *Plan) error {
	if err := Validate(plan, time.Time{}); err != nil {
		return err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, ".sshmgr-access-plan-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

func Read(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, errors.New("access plan exceeds 16 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return nil, err
	}
	if err := Validate(&plan, time.Now()); err != nil {
		return nil, err
	}
	return &plan, nil
}

func Render(plan *Plan) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Access plan %s\n  digest: %s\n  baseline: %s\n  expires: %s\n", plan.PlanID, plan.Digest, plan.BaselineScanID, plan.ExpiresAt)
	adds, removes := 0, 0
	for _, change := range plan.Changes {
		fmt.Fprintf(&out, "\n%s · %s · %s\n  precondition %s\n", change.Host, change.Account, change.Path, change.PreconditionSHA256)
		for _, operation := range change.Operations {
			prefix := "+"
			if operation.Action == "remove" {
				prefix = "-"
				removes++
			} else {
				adds++
			}
			fmt.Fprintf(&out, "  %s %s  %s  %s\n", prefix, operation.Fingerprint, operation.Identity, operation.Marker)
		}
	}
	fmt.Fprintf(&out, "\nSummary: %d file(s), %d addition(s), %d managed removal(s)\n", len(plan.Changes), adds, removes)
	return out.String()
}

func digestPlan(plan *Plan) (string, error) {
	copy := *plan
	copy.Digest = ""
	copy.Signature = nil
	return canonicalDigest(copy)
}

func planID(plan *Plan) (string, error) {
	seed := *plan
	seed.PlanID = ""
	seed.Digest = ""
	seed.Signature = nil
	digest, err := canonicalDigest(seed)
	if err != nil {
		return "", err
	}
	return "accessplan_" + strings.TrimPrefix(digest, "SHA256:")[:24], nil
}

func canonicalDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "SHA256:" + hex.EncodeToString(digest[:]), nil
}

func validDigest(value string) bool {
	if len(value) != len("SHA256:")+64 || !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil
}
