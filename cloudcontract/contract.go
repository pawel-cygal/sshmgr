// Package cloudcontract defines the public compatibility boundary between the
// open-source sshmgr client and a separately deployed sshmgr Cloud service.
//
// It contains transport models and validated evidence helpers only. It does
// not contain a server, browser UI, authentication store, database code, or
// deployment configuration.
package cloudcontract

import (
	"time"

	"github.com/systeampl/sshmgr/internal/access"
)

const (
	GrantStatusActive  = "active"
	GrantStatusRevoked = "revoked"

	OnboardingStatusInvited      = "invited"
	OnboardingStatusKeySubmitted = "key_submitted"
	OnboardingStatusApproved     = "approved"
	OnboardingStatusRejected     = "rejected"
	OnboardingStatusExpired      = "expired"

	VerificationNotSubmitted = "not_submitted"
	VerificationClaimed      = "claimed_by_identity"
	VerificationPossession   = "possession_verified"

	MaxWorkspaceBundleBytes = access.MaxWorkspaceBundleBytes
)

type OnboardingTarget struct {
	Kind     string `json:"kind"`
	Selector string `json:"selector"`
	Account  string `json:"account"`
}

type CreateOnboardingRequest struct {
	IdentityRef string             `json:"identity_ref"`
	DisplayName string             `json:"display_name,omitempty"`
	Kind        string             `json:"kind"`
	ExpiresIn   int                `json:"expires_in_hours"`
	Targets     []OnboardingTarget `json:"targets"`
}

type ReviewOnboardingRequest struct {
	Decision        string `json:"decision"`
	AllowUnverified bool   `json:"allow_unverified,omitempty"`
	OverrideReason  string `json:"override_reason,omitempty"`
}

type OnboardingInvitation struct {
	ID                 string             `json:"id"`
	Workspace          string             `json:"workspace"`
	IdentityRef        string             `json:"identity_ref"`
	DisplayName        string             `json:"display_name,omitempty"`
	Kind               string             `json:"kind"`
	Status             string             `json:"status"`
	Verification       string             `json:"verification"`
	Fingerprint        string             `json:"fingerprint,omitempty"`
	Algorithm          string             `json:"algorithm,omitempty"`
	Bits               int                `json:"bits,omitempty"`
	Comment            string             `json:"comment,omitempty"`
	PublicKey          string             `json:"public_key,omitempty"`
	Targets            []OnboardingTarget `json:"targets"`
	CreatedAt          string             `json:"created_at"`
	ExpiresAt          string             `json:"expires_at"`
	SubmittedAt        string             `json:"submitted_at,omitempty"`
	ReviewedAt         string             `json:"reviewed_at,omitempty"`
	ReviewedBy         string             `json:"reviewed_by,omitempty"`
	UnverifiedOverride bool               `json:"unverified_override,omitempty"`
}

type OnboardingCreateResult struct {
	SchemaVersion          string               `json:"schema_version"`
	Invitation             OnboardingInvitation `json:"invitation"`
	SubmissionToken        string               `json:"submission_token"`
	SubmissionPath         string               `json:"submission_path"`
	VerificationResultPath string               `json:"verification_result_path"`
}

type OnboardingList struct {
	SchemaVersion string                 `json:"schema_version"`
	Workspace     string                 `json:"workspace"`
	Invitations   []OnboardingInvitation `json:"invitations"`
}

type DesiredGrant struct {
	ID           string           `json:"id"`
	InvitationID string           `json:"invitation_id"`
	IdentityRef  string           `json:"identity_ref"`
	Fingerprint  string           `json:"fingerprint"`
	PublicKey    string           `json:"public_key"`
	Target       OnboardingTarget `json:"target"`
	Status       string           `json:"status"`
	ApprovedAt   string           `json:"approved_at"`
	ExpiresAt    string           `json:"expires_at"`
	RevokedAt    string           `json:"revoked_at,omitempty"`
	RevokedBy    string           `json:"revoked_by,omitempty"`
}

type DesiredGrantList struct {
	SchemaVersion string         `json:"schema_version"`
	Organization  string         `json:"organization"`
	Project       string         `json:"project"`
	Grants        []DesiredGrant `json:"grants"`
}

type RevokeDesiredGrantsRequest struct {
	IdentityRef string             `json:"identity_ref"`
	Targets     []OnboardingTarget `json:"targets"`
	Reason      string             `json:"reason"`
}

type RevokeDesiredGrantsResult struct {
	SchemaVersion string `json:"schema_version"`
	Revoked       int    `json:"revoked"`
}

type DeviceAuthorizationRequest struct {
	ClientName string `json:"client_name,omitempty"`
}

type DeviceAuthorization struct {
	SchemaVersion           string `json:"schema_version"`
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

type BrowserProject struct {
	ID           string   `json:"id"`
	Slug         string   `json:"slug"`
	Role         string   `json:"role"`
	Capabilities []string `json:"capabilities"`
}

type BrowserOrganization struct {
	ID           string           `json:"id"`
	Slug         string           `json:"slug"`
	Role         string           `json:"role"`
	Capabilities []string         `json:"capabilities"`
	Projects     []BrowserProject `json:"projects"`
}

type BrowserUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	EmailVerified bool   `json:"email_verified"`
}

type BrowserSession struct {
	SchemaVersion     string                `json:"schema_version"`
	SessionID         string                `json:"session_id"`
	User              BrowserUser           `json:"user"`
	Organizations     []BrowserOrganization `json:"organizations"`
	CreatedAt         time.Time             `json:"created_at"`
	LastSeenAt        time.Time             `json:"last_seen_at"`
	IdleExpiresAt     time.Time             `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time             `json:"absolute_expires_at"`
}

type CLISessionIssue struct {
	SchemaVersion string         `json:"schema_version"`
	AccessToken   string         `json:"access_token"`
	TokenType     string         `json:"token_type"`
	ExpiresIn     int            `json:"expires_in"`
	Session       BrowserSession `json:"session"`
}

// Evidence aliases and helpers keep the Cloud ingestion boundary identical to
// the artifacts produced by the CLI without exposing any SaaS implementation.
type WorkspaceBundle = access.WorkspaceBundle
type Snapshot = access.Snapshot
type UploadPlan = access.UploadPlan
type WorkspaceHistory = access.WorkspaceHistory
type OwnershipReview = access.OwnershipReview
type WorkspaceOwnershipHistory = access.WorkspaceOwnershipHistory
type WorkspaceOffboardingHistory = access.WorkspaceOffboardingHistory
type KeyObservation = access.KeyObservation

func ParseWorkspaceBundleJSON(data []byte) (*WorkspaceBundle, error) {
	return access.ParseWorkspaceBundleJSON(data)
}

func RenderWorkspaceBundleJSON(bundle *WorkspaceBundle) ([]byte, error) {
	return access.RenderWorkspaceBundleJSON(bundle)
}

func ValidateWorkspaceBundle(bundle *WorkspaceBundle) error {
	return access.ValidateWorkspaceBundle(bundle)
}

func ParseAuthorizedKeys(data []byte, includePublicKeys bool) ([]KeyObservation, error) {
	return access.ParseAuthorizedKeys(data, includePublicKeys)
}

func ReadSnapshot(path string) (*Snapshot, error) {
	return access.ReadSnapshot(path)
}

func ReadWorkspaceHistory(path string) (*WorkspaceHistory, error) {
	return access.ReadWorkspaceHistory(path)
}

func BuildUploadPlan(snapshot *Snapshot, workspace string, includeIdentityHints bool) (*UploadPlan, error) {
	return access.BuildUploadPlan(snapshot, workspace, includeIdentityHints)
}

func BuildWorkspaceHistory(plans ...*UploadPlan) (*WorkspaceHistory, error) {
	return access.BuildWorkspaceHistory(plans...)
}

func BuildWorkspaceBundle(history *WorkspaceHistory, ownership *OwnershipReview, ownershipHistory *WorkspaceOwnershipHistory, offboardingHistory *WorkspaceOffboardingHistory) (*WorkspaceBundle, error) {
	return access.BuildWorkspaceBundle(history, ownership, ownershipHistory, offboardingHistory)
}
