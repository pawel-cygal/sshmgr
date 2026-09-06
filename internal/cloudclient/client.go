package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/systeampl/sshmgr/internal/access"
)

const maxResponseBytes = 1 << 20

var workspacePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type Options struct {
	Endpoint              string
	Token                 string
	AllowInsecureLoopback bool
	Timeout               time.Duration
	UserAgent             string
	HTTPClient            *http.Client
}

type Client struct {
	base      *url.URL
	token     string
	userAgent string
	http      *http.Client
}

type BundleMetadata struct {
	Workspace     string `json:"workspace"`
	BundleID      string `json:"bundle_id"`
	HistoryID     string `json:"history_id"`
	LatestScanID  string `json:"latest_scan_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadBytes  int    `json:"payload_bytes"`
	ReceivedAt    string `json:"received_at"`
	PrincipalID   string `json:"principal_id"`
	RetainedUntil string `json:"retained_until,omitempty"`
}

type WorkspacePolicy struct {
	Organization      string `json:"organization"`
	Role              string `json:"role"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	MaxBundleBytes    int64  `json:"max_bundle_bytes"`
	MaxStorageBytes   int64  `json:"max_storage_bytes"`
	StorageBytes      int64  `json:"storage_bytes"`
	BundleCount       int64  `json:"bundle_count"`
	RetentionDays     int    `json:"retention_days"`
}

type UploadResult struct {
	SchemaVersion string         `json:"schema_version"`
	Status        string         `json:"status"`
	Bundle        BundleMetadata `json:"bundle"`
}

type ServiceStatus struct {
	SchemaVersion string           `json:"schema_version"`
	Service       string           `json:"service"`
	Status        string           `json:"status"`
	APIVersion    string           `json:"api_version"`
	Storage       string           `json:"storage"`
	Workspace     string           `json:"workspace"`
	Organization  string           `json:"organization,omitempty"`
	Project       string           `json:"project,omitempty"`
	PrincipalID   string           `json:"principal_id"`
	Version       string           `json:"version"`
	Commit        string           `json:"commit"`
	BuildDate     string           `json:"build_date"`
	ServerTime    string           `json:"server_time"`
	Capabilities  []string         `json:"capabilities"`
	Policy        *WorkspacePolicy `json:"policy,omitempty"`
}

type apiErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func New(options Options) (*Client, error) {
	base, err := parseEndpoint(options.Endpoint, options.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	if len(options.Token) < 32 || len(options.Token) > 512 || strings.TrimSpace(options.Token) != options.Token ||
		strings.IndexFunc(options.Token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, errors.New("Cloud bearer token must be 32-512 bytes without whitespace or control characters")
	}
	if options.Timeout <= 0 || options.Timeout > 10*time.Minute {
		return nil, errors.New("Cloud request timeout must be greater than zero and at most 10 minutes")
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		httpClient = &http.Client{Transport: transport}
	}
	clone := *httpClient
	clone.Timeout = options.Timeout
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("Cloud API redirects are disabled to protect the bearer token")
	}
	return &Client{base: base, token: options.Token, userAgent: strings.TrimSpace(options.UserAgent), http: &clone}, nil
}

// NormalizeEndpoint validates an API origin and returns its canonical form.
// HTTPS is mandatory except for an explicitly enabled literal loopback IP.
func NormalizeEndpoint(value string, allowInsecureLoopback bool) (string, error) {
	parsed, err := parseEndpoint(value, allowInsecureLoopback)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func (c *Client) UploadBundle(ctx context.Context, bundle *access.WorkspaceBundle) (*UploadResult, error) {
	if err := access.ValidateWorkspaceBundle(bundle); err != nil {
		return nil, err
	}
	body, err := access.RenderWorkspaceBundleJSON(bundle)
	if err != nil {
		return nil, err
	}
	target := *c.base
	target.Path = path.Join(target.Path, "v1", "workspaces", bundle.Workspace, "bundles")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build Cloud upload request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", bundle.IdempotencyKey)
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("upload Cloud bundle: %w", err)
	}
	defer response.Body.Close()
	data, err := readBoundedResponse(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, decodeAPIError(response.StatusCode, data)
	}
	var result UploadResult
	if err := decodeStrictJSON(data, &result); err != nil {
		return nil, fmt.Errorf("parse Cloud upload response: %w", err)
	}
	if result.SchemaVersion != "1" || result.Status != "created" && result.Status != "already_exists" ||
		result.Bundle.Workspace != bundle.Workspace || result.Bundle.BundleID != bundle.BundleID ||
		result.Bundle.HistoryID != bundle.Payload.WorkspaceHistory.HistoryID ||
		result.Bundle.LatestScanID != bundle.Payload.WorkspaceHistory.LatestScanID ||
		result.Bundle.PayloadSHA256 != bundle.PayloadSHA256 || result.Bundle.PayloadBytes != bundle.PayloadBytes ||
		result.Bundle.ReceivedAt == "" || result.Bundle.PrincipalID == "" {
		return nil, errors.New("Cloud upload response does not reconcile with the sent bundle")
	}
	if _, err := time.Parse(time.RFC3339Nano, result.Bundle.ReceivedAt); err != nil {
		return nil, errors.New("Cloud upload response has invalid received_at")
	}
	return &result, nil
}

func (c *Client) Status(ctx context.Context, workspace string) (*ServiceStatus, error) {
	if !workspacePattern.MatchString(workspace) {
		return nil, errors.New("Cloud workspace is invalid")
	}
	target := *c.base
	target.Path = path.Join(target.Path, "v1", "workspaces", workspace, "status")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Cloud status request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query Cloud status: %w", err)
	}
	defer response.Body.Close()
	data, err := readBoundedResponse(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, decodeAPIError(response.StatusCode, data)
	}
	var result ServiceStatus
	if err := decodeStrictJSON(data, &result); err != nil {
		return nil, fmt.Errorf("parse Cloud status response: %w", err)
	}
	if result.SchemaVersion != "1" || result.Service != "sshmgr-cloud-api" || result.Status != "ready" ||
		result.APIVersion != "v1" || result.Storage == "" || result.Workspace != workspace ||
		result.PrincipalID == "" || result.Version == "" || result.Commit == "" || result.BuildDate == "" ||
		len(result.Capabilities) == 0 {
		return nil, errors.New("Cloud status response does not reconcile with the selected workspace")
	}
	if !containsCapability(result.Capabilities, "workspace_status") || !containsCapability(result.Capabilities, "bundle_ingest") {
		return nil, errors.New("Cloud status response lacks required capabilities")
	}
	if result.Policy != nil && (result.Policy.Organization == "" || result.Policy.Role == "" ||
		result.Policy.RequestsPerMinute < 1 || result.Policy.MaxBundleBytes < 1 ||
		result.Policy.MaxStorageBytes < result.Policy.MaxBundleBytes || result.Policy.StorageBytes < 0 ||
		result.Policy.BundleCount < 0 || result.Policy.RetentionDays < 1) {
		return nil, errors.New("Cloud status response contains an invalid workspace policy")
	}
	if result.Policy != nil && !containsCapability(result.Capabilities, "tenant_limits") {
		return nil, errors.New("Cloud status response exposes a policy without the tenant_limits capability")
	}
	if _, err := time.Parse(time.RFC3339Nano, result.ServerTime); err != nil {
		return nil, errors.New("Cloud status response has invalid server_time")
	}
	return &result, nil
}

// ProjectStatus queries the v2 runner-plane status for one explicit
// organization/project context and requires the response to echo it exactly.
func (c *Client) ProjectStatus(ctx context.Context, organization, project string) (*ServiceStatus, error) {
	if !workspacePattern.MatchString(organization) {
		return nil, errors.New("Cloud organization is invalid")
	}
	if !workspacePattern.MatchString(project) {
		return nil, errors.New("Cloud project is invalid")
	}
	target := *c.base
	target.Path = path.Join(target.Path, "v2", "organizations", organization, "projects", project, "status")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Cloud project status request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query Cloud project status: %w", err)
	}
	defer response.Body.Close()
	data, err := readBoundedResponse(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, decodeAPIError(response.StatusCode, data)
	}
	var result ServiceStatus
	if err := decodeStrictJSON(data, &result); err != nil {
		return nil, fmt.Errorf("parse Cloud project status response: %w", err)
	}
	if result.SchemaVersion != "1" || result.Service != "sshmgr-cloud-api" || result.Status != "ready" ||
		result.APIVersion != "v2" || result.Storage == "" || result.Organization != organization ||
		result.Project != project || result.Workspace != project ||
		result.PrincipalID == "" || result.Version == "" || result.Commit == "" || result.BuildDate == "" ||
		len(result.Capabilities) == 0 {
		return nil, errors.New("Cloud project status response does not reconcile with the selected organization/project")
	}
	if !containsCapability(result.Capabilities, "workspace_status") || !containsCapability(result.Capabilities, "bundle_ingest") ||
		!containsCapability(result.Capabilities, "project_api") {
		return nil, errors.New("Cloud project status response lacks required capabilities")
	}
	if result.Policy != nil && (result.Policy.Organization == "" || result.Policy.Role == "" ||
		result.Policy.RequestsPerMinute < 1 || result.Policy.MaxBundleBytes < 1 ||
		result.Policy.MaxStorageBytes < result.Policy.MaxBundleBytes || result.Policy.StorageBytes < 0 ||
		result.Policy.BundleCount < 0 || result.Policy.RetentionDays < 1) {
		return nil, errors.New("Cloud project status response contains an invalid project policy")
	}
	if result.Policy != nil && !containsCapability(result.Capabilities, "tenant_limits") {
		return nil, errors.New("Cloud project status response exposes a policy without the tenant_limits capability")
	}
	if _, err := time.Parse(time.RFC3339Nano, result.ServerTime); err != nil {
		return nil, errors.New("Cloud project status response has invalid server_time")
	}
	return &result, nil
}

// UploadProjectBundle uploads one validated bundle through the v2
// organization/project route; the bundle's frozen workspace slug must equal
// the selected project.
func (c *Client) UploadProjectBundle(ctx context.Context, organization, project string, bundle *access.WorkspaceBundle) (*UploadResult, error) {
	if !workspacePattern.MatchString(organization) {
		return nil, errors.New("Cloud organization is invalid")
	}
	if !workspacePattern.MatchString(project) {
		return nil, errors.New("Cloud project is invalid")
	}
	if err := access.ValidateWorkspaceBundle(bundle); err != nil {
		return nil, err
	}
	if bundle.Workspace != project {
		return nil, fmt.Errorf("bundle workspace %q does not match Cloud project %q", bundle.Workspace, project)
	}
	body, err := access.RenderWorkspaceBundleJSON(bundle)
	if err != nil {
		return nil, err
	}
	target := *c.base
	target.Path = path.Join(target.Path, "v2", "organizations", organization, "projects", project, "bundles")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build Cloud project upload request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", bundle.IdempotencyKey)
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("upload Cloud project bundle: %w", err)
	}
	defer response.Body.Close()
	data, err := readBoundedResponse(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, decodeAPIError(response.StatusCode, data)
	}
	var result UploadResult
	if err := decodeStrictJSON(data, &result); err != nil {
		return nil, fmt.Errorf("parse Cloud project upload response: %w", err)
	}
	if result.SchemaVersion != "1" || result.Status != "created" && result.Status != "already_exists" ||
		result.Bundle.Workspace != bundle.Workspace || result.Bundle.BundleID != bundle.BundleID ||
		result.Bundle.HistoryID != bundle.Payload.WorkspaceHistory.HistoryID ||
		result.Bundle.LatestScanID != bundle.Payload.WorkspaceHistory.LatestScanID ||
		result.Bundle.PayloadSHA256 != bundle.PayloadSHA256 || result.Bundle.PayloadBytes != bundle.PayloadBytes ||
		result.Bundle.ReceivedAt == "" || result.Bundle.PrincipalID == "" {
		return nil, errors.New("Cloud project upload response does not reconcile with the sent bundle")
	}
	if _, err := time.Parse(time.RFC3339Nano, result.Bundle.ReceivedAt); err != nil {
		return nil, errors.New("Cloud project upload response has invalid received_at")
	}
	return &result, nil
}

func containsCapability(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func parseEndpoint(value string, allowInsecureLoopback bool) (*url.URL, error) {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse Cloud endpoint: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("Cloud endpoint must be an origin URL without credentials, path, query, or fragment")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	switch parsed.Scheme {
	case "https":
	case "http":
		if !allowInsecureLoopback || !isLoopbackHost(parsed.Hostname()) {
			return nil, errors.New("Cloud endpoint requires HTTPS; HTTP is allowed only for an explicitly enabled literal loopback address")
		}
	default:
		return nil, errors.New("Cloud endpoint scheme must be https")
	}
	return parsed, nil
}

func readBoundedResponse(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Cloud response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("Cloud response exceeds %d bytes", maxResponseBytes)
	}
	return data, nil
}

func decodeAPIError(status int, data []byte) error {
	var envelope apiErrorEnvelope
	if err := decodeStrictJSON(data, &envelope); err == nil && envelope.Error.Code != "" {
		return fmt.Errorf("Cloud API %s: %s", envelope.Error.Code, envelope.Error.Message)
	}
	return fmt.Errorf("Cloud API returned HTTP %d", status)
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("response contains more than one JSON value")
		}
		return err
	}
	return nil
}
