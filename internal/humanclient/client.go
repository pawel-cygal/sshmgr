// Package humanclient implements the human-authenticated sshmgr Cloud API.
// It is intentionally separate from cloudclient, whose bearer token belongs
// to a project runner and must never be promoted into a human session.
package humanclient

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
	"strings"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/cloudclient"
)

const maxResponseBytes = 4 << 20

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

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Cloud API %s (%d): %s", e.Code, e.Status, e.Message)
}

func IsCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

func New(options Options) (*Client, error) {
	canonical, err := cloudclient.NormalizeEndpoint(options.Endpoint, options.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse(canonical)
	if options.Timeout <= 0 || options.Timeout > 15*time.Minute {
		return nil, errors.New("human Cloud timeout must be greater than zero and at most 15 minutes")
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
		return errors.New("Cloud API redirects are disabled to protect the human session")
	}
	return &Client{base: base, token: strings.TrimSpace(options.Token), userAgent: strings.TrimSpace(options.UserAgent), http: &clone}, nil
}

func (c *Client) StartDeviceAuthorization(ctx context.Context) (*cloudcontract.DeviceAuthorization, error) {
	var result cloudcontract.DeviceAuthorization
	if err := c.doJSON(ctx, http.MethodPost, []string{"v2", "device", "authorize"}, cloudcontract.DeviceAuthorizationRequest{ClientName: "sshmgr CLI"}, &result, false); err != nil {
		return nil, err
	}
	if result.SchemaVersion != "1" || result.DeviceCode == "" || result.UserCode == "" || result.VerificationURI == "" || result.ExpiresIn < 1 || result.Interval < 1 {
		return nil, errors.New("Cloud device authorization response is invalid")
	}
	return &result, nil
}

func (c *Client) ExchangeDeviceAuthorization(ctx context.Context, deviceCode string) (*cloudcontract.CLISessionIssue, error) {
	var result cloudcontract.CLISessionIssue
	if err := c.doJSON(ctx, http.MethodPost, []string{"v2", "device", "token"}, cloudcontract.DeviceTokenRequest{DeviceCode: deviceCode}, &result, false); err != nil {
		return nil, err
	}
	if result.SchemaVersion != "1" || result.TokenType != "Bearer" || result.AccessToken == "" || result.ExpiresIn < 1 || result.Session.User.ID == "" {
		return nil, errors.New("Cloud device token response is invalid")
	}
	return &result, nil
}

func (c *Client) Session(ctx context.Context) (*cloudcontract.BrowserSession, error) {
	var result struct {
		SchemaVersion string                       `json:"schema_version"`
		Session       cloudcontract.BrowserSession `json:"session"`
	}
	if err := c.doJSON(ctx, http.MethodGet, []string{"v2", "cli", "session"}, nil, &result, true); err != nil {
		return nil, err
	}
	if result.SchemaVersion != "1" || result.Session.User.ID == "" {
		return nil, errors.New("Cloud human session response is invalid")
	}
	return &result.Session, nil
}

func (c *Client) Logout(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, []string{"v2", "cli", "session"}, nil, nil, true)
}

func (c *Client) Invite(ctx context.Context, organization, project string, request *cloudcontract.CreateOnboardingRequest) (*cloudcontract.OnboardingCreateResult, error) {
	var result cloudcontract.OnboardingCreateResult
	if err := c.doJSON(ctx, http.MethodPost, accessPath(organization, project, "invitations"), request, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Invitations(ctx context.Context, organization, project string) (*cloudcontract.OnboardingList, error) {
	var result cloudcontract.OnboardingList
	if err := c.doJSON(ctx, http.MethodGet, accessPath(organization, project, "invitations"), nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Approve(ctx context.Context, organization, project, invitationID string, request *cloudcontract.ReviewOnboardingRequest) (*cloudcontract.OnboardingInvitation, error) {
	var result cloudcontract.OnboardingInvitation
	if err := c.doJSON(ctx, http.MethodPost, accessPath(organization, project, "invitations", invitationID, "approve"), request, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Grants(ctx context.Context, organization, project string) (*cloudcontract.DesiredGrantList, error) {
	var result cloudcontract.DesiredGrantList
	if err := c.doJSON(ctx, http.MethodGet, accessPath(organization, project, "grants"), nil, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Revoke(ctx context.Context, organization, project string, request *cloudcontract.RevokeDesiredGrantsRequest) (*cloudcontract.RevokeDesiredGrantsResult, error) {
	var result cloudcontract.RevokeDesiredGrantsResult
	if err := c.doJSON(ctx, http.MethodPost, accessPath(organization, project, "revoke"), request, &result, true); err != nil {
		return nil, err
	}
	return &result, nil
}

func accessPath(organization, project string, tail ...string) []string {
	return append([]string{"v2", "organizations", organization, "projects", project, "access"}, tail...)
}

func (c *Client) doJSON(ctx context.Context, method string, segments []string, input, output any, authenticated bool) error {
	target := *c.base
	parts := append([]string{target.Path}, segments...)
	target.Path = path.Join(parts...)
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		if c.token == "" {
			return errors.New("human Cloud session token is missing")
		}
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("Cloud response exceeds the safety limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code, Message string
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &envelope)
		return &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("parse Cloud response: %w", err)
	}
	return nil
}
