// Package cloudtest provides a deliberately small in-memory HTTP fixture for
// testing the public Cloud client. It models the wire contract only and is not
// a deployable Cloud server.
package cloudtest

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/systeampl/sshmgr/cloudcontract"
	"github.com/systeampl/sshmgr/internal/cloudclient"
)

type Service struct {
	Token        string
	PrincipalID  string
	Organization string
	Project      string

	mu      sync.Mutex
	bundles map[string]cloudclient.BundleMetadata
}

func New(token, principalID string) *Service {
	return &Service{
		Token: token, PrincipalID: principalID, Organization: "local", Project: "golden-workspace",
		bundles: make(map[string]cloudclient.BundleMetadata),
	}
}

func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Service) Bundles() []cloudclient.BundleMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]cloudclient.BundleMetadata, 0, len(s.bundles))
	for _, metadata := range s.bundles {
		result = append(result, metadata)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].BundleID < result[j].BundleID })
	return result
}

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "bearer token is not authenticated")
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	organization, project, apiVersion, action, ok := route(segments)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if organization != "" && organization != s.Organization {
		writeError(w, http.StatusForbidden, "forbidden", "token is not authorized for this organization")
		return
	}
	if project != s.Project {
		writeError(w, http.StatusForbidden, "forbidden", "token is not authorized for this project")
		return
	}
	switch action {
	case "status":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		capabilities := []string{"workspace_status", "bundle_ingest"}
		if apiVersion == "v2" {
			capabilities = append(capabilities, "project_api")
		}
		_ = json.NewEncoder(w).Encode(cloudclient.ServiceStatus{
			SchemaVersion: "1", Service: "sshmgr-cloud-api", Status: "ready", APIVersion: apiVersion,
			Storage: "memory_contract_fixture", Workspace: project, Organization: organization, Project: project,
			PrincipalID: s.PrincipalID, Version: "contract-test", Commit: "test-commit", BuildDate: "2026-08-13T20:00:00Z",
			ServerTime: time.Now().UTC().Format(time.RFC3339Nano), Capabilities: capabilities,
		})
	case "bundles":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		var bundle cloudcontract.WorkspaceBundle
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, cloudcontract.MaxWorkspaceBundleBytes+1))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&bundle) != nil || cloudcontract.ValidateWorkspaceBundle(&bundle) != nil || bundle.Workspace != project {
			writeError(w, http.StatusBadRequest, "invalid_bundle", "bundle is invalid")
			return
		}
		metadata := cloudclient.BundleMetadata{
			Workspace: bundle.Workspace, BundleID: bundle.BundleID,
			HistoryID: bundle.Payload.WorkspaceHistory.HistoryID, LatestScanID: bundle.Payload.WorkspaceHistory.LatestScanID,
			PayloadSHA256: bundle.PayloadSHA256, PayloadBytes: bundle.PayloadBytes,
			ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), PrincipalID: s.PrincipalID,
		}
		s.mu.Lock()
		previous, exists := s.bundles[bundle.BundleID]
		if exists {
			metadata = previous
		} else {
			s.bundles[bundle.BundleID] = metadata
		}
		s.mu.Unlock()
		status := "created"
		code := http.StatusCreated
		if exists {
			status, code = "already_exists", http.StatusOK
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(cloudclient.UploadResult{SchemaVersion: "1", Status: status, Bundle: metadata})
	}
}

func route(segments []string) (organization, project, apiVersion, action string, ok bool) {
	if len(segments) == 4 && segments[0] == "v1" && segments[1] == "workspaces" && (segments[3] == "status" || segments[3] == "bundles") {
		return "", segments[2], "v1", segments[3], true
	}
	if len(segments) == 6 && segments[0] == "v2" && segments[1] == "organizations" && segments[3] == "projects" && (segments[5] == "status" || segments[5] == "bundles") {
		return segments[2], segments[4], "v2", segments[5], true
	}
	return "", "", "", "", false
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
