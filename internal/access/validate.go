package access

import (
	"fmt"
	"strings"
	"time"
)

// ValidateSnapshot enforces the stable semantic invariants of snapshot schema
// v1. Readers remain forward-compatible with unknown JSON fields, but an
// artifact that claims v1 must reconcile its normalized observations and
// summary counters before reports or a future cloud client may consume it.
func ValidateSnapshot(snapshot *Snapshot) error {
	if snapshot == nil {
		return invalidSnapshot("snapshot is nil")
	}
	if snapshot.SchemaVersion != SchemaVersion {
		return invalidSnapshot("unsupported schema_version %q (supported: %s)", snapshot.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(snapshot.ScanID) == "" {
		return invalidSnapshot("scan_id is required")
	}
	lineage := map[string]struct{}{}
	for index, sourceID := range snapshot.SourceScanIDs {
		if strings.TrimSpace(sourceID) == "" {
			return invalidSnapshot("source_scan_ids[%d] is empty", index)
		}
		if _, exists := lineage[sourceID]; exists {
			return invalidSnapshot("source_scan_ids contains duplicate %q", sourceID)
		}
		lineage[sourceID] = struct{}{}
	}
	started, err := time.Parse(time.RFC3339Nano, snapshot.StartedAt)
	if err != nil {
		return invalidSnapshot("started_at is not RFC3339: %v", err)
	}
	completed, err := time.Parse(time.RFC3339Nano, snapshot.CompletedAt)
	if err != nil {
		return invalidSnapshot("completed_at is not RFC3339: %v", err)
	}
	if completed.Before(started) {
		return invalidSnapshot("completed_at precedes started_at")
	}
	if snapshot.Scope.Mode != "current" && snapshot.Scope.Mode != "system" {
		return invalidSnapshot("scope.mode must be current or system, got %q", snapshot.Scope.Mode)
	}
	if strings.TrimSpace(snapshot.Scope.Selector) == "" {
		return invalidSnapshot("scope.selector is required")
	}
	if snapshot.Scope.RequestedHosts < 0 || snapshot.Scope.MaxAccounts < 0 || snapshot.Scope.MaxSourceBytes < 0 || snapshot.Scope.MaxTotalSourceBytes < 0 {
		return invalidSnapshot("scope budgets and requested_hosts cannot be negative")
	}
	if snapshot.Scope.MaxSourceBytes > 0 && snapshot.Scope.MaxTotalSourceBytes > 0 && snapshot.Scope.MaxSourceBytes > snapshot.Scope.MaxTotalSourceBytes {
		return invalidSnapshot("max_source_bytes exceeds max_total_source_bytes")
	}
	if snapshot.Scope.Preflight && snapshot.Scope.IncludePublicKeys {
		return invalidSnapshot("preflight cannot include public-key material")
	}
	if snapshot.Scope.Mode == "system" {
		switch snapshot.Scope.AccountMode {
		case AccountModeLocal, AccountModeNSS, AccountModeExplicit:
		default:
			return invalidSnapshot("system scope has invalid account_mode %q", snapshot.Scope.AccountMode)
		}
	}
	if snapshot.Scope.RequestedHosts != len(snapshot.Hosts) {
		return invalidSnapshot("scope.requested_hosts=%d, observed host records=%d", snapshot.Scope.RequestedHosts, len(snapshot.Hosts))
	}

	derived := Summary{HostsRequested: len(snapshot.Hosts)}
	fingerprints := map[string]struct{}{}
	hosts := map[string]struct{}{}
	for hostIndex, host := range snapshot.Hosts {
		if strings.TrimSpace(host.Alias) == "" {
			return invalidSnapshot("hosts[%d].alias is required", hostIndex)
		}
		if _, exists := hosts[host.Alias]; exists {
			return invalidSnapshot("duplicate host alias %q", host.Alias)
		}
		hosts[host.Alias] = struct{}{}
		if host.DurationMS < 0 {
			return invalidSnapshot("host %q has negative duration_ms", host.Alias)
		}
		switch host.Coverage {
		case CoverageFull:
			derived.HostsFull++
		case CoveragePartial:
			derived.HostsPartial++
		case CoverageFailed:
			derived.HostsFailed++
		default:
			return invalidSnapshot("host %q has invalid coverage %q", host.Alias, host.Coverage)
		}
		for errorIndex, scanError := range host.Errors {
			if strings.TrimSpace(scanError.Stage) == "" || strings.TrimSpace(scanError.Message) == "" {
				return invalidSnapshot("host %q errors[%d] requires stage and message", host.Alias, errorIndex)
			}
		}
		accounts := map[string]struct{}{}
		for accountIndex, account := range host.Accounts {
			if strings.TrimSpace(account.Username) == "" {
				return invalidSnapshot("host %q accounts[%d].username is required", host.Alias, accountIndex)
			}
			if _, exists := accounts[account.Username]; exists {
				return invalidSnapshot("host %q has duplicate account %q", host.Alias, account.Username)
			}
			accounts[account.Username] = struct{}{}
			derived.AccountsObserved++
			for sourceIndex, source := range account.Sources {
				ref := fmt.Sprintf("host %q account %q sources[%d]", host.Alias, account.Username, sourceIndex)
				if strings.TrimSpace(source.Type) == "" || strings.TrimSpace(source.Path) == "" {
					return invalidSnapshot("%s requires type and path", ref)
				}
				if source.Size < 0 {
					return invalidSnapshot("%s has negative size", ref)
				}
				if source.ContentInspected && !source.Exists {
					return invalidSnapshot("%s is inspected but does not exist", ref)
				}
				if !source.ContentInspected && len(source.Entries) > 0 {
					return invalidSnapshot("%s has entries although content_inspected is false", ref)
				}
				if source.ContentSHA256 != "" && (!source.ContentInspected || len(source.ContentSHA256) != len("SHA256:")+64 || !strings.HasPrefix(source.ContentSHA256, "SHA256:")) {
					return invalidSnapshot("%s has invalid content_sha256", ref)
				}
				if source.Exists {
					derived.KeySourcesFound++
				}
				if source.ContentInspected {
					derived.KeyBytesInspected += source.Size
				}
				for entryIndex, entry := range source.Entries {
					entryRef := fmt.Sprintf("%s entries[%d]", ref, entryIndex)
					if entry.Line < 1 {
						return invalidSnapshot("%s has invalid line %d", entryRef, entry.Line)
					}
					if entry.ParseError != "" {
						if entry.Fingerprint != "" || entry.PublicKey != "" {
							return invalidSnapshot("%s mixes parse_error with parsed key material", entryRef)
						}
						derived.MalformedEntries++
						continue
					}
					if !strings.HasPrefix(entry.Fingerprint, "SHA256:") || len(entry.Fingerprint) == len("SHA256:") {
						return invalidSnapshot("%s has invalid fingerprint %q", entryRef, entry.Fingerprint)
					}
					if strings.TrimSpace(entry.Algorithm) == "" || entry.Bits < 0 {
						return invalidSnapshot("%s requires an algorithm and non-negative bits", entryRef)
					}
					if entry.PublicKey != "" && !snapshot.Scope.IncludePublicKeys {
						return invalidSnapshot("%s contains public_key while include_public_keys is false", entryRef)
					}
					derived.AuthorizedKeyEntries++
					fingerprints[entry.Fingerprint] = struct{}{}
				}
			}
		}
	}
	derived.UniqueFingerprints = len(fingerprints)
	for findingIndex, finding := range snapshot.Findings {
		if strings.TrimSpace(finding.RuleID) == "" || finding.RuleVersion != FindingRuleVersion || strings.TrimSpace(finding.Title) == "" {
			return invalidSnapshot("findings[%d] requires rule_id, rule_version=%s, and title", findingIndex, FindingRuleVersion)
		}
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
			return invalidSnapshot("findings[%d] has invalid severity %q", findingIndex, finding.Severity)
		}
	}
	if snapshot.Summary != derived {
		return invalidSnapshot("summary does not reconcile: got %+v, derived %+v", snapshot.Summary, derived)
	}
	return nil
}

func invalidSnapshot(format string, args ...any) error {
	return fmt.Errorf("invalid access snapshot v%s: %s", SchemaVersion, fmt.Sprintf(format, args...))
}
