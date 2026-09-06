package access

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const FindingRuleVersion = "1"

const collectorUnsupportedStage = "collector-unsupported"

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is a versioned conclusion derived locally from normalized scan
// evidence. It never upgrades comments into verified identity ownership.
type Finding struct {
	RuleID            string   `json:"rule_id"`
	RuleVersion       string   `json:"rule_version"`
	Severity          string   `json:"severity"`
	Title             string   `json:"title"`
	Host              string   `json:"host,omitempty"`
	Account           string   `json:"account,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`
	Occurrences       int      `json:"occurrences,omitempty"`
	Hosts             []string `json:"hosts,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
	CoverageCaveat    string   `json:"coverage_caveat,omitempty"`
	RecommendedAction string   `json:"recommended_action,omitempty"`
}

type keyOccurrence struct {
	host      string
	account   string
	source    string
	line      int
	algorithm string
	bits      int
	comment   string
}

// Analyze applies the v1 local rule set. Unknown/shared ownership rules are
// intentionally deferred until an explicit identity map exists.
func Analyze(snapshot *Snapshot) []Finding {
	if snapshot == nil {
		return nil
	}
	var findings []Finding
	byFingerprint := map[string][]keyOccurrence{}

	for _, host := range snapshot.Hosts {
		switch host.Coverage {
		case CoverageFailed:
			if hasScanErrorStage(host.Errors, collectorUnsupportedStage) {
				findings = append(findings, Finding{
					RuleID: "unsupported_ssh_target", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
					Title: "SSH target does not support the Unix access collectors", Host: host.Alias,
					Evidence:          scanErrorEvidence(host.Errors),
					CoverageCaveat:    "No conclusion about SSH access on this target can be drawn from this snapshot.",
					RecommendedAction: "Classify the target in inventory and use a device-specific access review, or explicitly exclude it with documented scope.",
				})
			} else {
				findings = append(findings, Finding{
					RuleID: "scan_failed", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
					Title: "Host could not be scanned", Host: host.Alias,
					Evidence:          scanErrorEvidence(host.Errors),
					CoverageCaveat:    "No conclusion about SSH access on this host can be drawn from this snapshot.",
					RecommendedAction: "Resolve the reported connection or collector error and scan the host again.",
				})
			}
		case CoveragePartial:
			findings = append(findings, Finding{
				RuleID: "partial_scan", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
				Title: "SSH access coverage is partial", Host: host.Alias,
				Evidence:          append([]string(nil), host.Limitations...),
				CoverageCaveat:    "Unobserved SSH access sources may still grant access.",
				RecommendedAction: "Review coverage limitations before using this scan for an access decision.",
			})
		}
		if host.System != nil {
			sshd := host.System.SSHD
			if len(host.System.MissingAccounts) > 0 {
				findings = append(findings, Finding{
					RuleID: "requested_account_missing", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "One or more explicitly requested accounts were not found", Host: host.Alias,
					Evidence:          []string{"missing accounts: " + strings.Join(host.System.MissingAccounts, ", ")},
					CoverageCaveat:    "A failed keyed NSS lookup does not prove that the identity has no access through another account or source.",
					RecommendedAction: "Verify the account spelling and identity-provider visibility, then rerun the explicit scan.",
				})
			}
			if host.System.AccountsTruncated {
				findings = append(findings, Finding{
					RuleID: "account_enumeration_truncated", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "System account enumeration reached its safety limit", Host: host.Alias,
					Evidence:          []string{fmt.Sprintf("at most %d accounts were returned", host.System.AccountLimit)},
					CoverageCaveat:    "Accounts beyond the limit may have additional SSH access sources.",
					RecommendedAction: "Review the account source and use a narrower account policy before increasing the limit.",
				})
			}
			if host.System.SourcesTruncated {
				findings = append(findings, Finding{
					RuleID: "key_source_enumeration_truncated", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "Static key source enumeration reached its safety limit", Host: host.Alias,
					Evidence:          []string{fmt.Sprintf("%d static sources were discovered", host.System.SourcesRequested)},
					CoverageCaveat:    "Sources beyond the collector limit were not inspected.",
					RecommendedAction: "Narrow the account scope and scan the remaining accounts separately.",
				})
			}
			if host.System.ContentBudgetHit {
				findings = append(findings, Finding{
					RuleID: "key_content_budget_exhausted", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "Per-host authorized-key read budget was exhausted", Host: host.Alias,
					Evidence:          []string{fmt.Sprintf("%d source bytes were inspected", host.System.SourceBytesRead)},
					CoverageCaveat:    "One or more static key sources were not read.",
					RecommendedAction: "Review source sizes and rerun with a narrowly scoped, explicitly increased read budget.",
				})
			}
			if enabledSSHDSource(sshd.AuthorizedKeysCommand) {
				findings = append(findings, Finding{
					RuleID: "external_key_source", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "AuthorizedKeysCommand supplies dynamic SSH keys", Host: host.Alias,
					Evidence:          []string{fmt.Sprintf("AuthorizedKeysCommand=%s (user=%s)", sshd.AuthorizedKeysCommand, sshd.AuthorizedKeysCommandUser)},
					CoverageCaveat:    "A command-backed key source cannot be enumerated by file inspection alone.",
					RecommendedAction: "Identify the command's upstream identity source and include it in the access review.",
				})
			}
			if enabledSSHDSource(sshd.TrustedUserCAKeys) {
				findings = append(findings, Finding{
					RuleID: "trusted_ssh_ca_detected", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "Host trusts an SSH user certificate authority", Host: host.Alias,
					Evidence:          []string{"TrustedUserCAKeys=" + sshd.TrustedUserCAKeys},
					CoverageCaveat:    "Certificate access cannot be derived from authorized_keys files alone.",
					RecommendedAction: "Review the CA issuer, principals policy, and certificate lifetime controls.",
				})
			}
			if enabledSSHDSource(sshd.AuthorizedPrincipalsCommand) {
				findings = append(findings, Finding{
					RuleID: "external_principals_source", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
					Title: "AuthorizedPrincipalsCommand supplies dynamic certificate principals", Host: host.Alias,
					Evidence:          []string{"AuthorizedPrincipalsCommand=" + sshd.AuthorizedPrincipalsCommand},
					CoverageCaveat:    "Dynamic principal authorization requires review of the command's upstream policy.",
					RecommendedAction: "Map the principals command to its identity source and access policy.",
				})
			}
		}

		for _, account := range host.Accounts {
			if account.Auth != nil && host.System != nil {
				hostSSHD := host.System.SSHD
				if enabledSSHDSource(account.Auth.AuthorizedKeysCommand) && account.Auth.AuthorizedKeysCommand != hostSSHD.AuthorizedKeysCommand {
					findings = append(findings, Finding{
						RuleID: "external_key_source", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
						Title: "Account-specific AuthorizedKeysCommand supplies dynamic SSH keys", Host: host.Alias, Account: account.Username,
						Evidence:          []string{fmt.Sprintf("AuthorizedKeysCommand=%s (user=%s)", account.Auth.AuthorizedKeysCommand, account.Auth.AuthorizedKeysCommandUser)},
						CoverageCaveat:    "A command-backed key source cannot be enumerated by file inspection alone.",
						RecommendedAction: "Identify the command's upstream identity source and include it in the access review.",
					})
				}
				if enabledSSHDSource(account.Auth.TrustedUserCAKeys) && account.Auth.TrustedUserCAKeys != hostSSHD.TrustedUserCAKeys {
					findings = append(findings, Finding{
						RuleID: "trusted_ssh_ca_detected", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
						Title: "Account-specific SSH user certificate authority is trusted", Host: host.Alias, Account: account.Username,
						Evidence:          []string{"TrustedUserCAKeys=" + account.Auth.TrustedUserCAKeys},
						CoverageCaveat:    "Certificate access cannot be derived from authorized_keys files alone.",
						RecommendedAction: "Review the CA issuer, principals policy, and certificate lifetime controls.",
					})
				}
				if enabledSSHDSource(account.Auth.AuthorizedPrincipalsCommand) && account.Auth.AuthorizedPrincipalsCommand != hostSSHD.AuthorizedPrincipalsCommand {
					findings = append(findings, Finding{
						RuleID: "external_principals_source", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
						Title: "Account-specific command supplies dynamic certificate principals", Host: host.Alias, Account: account.Username,
						Evidence:          []string{"AuthorizedPrincipalsCommand=" + account.Auth.AuthorizedPrincipalsCommand},
						CoverageCaveat:    "Dynamic principal authorization requires review of the command's upstream policy.",
						RecommendedAction: "Map the principals command to its identity source and access policy.",
					})
				}
			}
			for _, source := range account.Sources {
				if source.Exists && unsafeAuthorizedKeysMode(source.Mode) {
					findings = append(findings, Finding{
						RuleID: "unsafe_key_file_permissions", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
						Title: "authorized_keys is writable by group or others", Host: host.Alias, Account: account.Username,
						Evidence:          []string{fmt.Sprintf("%s mode is %s", source.Path, source.Mode)},
						RecommendedAction: "Inspect ownership and permissions; OpenSSH key files should not be writable by group or others.",
					})
				}
				if source.ParentMode != "" && unsafeAuthorizedKeysMode(source.ParentMode) {
					findings = append(findings, Finding{
						RuleID: "unsafe_key_directory_permissions", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
						Title: "authorized_keys parent directory is writable by group or others", Host: host.Alias, Account: account.Username,
						Evidence:          []string{fmt.Sprintf("%s mode is %s", source.ParentPath, source.ParentMode)},
						RecommendedAction: "Inspect ownership and permissions before changing them; the key directory should not be writable by group or others.",
					})
				}
				if unexpectedAuthorizedKeysOwner(source.OwnerUID, account.UID) {
					findings = append(findings, Finding{
						RuleID: "unexpected_key_file_owner", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
						Title: "authorized_keys is not owned by the account or root", Host: host.Alias, Account: account.Username,
						Evidence:          []string{fmt.Sprintf("%s owner uid is %d; account uid is %d", source.Path, *source.OwnerUID, *account.UID)},
						RecommendedAction: "Verify why another identity owns this access file before changing ownership.",
					})
				}
				if unexpectedAuthorizedKeysOwner(source.ParentOwnerUID, account.UID) {
					findings = append(findings, Finding{
						RuleID: "unexpected_key_directory_owner", RuleVersion: FindingRuleVersion, Severity: SeverityHigh,
						Title: "authorized_keys parent directory is not owned by the account or root", Host: host.Alias, Account: account.Username,
						Evidence:          []string{fmt.Sprintf("%s owner uid is %d; account uid is %d", source.ParentPath, *source.ParentOwnerUID, *account.UID)},
						RecommendedAction: "Verify the directory ownership and effective sshd policy before changing it.",
					})
				}
				if source.Symlink || source.AncestorSymlink {
					target := source.Path
					findings = append(findings, Finding{
						RuleID: "symlinked_key_source", RuleVersion: FindingRuleVersion, Severity: SeverityMedium,
						Title: "Static authorized-key source uses a symlink", Host: host.Alias, Account: account.Username,
						Evidence:          []string{target + " is a symlink or has a symlinked ancestor and was not followed"},
						CoverageCaveat:    "The destination and its key entries were deliberately not inspected.",
						RecommendedAction: "Review the symlink target and ownership manually before deciding whether it is expected.",
					})
				}
				if source.Exists && !source.ContentInspected && source.Error != "" {
					findings = append(findings, Finding{
						RuleID: "key_source_not_inspected", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
						Title: "Static authorized-key source was not fully inspected", Host: host.Alias, Account: account.Username,
						Evidence:          []string{fmt.Sprintf("%s: %s", source.Path, source.Error)},
						CoverageCaveat:    "The source may contain additional SSH access grants.",
						RecommendedAction: "Resolve the source-specific limitation and rerun a narrowly scoped scan.",
					})
				}
				perSource := map[string]int{}
				for _, entry := range source.Entries {
					if entry.ParseError != "" || entry.Fingerprint == "" {
						continue
					}
					byFingerprint[entry.Fingerprint] = append(byFingerprint[entry.Fingerprint], keyOccurrence{
						host: host.Alias, account: account.Username, source: source.Path, line: entry.Line,
						algorithm: entry.Algorithm, bits: entry.Bits, comment: entry.Comment,
					})
					perSource[entry.Fingerprint]++
				}
				for fingerprint, count := range perSource {
					if count < 2 {
						continue
					}
					findings = append(findings, Finding{
						RuleID: "duplicate_key_entry", RuleVersion: FindingRuleVersion, Severity: SeverityLow,
						Title: "The same key appears multiple times in one access file", Host: host.Alias, Account: account.Username,
						Fingerprint: fingerprint, Occurrences: count,
						Evidence:          []string{fmt.Sprintf("%s contains %d entries with this fingerprint", source.Path, count)},
						RecommendedAction: "Review the duplicate lines and their comments; remove duplication only after confirming intent.",
					})
				}
			}
		}
	}

	fingerprints := make([]string, 0, len(byFingerprint))
	for fingerprint := range byFingerprint {
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	for _, fingerprint := range fingerprints {
		occurrences := byFingerprint[fingerprint]
		hosts := distinctOccurrenceHosts(occurrences)
		if len(hosts) > 1 {
			findings = append(findings, Finding{
				RuleID: "reused_key", RuleVersion: FindingRuleVersion, Severity: SeverityInfo,
				Title: "SSH key grants access on multiple hosts", Fingerprint: fingerprint,
				Occurrences: len(occurrences), Hosts: hosts,
				Evidence:          []string{fmt.Sprintf("fingerprint appears in %d entries across %d hosts", len(occurrences), len(hosts))},
				CoverageCaveat:    "Key reuse can be intentional; this rule does not establish ownership.",
				RecommendedAction: "Assign and verify an owner, then confirm that every observed host grant is still required.",
			})
		}
		comments := distinctOccurrenceComments(occurrences)
		if len(comments) > 1 {
			findings = append(findings, Finding{
				RuleID: "ambiguous_identity_hint", RuleVersion: FindingRuleVersion, Severity: SeverityMedium,
				Title: "One fingerprint has conflicting authorized_keys comments", Fingerprint: fingerprint,
				Occurrences: len(occurrences), Hosts: hosts,
				Evidence:          []string{"comments observed: " + strings.Join(comments, ", ")},
				CoverageCaveat:    "authorized_keys comments are unverified hints, not proof of identity or private-key possession.",
				RecommendedAction: "Ask the suspected owners to claim and verify the fingerprint before changing access.",
			})
		}
		if severity, reason := weakKey(occurrences[0].algorithm, occurrences[0].bits); severity != "" {
			findings = append(findings, Finding{
				RuleID: "weak_key", RuleVersion: FindingRuleVersion, Severity: severity,
				Title: "SSH key does not meet the default cryptographic policy", Fingerprint: fingerprint,
				Occurrences: len(occurrences), Hosts: hosts, Evidence: []string{reason},
				RecommendedAction: "Verify the owner and plan rotation to a modern key before removing existing access.",
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Host != findings[j].Host {
			return findings[i].Host < findings[j].Host
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings
}

func hasScanErrorStage(errors []ScanError, stage string) bool {
	for _, scanError := range errors {
		if scanError.Stage == stage {
			return true
		}
	}
	return false
}

func enabledSSHDSource(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.EqualFold(value, "none")
}

func unsafeAuthorizedKeysMode(value string) bool {
	mode, err := strconv.ParseUint(value, 8, 32)
	return err == nil && mode&0o022 != 0
}

func unexpectedAuthorizedKeysOwner(ownerUID, accountUID *uint64) bool {
	return ownerUID != nil && accountUID != nil && *ownerUID != 0 && *ownerUID != *accountUID
}

func weakKey(algorithm string, bits int) (string, string) {
	switch algorithm {
	case "ssh-dss":
		return SeverityHigh, "DSA SSH keys are deprecated"
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		if bits > 0 && bits < 2048 {
			return SeverityHigh, fmt.Sprintf("RSA key size is %d bits; minimum policy is 2048", bits)
		}
	}
	return "", ""
}

func distinctOccurrenceHosts(occurrences []keyOccurrence) []string {
	set := map[string]bool{}
	for _, occurrence := range occurrences {
		set[occurrence.host] = true
	}
	return sortedSet(set)
}

func distinctOccurrenceComments(occurrences []keyOccurrence) []string {
	set := map[string]bool{}
	for _, occurrence := range occurrences {
		if comment := strings.TrimSpace(occurrence.comment); comment != "" {
			set[comment] = true
		}
	}
	return sortedSet(set)
}

func sortedSet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func scanErrorEvidence(errors []ScanError) []string {
	evidence := make([]string, 0, len(errors))
	for _, scanError := range errors {
		evidence = append(evidence, fmt.Sprintf("%s: %s", scanError.Stage, scanError.Message))
	}
	return evidence
}

func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}
