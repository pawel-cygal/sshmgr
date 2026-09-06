package access

import "testing"

func TestAnalyzeDistinguishesUnsupportedSSHTargetFromConnectionFailure(t *testing.T) {
	snapshot := &Snapshot{Hosts: []HostSnapshot{
		{
			Alias: "network-device", Coverage: CoverageFailed,
			Errors: []ScanError{
				{Stage: "sftp", Message: "EOF"},
				{Stage: collectorUnsupportedStage, Message: "authenticated target has no supported collector"},
			},
		},
		{
			Alias: "unreachable", Coverage: CoverageFailed,
			Errors: []ScanError{{Stage: "connect", Message: "authentication failed"}},
		},
	}}

	findings := Analyze(snapshot)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want two distinct failed-coverage findings", findings)
	}
	byHost := map[string]Finding{}
	for _, finding := range findings {
		byHost[finding.Host] = finding
	}
	unsupported := byHost["network-device"]
	if unsupported.RuleID != "unsupported_ssh_target" || unsupported.Severity != SeverityHigh {
		t.Fatalf("unsupported target finding = %+v", unsupported)
	}
	if len(unsupported.Evidence) != 2 || unsupported.CoverageCaveat == "" || unsupported.RecommendedAction == "" {
		t.Fatalf("unsupported target lost evidence or coverage guidance: %+v", unsupported)
	}
	failed := byHost["unreachable"]
	if failed.RuleID != "scan_failed" || failed.Severity != SeverityHigh {
		t.Fatalf("connection failure finding = %+v", failed)
	}
}

func TestAnalyzeFindsReuseDuplicatesAmbiguousHintsAndPermissions(t *testing.T) {
	snapshot := &Snapshot{Hosts: []HostSnapshot{
		{
			Alias: "one", Coverage: CoveragePartial,
			Accounts: []AccountSnapshot{{Username: "deploy", Sources: []KeySource{{
				Path: ".ssh/authorized_keys", Exists: true, Mode: "0664",
				Entries: []KeyObservation{
					{Line: 1, Fingerprint: "SHA256:key", Algorithm: "ssh-ed25519", Bits: 256, Comment: "alice@laptop"},
					{Line: 2, Fingerprint: "SHA256:key", Algorithm: "ssh-ed25519", Bits: 256, Comment: "bob@desktop"},
				},
			}}}},
		},
		{
			Alias: "two", Coverage: CoveragePartial,
			Accounts: []AccountSnapshot{{Username: "root", Sources: []KeySource{{
				Path: ".ssh/authorized_keys", Exists: true, Mode: "0600",
				Entries: []KeyObservation{{Line: 1, Fingerprint: "SHA256:key", Algorithm: "ssh-ed25519", Bits: 256, Comment: "alice@laptop"}},
			}}}},
		},
	}}
	findings := Analyze(snapshot)
	want := map[string]bool{
		"partial_scan": false, "unsafe_key_file_permissions": false, "duplicate_key_entry": false,
		"reused_key": false, "ambiguous_identity_hint": false,
	}
	for _, finding := range findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for rule, found := range want {
		if !found {
			t.Errorf("expected %s finding; got %+v", rule, findings)
		}
	}
}

func TestAnalyzeWeakKeyPolicyDoesNotFlagRSA2048(t *testing.T) {
	if severity, _ := weakKey("ssh-rsa", 2048); severity != "" {
		t.Fatalf("RSA 2048 incorrectly flagged: %s", severity)
	}
	if severity, _ := weakKey("ssh-rsa", 1024); severity != SeverityHigh {
		t.Fatalf("RSA 1024 severity = %q", severity)
	}
	if severity, _ := weakKey("ssh-dss", 1024); severity != SeverityHigh {
		t.Fatalf("DSA severity = %q", severity)
	}
}

func TestAnalyzeFindsTruncatedAndAccountSpecificSources(t *testing.T) {
	snapshot := &Snapshot{Hosts: []HostSnapshot{{
		Alias: "server", Coverage: CoveragePartial,
		System: &SystemSnapshot{
			AccountsTruncated: true,
			AccountLimit:      512,
			MissingAccounts:   []string{"ghost"},
			SSHD: SSHDConfigSnapshot{
				AuthorizedKeysCommand:       "none",
				TrustedUserCAKeys:           "none",
				AuthorizedPrincipalsCommand: "none",
			},
		},
		Accounts: []AccountSnapshot{{
			Username: "deploy",
			Auth: &AccountAuthSnapshot{
				EffectiveConfig:             true,
				AuthorizedKeysCommand:       "/usr/local/bin/keys",
				AuthorizedKeysCommandUser:   "nobody",
				TrustedUserCAKeys:           "/etc/ssh/deploy-ca.pub",
				AuthorizedPrincipalsCommand: "/usr/local/bin/principals",
			},
		}},
	}}}
	findings := Analyze(snapshot)
	want := map[string]bool{
		"account_enumeration_truncated": false,
		"requested_account_missing":     false,
		"external_key_source":           false,
		"trusted_ssh_ca_detected":       false,
		"external_principals_source":    false,
	}
	for _, finding := range findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for rule, found := range want {
		if !found {
			t.Errorf("expected %s finding; got %+v", rule, findings)
		}
	}
}

func TestAnalyzeSystemSourceOwnershipDirectoryAndCoverageFindings(t *testing.T) {
	accountUID := uint64(1000)
	foreignUID := uint64(2000)
	snapshot := &Snapshot{Hosts: []HostSnapshot{{
		Alias: "server", Coverage: CoveragePartial,
		System: &SystemSnapshot{
			SourcesRequested: 3, SourcesInspected: 1, SourceBytesRead: 128,
			SourcesTruncated: true, ContentBudgetHit: true,
		},
		Accounts: []AccountSnapshot{{
			Username: "deploy", UID: &accountUID,
			Sources: []KeySource{{
				Path: "/home/deploy/.ssh/authorized_keys", Exists: true,
				Mode: "0600", OwnerUID: &foreignUID,
				ParentPath: "/home/deploy/.ssh", ParentMode: "0775", ParentOwnerUID: &foreignUID,
				Error: "key source exceeds the remaining per-host read budget",
			}},
		}},
	}}}
	findings := Analyze(snapshot)
	want := map[string]bool{
		"key_source_enumeration_truncated": false,
		"key_content_budget_exhausted":     false,
		"unsafe_key_directory_permissions": false,
		"unexpected_key_file_owner":        false,
		"unexpected_key_directory_owner":   false,
		"key_source_not_inspected":         false,
	}
	for _, finding := range findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for rule, found := range want {
		if !found {
			t.Errorf("expected %s finding; got %+v", rule, findings)
		}
	}
}
