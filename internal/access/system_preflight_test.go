package access

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseSystemPreflight(t *testing.T) {
	data := strings.Join([]string{
		systemPreflightMagic,
		"CAP\teuid\t0",
		"CAP\troot\ttrue",
		"CAP\tos\tLinux",
		"CAP\taccount_database\tgetent",
		"CAP\tsshd_present\ttrue",
		"CAP\tsshd_path\t/usr/sbin/sshd",
		"CAP\tsshd_config_valid\ttrue",
		"CTX\teffective_user\taudit",
		"CTX\tmatch_host\tserver.example",
		"CTX\tmatch_address\t127.0.0.1",
		"CAP\tsshd_effective_config\ttrue",
		"SSHD\tpubkeyauthentication\tyes",
		"SSHD\tstrictmodes\tyes",
		"SSHD\tauthorizedkeysfile\t.ssh/authorized_keys /etc/ssh/keys/%u",
		"SSHD\tauthorizedkeyscommand\t/usr/local/bin/key-source",
		"SSHD\tauthorizedkeyscommanduser\tnobody",
		"SSHD\ttrustedusercakeys\t/etc/ssh/user_ca.pub",
		"SSHD\tauthorizedprincipalsfile\t/etc/ssh/principals/%u",
		"SSHD\tauthorizedprincipalscommand\t/usr/local/bin/principals",
		"CAP\taccount_mode\tlocal",
		"CAP\taccount_limit\t512",
		"CAP\taccounts_truncated\tfalse",
		"ACCOUNT\troot\t0\t0\t/root\t/bin/bash",
		"ACCOUNT_SSHD\troot\teffective_config\ttrue",
		"ACCOUNT_SSHD\troot\tpubkeyauthentication\tyes",
		"ACCOUNT_SSHD\troot\tauthorizedkeysfile\t.ssh/authorized_keys /etc/ssh/keys/%u-%U %%archive",
		"ACCOUNT\taudit\t1000\t1000\t/home/audit\t/bin/sh",
		"ACCOUNT_SSHD\taudit\teffective_config\tfalse",
		"ACCOUNT_MISSING\tghost\tnot-found",
		"CAP\taccounts_enumerated\ttrue",
		"FUTURE\tignored\tvalue",
		"END",
		"",
	}, "\n")
	system, accounts, err := ParseSystemPreflight([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if !system.Root || system.OS != "Linux" || system.AccountDatabase != "getent" {
		t.Fatalf("capabilities mismatch: %+v", system)
	}
	if !system.SSHD.Present || !system.SSHD.ConfigValid || !system.SSHD.EffectiveConfig {
		t.Fatalf("sshd state mismatch: %+v", system.SSHD)
	}
	if len(system.SSHD.AuthorizedKeysFiles) != 2 || system.SSHD.AuthorizedKeysFiles[1] != "/etc/ssh/keys/%u" {
		t.Fatalf("authorized key templates mismatch: %+v", system.SSHD.AuthorizedKeysFiles)
	}
	if system.SSHD.AuthorizedKeysCommandUser != "nobody" || system.SSHD.TrustedUserCAKeys != "/etc/ssh/user_ca.pub" {
		t.Fatalf("dynamic source mismatch: %+v", system.SSHD)
	}
	if !system.AccountsEnumerated || system.AccountsTruncated || system.AccountLimit != 512 || system.AccountMode != AccountModeLocal {
		t.Fatalf("account discovery state mismatch: %+v", system)
	}
	if len(accounts) != 2 || accounts[0].Username != "root" || accounts[1].Username != "audit" {
		t.Fatalf("account records mismatch: %+v", accounts)
	}
	if len(accounts[0].Sources) != 3 {
		t.Fatalf("expanded root sources mismatch: %+v", accounts[0].Sources)
	}
	wantPaths := []string{"/root/.ssh/authorized_keys", "/etc/ssh/keys/root-0", "/root/%archive"}
	for index, want := range wantPaths {
		if accounts[0].Sources[index].Path != want {
			t.Errorf("source %d = %q, want %q", index, accounts[0].Sources[index].Path, want)
		}
		if accounts[0].Sources[index].ContentInspected || accounts[0].Sources[index].Exists {
			t.Errorf("preflight source was treated as inspected: %+v", accounts[0].Sources[index])
		}
	}
	if len(accounts[1].Limitations) != 1 {
		t.Fatalf("missing ineffective sshd limitation: %+v", accounts[1])
	}
	if len(system.MissingAccounts) != 1 || system.MissingAccounts[0] != "ghost" {
		t.Fatalf("missing-account records mismatch: %+v", system.MissingAccounts)
	}
}

func TestParseSystemPreflightRejectsMalformedOrIncompleteProtocol(t *testing.T) {
	for name, data := range map[string]string{
		"bad header": "wrong\nEND\n",
		"bad record": systemPreflightMagic + "\nCAP\troot\nEND\n",
		"incomplete": systemPreflightMagic + "\nCAP\troot\ttrue\n",
		"bad euid":   systemPreflightMagic + "\nCAP\teuid\tnot-a-number\nEND\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseSystemPreflight([]byte(data)); err == nil {
				t.Fatalf("invalid protocol accepted: %q", data)
			}
		})
	}
}

func TestParseSystemPreflightRejectsUnsafeAccountRecords(t *testing.T) {
	tests := map[string]string{
		"duplicate":   "ACCOUNT\troot\t0\t0\t/root\t/bin/sh\nACCOUNT\troot\t0\t0\t/root\t/bin/sh",
		"bad uid":     "ACCOUNT\troot\tnan\t0\t/root\t/bin/sh",
		"bad user":    "ACCOUNT\t\t1\t1\t/home/bad\t/bin/sh",
		"orphan auth": "ACCOUNT_SSHD\troot\teffective_config\ttrue",
	}
	for name, records := range tests {
		t.Run(name, func(t *testing.T) {
			data := systemPreflightMagic + "\n" + records + "\nEND\n"
			if _, _, err := ParseSystemPreflight([]byte(data)); err == nil {
				t.Fatalf("unsafe account protocol accepted: %q", records)
			}
		})
	}
}

func TestExpandAuthorizedKeysPath(t *testing.T) {
	uid := uint64(1234)
	account := AccountSnapshot{Username: "deploy", UID: &uid, Home: "/srv/deploy"}
	for template, want := range map[string]string{
		".ssh/authorized_keys":        "/srv/deploy/.ssh/authorized_keys",
		"%h/.ssh/keys":                "/srv/deploy/.ssh/keys",
		"/etc/ssh/keys/%u/%U":         "/etc/ssh/keys/deploy/1234",
		"/etc/ssh/keys/%%break-glass": "/etc/ssh/keys/%break-glass",
	} {
		got, err := expandAuthorizedKeysPath(template, account)
		if err != nil {
			t.Fatalf("expand %q: %v", template, err)
		}
		if got != want {
			t.Errorf("expand %q = %q, want %q", template, got, want)
		}
	}
	for _, template := range []string{"", "%x/file", "dangling%"} {
		if _, err := expandAuthorizedKeysPath(template, account); err == nil {
			t.Errorf("invalid template accepted: %q", template)
		}
	}
	account.Home = "relative/home"
	if _, err := expandAuthorizedKeysPath("%h/.ssh/authorized_keys", account); err == nil {
		t.Error("%h accepted a non-absolute account home")
	}
}

func TestParseSystemPreflightEnforcesAccountRecordLimit(t *testing.T) {
	var data strings.Builder
	fmt.Fprintln(&data, systemPreflightMagic)
	for index := 0; index <= maxSystemAccounts; index++ {
		fmt.Fprintf(&data, "ACCOUNT\tuser%d\t%d\t%d\t/home/user%d\t/bin/sh\n", index, index, index, index)
	}
	fmt.Fprintln(&data, "END")
	if _, _, err := ParseSystemPreflight([]byte(data.String())); err == nil {
		t.Fatalf("more than %d system accounts were accepted", maxSystemAccounts)
	}
}

func FuzzParseSystemPreflight(f *testing.F) {
	f.Add(systemPreflightMagic + "\nCAP\teuid\t0\nCAP\troot\ttrue\nEND\n")
	f.Add(systemPreflightMagic + "\nACCOUNT\troot\t0\t0\t/root\t/bin/sh\nACCOUNT_SSHD\troot\teffective_config\ttrue\nEND\n")
	f.Add("not-a-protocol\n")
	f.Fuzz(func(t *testing.T, input string) {
		_, _, _ = ParseSystemPreflight([]byte(input))
	})
}

func TestNormalizeSystemAccountSelection(t *testing.T) {
	mode, accounts, limit, err := NormalizeSystemAccountSelection("", nil, 0)
	if err != nil || mode != AccountModeLocal || limit != defaultLocalAccountLimit || len(accounts) != 0 {
		t.Fatalf("default local selection mismatch: mode=%q accounts=%v limit=%d err=%v", mode, accounts, limit, err)
	}
	mode, accounts, limit, err = NormalizeSystemAccountSelection(AccountModeNSS, nil, 0)
	if err != nil || mode != AccountModeNSS || limit != defaultNSSAccountLimit {
		t.Fatalf("default NSS selection mismatch: mode=%q limit=%d err=%v", mode, limit, err)
	}
	mode, accounts, limit, err = NormalizeSystemAccountSelection(AccountModeExplicit, []string{"deploy", "root", "deploy"}, 0)
	if err != nil || mode != AccountModeExplicit || limit != 2 || strings.Join(accounts, ",") != "deploy,root" {
		t.Fatalf("explicit selection mismatch: mode=%q accounts=%v limit=%d err=%v", mode, accounts, limit, err)
	}
	for name, test := range map[string]struct {
		mode     string
		accounts []string
		limit    int
	}{
		"bad mode":             {mode: "ldap"},
		"missing explicit":     {mode: AccountModeExplicit},
		"account with local":   {mode: AccountModeLocal, accounts: []string{"root"}},
		"too many":             {mode: AccountModeNSS, limit: maxSystemAccounts + 1},
		"explicit limit small": {mode: AccountModeExplicit, accounts: []string{"root", "deploy"}, limit: 1},
		"protocol separator":   {mode: AccountModeExplicit, accounts: []string{"bad=name"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := NormalizeSystemAccountSelection(test.mode, test.accounts, test.limit); err == nil {
				t.Fatalf("invalid selection accepted: %+v", test)
			}
		})
	}
}

func TestSystemPreflightRemoteCommandQuotesExplicitAccounts(t *testing.T) {
	options := ScanOptions{
		AccountMode: AccountModeExplicit,
		Accounts:    []string{"o'connor", "user@domain"},
		MaxAccounts: 2,
	}
	got := systemPreflightRemoteCommand(options, true)
	want := `sudo -n sh -s -- preflight explicit 2 'o'"'"'connor' 'user@domain'`
	if got != want {
		t.Fatalf("remote command = %q, want %q", got, want)
	}
}

func TestAnalyzeSystemAuthenticationSources(t *testing.T) {
	snapshot := &Snapshot{Hosts: []HostSnapshot{{
		Alias: "server", Coverage: CoveragePartial,
		System: &SystemSnapshot{SSHD: SSHDConfigSnapshot{
			AuthorizedKeysCommand:       "/usr/local/bin/keys",
			AuthorizedKeysCommandUser:   "nobody",
			TrustedUserCAKeys:           "/etc/ssh/ca.pub",
			AuthorizedPrincipalsCommand: "/usr/local/bin/principals",
		}},
	}}}
	findings := Analyze(snapshot)
	want := map[string]bool{
		"partial_scan": false, "external_key_source": false,
		"trusted_ssh_ca_detected": false, "external_principals_source": false,
	}
	for _, finding := range findings {
		if _, ok := want[finding.RuleID]; ok {
			want[finding.RuleID] = true
		}
	}
	for rule, found := range want {
		if !found {
			t.Errorf("missing %s: %+v", rule, findings)
		}
	}
}
