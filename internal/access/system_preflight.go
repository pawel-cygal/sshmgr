package access

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/systeampl/sshmgr/internal/config"
	"github.com/systeampl/sshmgr/internal/sshc"
)

const (
	systemPreflightMagic          = "SSHMGR_SYSTEM_PREFLIGHT_V1"
	maxSystemPreflightOutputBytes = 16 << 20
	maxSystemPreflightLineBytes   = 64 << 10
	maxSystemAccounts             = 10_000
	defaultLocalAccountLimit      = 4_096
	defaultNSSAccountLimit        = 1_000
)

const (
	AccountModeLocal    = "local"
	AccountModeNSS      = "nss"
	AccountModeExplicit = "explicit"
)

// NormalizeSystemAccountSelection validates the requested account source and
// resolves a bounded per-host work budget. The returned account list is
// deduplicated and sorted so snapshots and remote commands are deterministic.
func NormalizeSystemAccountSelection(mode string, accounts []string, limit int) (string, []string, int, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = AccountModeLocal
	}
	if mode != AccountModeLocal && mode != AccountModeNSS && mode != AccountModeExplicit {
		return "", nil, 0, fmt.Errorf("unsupported account mode %q (use local, nss, or explicit)", mode)
	}
	seen := map[string]bool{}
	cleanAccounts := make([]string, 0, len(accounts))
	for _, account := range accounts {
		account = strings.TrimSpace(account)
		if account == "" || !validSystemAccountField(account, 256) || strings.ContainsAny(account, ",=") {
			return "", nil, 0, fmt.Errorf("invalid explicit account name %q", account)
		}
		if !seen[account] {
			seen[account] = true
			cleanAccounts = append(cleanAccounts, account)
		}
	}
	sort.Strings(cleanAccounts)
	if mode == AccountModeExplicit && len(cleanAccounts) == 0 {
		return "", nil, 0, errors.New("explicit account mode requires --account")
	}
	if mode != AccountModeExplicit && len(cleanAccounts) > 0 {
		return "", nil, 0, errors.New("--account requires --accounts explicit")
	}
	if limit < 0 || limit > maxSystemAccounts {
		return "", nil, 0, fmt.Errorf("--max-accounts must be between 1 and %d (or 0 for the mode default)", maxSystemAccounts)
	}
	if limit == 0 {
		switch mode {
		case AccountModeLocal:
			limit = defaultLocalAccountLimit
		case AccountModeNSS:
			limit = defaultNSSAccountLimit
		case AccountModeExplicit:
			limit = len(cleanAccounts)
		}
	}
	if limit < 1 {
		return "", nil, 0, errors.New("--max-accounts must be at least 1")
	}
	if mode == AccountModeExplicit && limit < len(cleanAccounts) {
		return "", nil, 0, fmt.Errorf("--max-accounts=%d is smaller than the %d explicitly requested accounts", limit, len(cleanAccounts))
	}
	return mode, cleanAccounts, limit, nil
}

// systemPreflightScript is sent through stdin to a fixed sh command. It only
// inspects capabilities, bounded account metadata, and effective sshd settings;
// it does not stat/read user authorized-key files, create files, or change
// configuration.
const systemPreflightScript = `set -u
emit() { printf '%s\t%s\t%s\n' "$1" "$2" "$3"; }
emit_account() { printf 'ACCOUNT\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5"; }
emit_account_sshd() { printf 'ACCOUNT_SSHD\t%s\t%s\t%s\n' "$1" "$2" "$3"; }
emit_account_missing() { printf 'ACCOUNT_MISSING\t%s\t%s\n' "$1" "$2"; }
printf 'SSHMGR_SYSTEM_PREFLIGHT_V1\n'
euid=$(id -u 2>/dev/null || printf 'unknown')
emit CAP euid "$euid"
if [ "$euid" = "0" ]; then emit CAP root true; else emit CAP root false; printf 'END\n'; exit 0; fi
requested_mode=${2:-local}
requested_limit=${3:-0}
shift 3
case "$requested_mode" in local|nss|explicit) ;; *) exit 64 ;; esac
case "$requested_limit" in ''|*[!0-9]*) exit 64 ;; esac
if [ "$requested_limit" -lt 1 ] || [ "$requested_limit" -gt 10000 ]; then exit 64; fi
emit CAP account_mode "$requested_mode"
emit CAP account_limit "$requested_limit"
emit CAP accounts_truncated false
emit CAP os "$(uname -s 2>/dev/null || printf 'unknown')"
case "$requested_mode" in
  local)
    if [ -r /etc/passwd ]; then account_database=etc-passwd; else account_database=unavailable; fi
    ;;
  nss)
    if command -v getent >/dev/null 2>&1 && getent passwd root >/dev/null 2>&1; then account_database=getent; else account_database=unavailable; fi
    ;;
  explicit)
    if command -v getent >/dev/null 2>&1; then
      account_database=getent-keyed
    elif [ -r /etc/passwd ]; then
      account_database=etc-passwd-keyed
    else
      account_database=unavailable
    fi
    ;;
esac
emit CAP account_database "$account_database"
sshd_path=$(command -v sshd 2>/dev/null || true)
if [ -z "$sshd_path" ] && [ -x /usr/sbin/sshd ]; then sshd_path=/usr/sbin/sshd; fi
if [ -z "$sshd_path" ]; then
  emit CAP sshd_present false
else
  emit CAP sshd_present true
  emit CAP sshd_path "$sshd_path"
  if "$sshd_path" -t >/dev/null 2>&1; then emit CAP sshd_config_valid true; else emit CAP sshd_config_valid false; fi
fi
scan_user=${SUDO_USER:-}
if [ -z "$scan_user" ]; then scan_user=$(id -un 2>/dev/null || printf root); fi
match_host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf localhost)
match_addr=127.0.0.1
emit CTX effective_user "$scan_user"
emit CTX match_host "$match_host"
emit CTX match_address "$match_addr"
if [ -n "$sshd_path" ]; then
  effective=$("$sshd_path" -T -C "user=$scan_user,host=$match_host,addr=$match_addr" 2>/dev/null)
  if [ $? -ne 0 ]; then
    emit CAP sshd_effective_config false
  else
    emit CAP sshd_effective_config true
    printf '%s\n' "$effective" | while IFS=' ' read -r key value; do
      case "$key" in
        pubkeyauthentication|strictmodes|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|trustedusercakeys|authorizedprincipalsfile|authorizedprincipalscommand)
          emit SSHD "$key" "$value"
          ;;
      esac
    done
  fi
fi
max_accounts=$requested_limit
enumerate_accounts() {
  account_count=0
  while IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell _; do
    if [ -z "$account_name" ]; then continue; fi
    account_count=$((account_count + 1))
    if [ "$account_count" -gt "$max_accounts" ]; then
      emit CAP accounts_truncated true
      break
    fi
    emit_account "$account_name" "$account_uid" "$account_gid" "$account_home" "$account_shell"
    if [ -z "$sshd_path" ]; then continue; fi
    case "$account_name" in
      *','*|*'='*) emit_account_sshd "$account_name" effective_config false; continue ;;
    esac
    account_effective=$("$sshd_path" -T -C "user=$account_name,host=$match_host,addr=$match_addr" 2>/dev/null)
    if [ $? -ne 0 ]; then
      emit_account_sshd "$account_name" effective_config false
      continue
    fi
    emit_account_sshd "$account_name" effective_config true
    printf '%s\n' "$account_effective" | while IFS=' ' read -r key value; do
      case "$key" in
        pubkeyauthentication|strictmodes|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|trustedusercakeys|authorizedprincipalsfile|authorizedprincipalscommand)
          emit_account_sshd "$account_name" "$key" "$value"
          ;;
      esac
    done
  done
}
lookup_local_account() {
  lookup_name=$1
  while IFS= read -r lookup_line; do
    case "$lookup_line" in "$lookup_name":*) printf '%s\n' "$lookup_line"; return 0 ;; esac
  done < /etc/passwd
  return 1
}
case "$requested_mode" in
  local)
    if [ "$account_database" = etc-passwd ]; then
      sed -n "1,$((max_accounts + 1))p" /etc/passwd | enumerate_accounts
      emit CAP accounts_enumerated true
    else
      emit CAP accounts_enumerated false
    fi
    ;;
  nss)
    if [ "$account_database" = getent ]; then
      getent passwd | enumerate_accounts
      emit CAP accounts_enumerated true
    else
      emit CAP accounts_enumerated false
    fi
    ;;
  explicit)
    if [ "$account_database" = unavailable ]; then
      emit CAP accounts_enumerated false
    else
      explicit_count=0
      for requested_account do
        explicit_count=$((explicit_count + 1))
        if [ "$explicit_count" -gt "$max_accounts" ]; then emit CAP accounts_truncated true; break; fi
        if [ "$account_database" = getent-keyed ]; then
          account_record=$(getent passwd "$requested_account" 2>/dev/null | sed -n '1p')
        else
          account_record=$(lookup_local_account "$requested_account" 2>/dev/null || true)
        fi
        if [ -z "$account_record" ]; then
          emit_account_missing "$requested_account" not-found
          continue
        fi
        printf '%s\n' "$account_record" | enumerate_accounts
      done
      emit CAP accounts_enumerated true
    fi
    ;;
esac
printf 'END\n'
`

// ScanSystemPreflight performs capability/source discovery only. System-wide
// account and key-content collection is a later, separately gated operation.
func ScanSystemPreflight(ctx context.Context, cfg *config.Config, aliases []string, options ScanOptions) *Snapshot {
	options.Preflight = true
	mode, accounts, limit, err := NormalizeSystemAccountSelection(options.AccountMode, options.Accounts, options.MaxAccounts)
	if err != nil {
		return scanWith(ctx, cfg, aliases, "system", options, func(_ context.Context, _ *config.Config, alias string, _ ScanOptions) HostSnapshot {
			return failedHost(alias, nil, "account-selection", err, 0)
		})
	}
	options.AccountMode = mode
	options.Accounts = accounts
	options.MaxAccounts = limit
	return scanWith(ctx, cfg, aliases, "system", options, collectSystemPreflightHost)
}

func collectSystemPreflightHost(parent context.Context, cfg *config.Config, alias string, options ScanOptions) HostSnapshot {
	return collectSystemHost(parent, cfg, alias, options, false)
}

func collectSystemKeyHost(parent context.Context, cfg *config.Config, alias string, options ScanOptions) HostSnapshot {
	return collectSystemHost(parent, cfg, alias, options, true)
}

func collectSystemHost(parent context.Context, cfg *config.Config, alias string, options ScanOptions, inspectKeySources bool) HostSnapshot {
	started := time.Now()
	resolved, ok := cfg.ResolveHost(alias)
	if !ok {
		return failedHost(alias, nil, "resolve", errors.New("alias not found"), time.Since(started))
	}
	limitations := []string{
		"effective sshd Match evaluation uses loopback as the client address during inspection",
	}
	if inspectKeySources {
		limitations = append(limitations, "system scan inspects static AuthorizedKeysFile sources only; dynamic commands and SSH certificates require separate review")
	} else {
		limitations = append(limitations, "system preflight enumerates bounded account metadata and expands effective sources but does not stat or read authorized-key files")
	}
	host := HostSnapshot{
		Alias:       alias,
		Groups:      append([]string(nil), resolved.Groups...),
		Tags:        append([]string(nil), resolved.Tags...),
		Coverage:    CoveragePartial,
		Limitations: limitations,
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var run boundedRemoteInputRunner
	if resolved.External {
		run = func(command, input string, limit int64) ([]byte, error) {
			return runBoundedExternalInput(ctx, resolved, command, input, limit)
		}
	} else {
		if unsafeAlias := proxyCommandInChain(cfg, alias, map[string]bool{}); unsafeAlias != "" {
			return failedHost(alias, &host, "backend", fmt.Errorf("batch system preflight does not support proxy_command in connection chain at %s", unsafeAlias), time.Since(started))
		}
		scanConfig := batchConfig(cfg, timeout)
		client, err := sshc.ConnectAlias(scanConfig, alias)
		if err != nil {
			return failedHost(alias, &host, "connect", err, time.Since(started))
		}
		var closeOnce sync.Once
		closeClient := func() { closeOnce.Do(func() { sshc.CloseChain(client) }) }
		defer closeClient()
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				closeClient()
			case <-done:
			}
		}()
		run = func(command, input string, limit int64) ([]byte, error) {
			return runBoundedSSHInput(client, command, input, limit)
		}
	}

	command := systemPreflightRemoteCommand(options, false)
	privilegeMode := "direct-root"
	if options.UseSudo {
		command = systemPreflightRemoteCommand(options, true)
		privilegeMode = "sudo-n"
	}
	data, err := run(command, systemPreflightScript, maxSystemPreflightOutputBytes)
	if err != nil {
		if timeoutErr := ctx.Err(); timeoutErr != nil {
			return failedHost(alias, &host, "timeout", timeoutErr, time.Since(started))
		}
		message := "system preflight command failed"
		stage := "system-preflight"
		if options.UseSudo {
			message = "sudo -n system preflight was denied or unavailable"
			stage = "sudo-n"
		}
		return failedHost(alias, &host, stage, errors.New(message), time.Since(started))
	}
	system, accounts, err := ParseSystemPreflight(data)
	if err != nil {
		return failedHost(alias, &host, "system-protocol", err, time.Since(started))
	}
	system.PrivilegeMode = privilegeMode
	system.SudoNonInteractive = options.UseSudo && system.Root
	host.System = system
	host.Accounts = accounts
	if !system.Root {
		return failedHost(alias, &host, "privilege", errors.New("system preflight requires root or --sudo with non-interactive sudo access"), time.Since(started))
	}
	if system.AccountDatabase == "unavailable" {
		host.Limitations = append(host.Limitations, "system account database is unavailable")
	}
	switch system.AccountMode {
	case AccountModeLocal:
		host.Limitations = append(host.Limitations, "local account mode excludes directory-only NSS/SSSD/LDAP accounts")
	case AccountModeNSS:
		host.Limitations = append(host.Limitations, "NSS account completeness depends on whether the configured identity provider permits enumeration")
	}
	if !system.AccountsEnumerated {
		host.Limitations = append(host.Limitations, "system accounts could not be enumerated")
	}
	if system.AccountsTruncated {
		host.Limitations = append(host.Limitations, fmt.Sprintf("system account enumeration reached the safety limit of %d accounts", system.AccountLimit))
	}
	if len(system.MissingAccounts) > 0 {
		host.Limitations = append(host.Limitations, "explicit accounts were not found: "+strings.Join(system.MissingAccounts, ", "))
	}
	if !system.SSHD.Present {
		host.Limitations = append(host.Limitations, "OpenSSH sshd was not found")
	} else {
		if !system.SSHD.ConfigValid {
			host.Limitations = append(host.Limitations, "sshd configuration validation failed")
		}
		if !system.SSHD.EffectiveConfig {
			host.Limitations = append(host.Limitations, "effective sshd configuration could not be evaluated")
		}
	}
	if inspectKeySources {
		stats, sourcesRequested, sourcesTruncated, collectErr := collectSystemKeySourcesWith(host.Accounts, options, run)
		system.SourcesRequested = sourcesRequested
		system.SourcesInspected = stats.SourcesInspected
		system.SourceBytesRead = stats.BytesRead
		system.SourcesTruncated = sourcesTruncated
		system.ContentBudgetHit = stats.ContentBudgetHit
		if collectErr != nil {
			return failedHost(alias, &host, "system-collection", collectErr, time.Since(started))
		}
		if sourcesRequested == 0 {
			host.Limitations = append(host.Limitations, "no static authorized-key sources were available for inspection")
		}
		if sourcesTruncated {
			host.Limitations = append(host.Limitations, fmt.Sprintf("static key source enumeration reached the safety limit of %d sources", maxSystemKeySources))
		}
		if stats.ContentBudgetHit {
			host.Limitations = append(host.Limitations, fmt.Sprintf("authorized-key content reached the per-host read budget of %d bytes", options.MaxTotalBytes))
		}
		sourceFailures := 0
		for accountIndex := range host.Accounts {
			for sourceIndex := range host.Accounts[accountIndex].Sources {
				if host.Accounts[accountIndex].Sources[sourceIndex].Error != "" {
					sourceFailures++
				}
			}
		}
		if sourceFailures > 0 {
			host.Limitations = append(host.Limitations, fmt.Sprintf("%d static key source(s) could not be fully inspected", sourceFailures))
		}
	}
	if err := ctx.Err(); err != nil {
		host.Errors = append(host.Errors, ScanError{Stage: "timeout", Message: err.Error()})
		host.Limitations = append(host.Limitations, "system preflight timeout interrupted remote inspection")
	}
	if inspectKeySources && systemCoverageComplete(system, host.Accounts) && len(host.Errors) == 0 {
		host.Coverage = CoverageFull
	}
	host.DurationMS = time.Since(started).Milliseconds()
	return host
}

// systemCoverageComplete promotes only a byte-exact, bounded static-key scan.
// Dynamic key/principal providers and SSH CAs deliberately retain partial
// coverage because this scanner neither invokes nor provisions those sources.
func systemCoverageComplete(system *SystemSnapshot, accounts []AccountSnapshot) bool {
	if system == nil || !system.Root || system.AccountDatabase == "unavailable" ||
		!system.AccountsEnumerated || system.AccountsTruncated || len(system.MissingAccounts) > 0 ||
		!system.SSHD.Present || !system.SSHD.ConfigValid || !system.SSHD.EffectiveConfig ||
		system.SourcesTruncated || system.ContentBudgetHit {
		return false
	}
	if dynamicSSHAccessConfigured(system.SSHD.AuthorizedKeysCommand, system.SSHD.TrustedUserCAKeys,
		system.SSHD.AuthorizedPrincipalsFile, system.SSHD.AuthorizedPrincipalsCommand) {
		return false
	}
	sources := 0
	inspected := 0
	for _, account := range accounts {
		if account.Auth == nil || !account.Auth.EffectiveConfig ||
			!strings.EqualFold(strings.TrimSpace(account.Auth.PubkeyAuthentication), "yes") ||
			len(account.Limitations) > 0 ||
			dynamicSSHAccessConfigured(account.Auth.AuthorizedKeysCommand, account.Auth.TrustedUserCAKeys,
				account.Auth.AuthorizedPrincipalsFile, account.Auth.AuthorizedPrincipalsCommand) {
			return false
		}
		for _, source := range account.Sources {
			if source.Type != "authorized_keys_file" || source.Error != "" || source.Symlink || source.AncestorSymlink {
				return false
			}
			sources++
			if source.Exists {
				if !source.ContentInspected || source.ContentSHA256 == "" {
					return false
				}
				inspected++
			}
		}
	}
	return len(accounts) > 0 && system.SourcesRequested == sources && system.SourcesInspected == inspected
}

func dynamicSSHAccessConfigured(values ...string) bool {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "none") {
			return true
		}
	}
	return false
}

func systemPreflightRemoteCommand(options ScanOptions, useSudo bool) string {
	command := "sh -s -- preflight " + options.AccountMode + " " + strconv.Itoa(options.MaxAccounts)
	if useSudo {
		command = "sudo -n " + command
	}
	for _, account := range options.Accounts {
		command += " " + quoteShellArgument(account)
	}
	return command
}

func quoteShellArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// ParseSystemPreflight parses the bounded line protocol produced by the fixed
// preflight script. Unknown records/keys are ignored for forward compatibility.
func ParseSystemPreflight(data []byte) (*SystemSnapshot, []AccountSnapshot, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxSystemPreflightLineBytes)
	if !scanner.Scan() || scanner.Text() != systemPreflightMagic {
		return nil, nil, errors.New("invalid system preflight protocol header")
	}
	system := &SystemSnapshot{}
	var accounts []AccountSnapshot
	accountIndexes := map[string]int{}
	ended := false
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "END" {
			ended = true
			break
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			return nil, nil, fmt.Errorf("invalid system preflight record")
		}
		record, key := fields[0], fields[1]
		switch record {
		case "CAP":
			if len(fields) != 3 {
				return nil, nil, errors.New("invalid system capability record")
			}
			value := fields[2]
			switch key {
			case "euid":
				if value != "0" && value != "unknown" {
					if _, err := strconv.Atoi(value); err != nil {
						return nil, nil, errors.New("invalid system preflight euid")
					}
				}
			case "root":
				system.Root = value == "true"
			case "os":
				system.OS = value
			case "account_database":
				system.AccountDatabase = value
			case "account_mode":
				if value != AccountModeLocal && value != AccountModeNSS && value != AccountModeExplicit {
					return nil, nil, errors.New("invalid system account mode")
				}
				system.AccountMode = value
			case "accounts_enumerated":
				system.AccountsEnumerated = value == "true"
			case "accounts_truncated":
				system.AccountsTruncated = value == "true"
			case "account_limit":
				limit, err := strconv.Atoi(value)
				if err != nil || limit < 1 || limit > maxSystemAccounts {
					return nil, nil, errors.New("invalid system account limit")
				}
				system.AccountLimit = limit
			case "sshd_present":
				system.SSHD.Present = value == "true"
			case "sshd_path":
				system.SSHD.Path = value
			case "sshd_config_valid":
				system.SSHD.ConfigValid = value == "true"
			case "sshd_effective_config":
				system.SSHD.EffectiveConfig = value == "true"
			}
		case "CTX":
			if len(fields) != 3 {
				return nil, nil, errors.New("invalid system context record")
			}
			value := fields[2]
			switch key {
			case "effective_user":
				system.SSHD.EffectiveUser = value
			case "match_host":
				system.SSHD.MatchHost = value
			case "match_address":
				system.SSHD.MatchAddress = value
			}
		case "SSHD":
			if len(fields) != 3 {
				return nil, nil, errors.New("invalid system sshd record")
			}
			value := fields[2]
			switch key {
			case "pubkeyauthentication":
				system.SSHD.PubkeyAuthentication = value
			case "strictmodes":
				system.SSHD.StrictModes = value
			case "authorizedkeysfile":
				system.SSHD.AuthorizedKeysFiles = strings.Fields(value)
			case "authorizedkeyscommand":
				system.SSHD.AuthorizedKeysCommand = value
			case "authorizedkeyscommanduser":
				system.SSHD.AuthorizedKeysCommandUser = value
			case "trustedusercakeys":
				system.SSHD.TrustedUserCAKeys = value
			case "authorizedprincipalsfile":
				system.SSHD.AuthorizedPrincipalsFile = value
			case "authorizedprincipalscommand":
				system.SSHD.AuthorizedPrincipalsCommand = value
			}
		case "ACCOUNT":
			if len(fields) != 6 {
				return nil, nil, errors.New("invalid system account record")
			}
			if len(accounts) >= maxSystemAccounts {
				return nil, nil, errors.New("system account record limit exceeded")
			}
			username := fields[1]
			if username == "" || !validSystemAccountField(username, 256) {
				return nil, nil, errors.New("invalid system account username")
			}
			if _, duplicate := accountIndexes[username]; duplicate {
				return nil, nil, errors.New("duplicate system account record")
			}
			uid, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				return nil, nil, errors.New("invalid system account uid")
			}
			gid, err := strconv.ParseUint(fields[3], 10, 64)
			if err != nil {
				return nil, nil, errors.New("invalid system account gid")
			}
			if !validSystemAccountField(fields[4], 16<<10) || !validSystemAccountField(fields[5], 16<<10) {
				return nil, nil, errors.New("invalid system account path field")
			}
			accountIndexes[username] = len(accounts)
			accounts = append(accounts, AccountSnapshot{
				Username: username, UID: &uid, GID: &gid, Home: fields[4], Shell: fields[5],
			})
		case "ACCOUNT_SSHD":
			if len(fields) != 4 {
				return nil, nil, errors.New("invalid per-account sshd record")
			}
			index, ok := accountIndexes[fields[1]]
			if !ok {
				return nil, nil, errors.New("per-account sshd record precedes account")
			}
			account := &accounts[index]
			if account.Auth == nil {
				account.Auth = &AccountAuthSnapshot{}
			}
			applyAccountSSHDValue(account.Auth, fields[2], fields[3])
		case "ACCOUNT_MISSING":
			if len(fields) != 3 || fields[1] == "" || !validSystemAccountField(fields[1], 256) {
				return nil, nil, errors.New("invalid missing-account record")
			}
			system.MissingAccounts = append(system.MissingAccounts, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("system preflight record exceeds %d bytes: %w", maxSystemPreflightLineBytes, err)
	}
	if !ended {
		return nil, nil, errors.New("system preflight protocol is incomplete")
	}
	for index := range accounts {
		populateAccountSources(&accounts[index])
	}
	sort.Strings(system.MissingAccounts)
	return system, accounts, nil
}

func applyAccountSSHDValue(auth *AccountAuthSnapshot, key, value string) {
	switch key {
	case "effective_config":
		auth.EffectiveConfig = value == "true"
	case "pubkeyauthentication":
		auth.PubkeyAuthentication = value
	case "strictmodes":
		auth.StrictModes = value
	case "authorizedkeysfile":
		auth.AuthorizedKeysFiles = strings.Fields(value)
	case "authorizedkeyscommand":
		auth.AuthorizedKeysCommand = value
	case "authorizedkeyscommanduser":
		auth.AuthorizedKeysCommandUser = value
	case "trustedusercakeys":
		auth.TrustedUserCAKeys = value
	case "authorizedprincipalsfile":
		auth.AuthorizedPrincipalsFile = value
	case "authorizedprincipalscommand":
		auth.AuthorizedPrincipalsCommand = value
	}
}

func populateAccountSources(account *AccountSnapshot) {
	if account.Auth == nil || !account.Auth.EffectiveConfig {
		account.Limitations = append(account.Limitations, "effective sshd configuration unavailable for account")
		return
	}
	if strings.EqualFold(strings.TrimSpace(account.Auth.PubkeyAuthentication), "no") {
		account.Limitations = append(account.Limitations, "public-key authentication is disabled for this effective account context")
	}
	seen := map[string]bool{}
	for _, configuredPath := range account.Auth.AuthorizedKeysFiles {
		if strings.EqualFold(strings.TrimSpace(configuredPath), "none") {
			continue
		}
		expanded, err := expandAuthorizedKeysPath(configuredPath, *account)
		if err != nil {
			account.Limitations = append(account.Limitations, fmt.Sprintf("cannot expand AuthorizedKeysFile %q: %v", configuredPath, err))
			continue
		}
		if seen[expanded] {
			continue
		}
		seen[expanded] = true
		account.Sources = append(account.Sources, KeySource{
			Type: "authorized_keys_file", Path: expanded, ConfiguredPath: configuredPath,
		})
	}
}

func expandAuthorizedKeysPath(template string, account AccountSnapshot) (string, error) {
	var expanded strings.Builder
	for index := 0; index < len(template); index++ {
		if template[index] != '%' {
			expanded.WriteByte(template[index])
			continue
		}
		index++
		if index >= len(template) {
			return "", errors.New("dangling percent token")
		}
		switch template[index] {
		case '%':
			expanded.WriteByte('%')
		case 'h':
			if !path.IsAbs(account.Home) {
				return "", errors.New("%h requires an absolute account home")
			}
			expanded.WriteString(account.Home)
		case 'u':
			expanded.WriteString(account.Username)
		case 'U':
			if account.UID == nil {
				return "", errors.New("%U requires a known account uid")
			}
			expanded.WriteString(strconv.FormatUint(*account.UID, 10))
		default:
			return "", fmt.Errorf("unsupported token %%%c", template[index])
		}
	}
	value := expanded.String()
	if value == "" {
		return "", errors.New("empty path")
	}
	if !path.IsAbs(value) {
		if !path.IsAbs(account.Home) {
			return "", errors.New("relative path requires an absolute account home")
		}
		value = path.Join(account.Home, value)
	}
	return path.Clean(value), nil
}

func validSystemAccountField(value string, maxLength int) bool {
	if len(value) > maxLength || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}
