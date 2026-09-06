#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
sshmgr_bin=${SSHMGR_CLOUD_BIN:-"$repo_dir/sshmgr-cloud"}
test_dir=$(mktemp -d)
container="sshmgr-access-$RANDOM-$$"
image="sshmgr-access-integration:local"

cleanup() {
	if [[ "$container" == sshmgr-access-* ]]; then
		docker rm -f "$container" >/dev/null 2>&1 || true
	else
		echo "refusing to remove unexpected container: $container" >&2
	fi
	case "$test_dir" in
		/tmp/tmp.*) rm -rf -- "$test_dir" ;;
		*) echo "refusing to remove unexpected test dir: $test_dir" >&2 ;;
	esac
}
trap cleanup EXIT

if [[ ! -x "$sshmgr_bin" ]]; then
	echo "sshmgr Cloud binary is missing or not executable: $sshmgr_bin" >&2
	exit 1
fi

mkdir -p "$test_dir/remote-ssh" "$test_dir/system-keys" "$test_dir/state"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/access_key"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/extra_key"
primary_key=$(awk '{print $1 " " $2}' "$test_dir/access_key.pub")
extra_key=$(awk '{print $1 " " $2}' "$test_dir/extra_key.pub")
printf '%s %s\n%s %s\n' \
	"$primary_key" "alice@laptop" \
	"$primary_key" "contractor@old-device" \
	>"$test_dir/remote-ssh/authorized_keys"
chmod 700 "$test_dir/remote-ssh"
chmod 600 "$test_dir/remote-ssh/authorized_keys"
printf '%s %s\n' "$extra_key" "service@system-source" >"$test_dir/system-keys/audit-1000"
printf '%s %s\n' "$primary_key" "device@test-fixture" >"$test_dir/system-keys/device-1001"
chmod 664 "$test_dir/system-keys/audit-1000"
chmod 644 "$test_dir/system-keys/device-1001"

docker build -t "$image" "$repo_dir/integration/access" >/dev/null
docker run -d --name "$container" \
	-p 127.0.0.1::22 \
	-v "$test_dir/remote-ssh:/home/audit/.ssh" \
	-v "$test_dir/system-keys:/etc/ssh/keys:ro" \
	"$image" >/dev/null

port=""
ready=0
for _ in $(seq 1 50); do
	mapping=$(docker port "$container" 22/tcp 2>/dev/null || true)
	port=${mapping##*:}
	if [[ -n "$port" ]] && ssh -F /dev/null -i "$test_dir/access_key" -p "$port" \
		-o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile="$test_dir/openssh-known-hosts" \
		audit@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 0.1
done
if [[ "$ready" != 1 ]]; then
	echo "isolated sshd did not become ready" >&2
	docker logs "$container" >&2 || true
	exit 1
fi

proxy_count="$test_dir/proxy-count"
proxy_command="$test_dir/proxy-command"
printf '#!/bin/sh\nprintf "x\\n" >> "%s"\nexec nc 127.0.0.1 "%s"\n' \
	"$proxy_count" "$port" >"$proxy_command"
chmod 700 "$proxy_command"
: >"$proxy_count"

printf '%s\n' \
	"hosts:" \
	"  smoke:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: audit" \
	"    key: $test_dir/access_key" \
	"    groups: [access-e2e]" \
	"  external-smoke:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: audit" \
	"    key: $test_dir/access_key" \
	"    external: true" \
	"    proxy_command: $proxy_command" \
	"    ssh_options:" \
	"      - UserKnownHostsFile=$test_dir/known_hosts" \
	"      - GlobalKnownHostsFile=/dev/null" \
	"      - StrictHostKeyChecking=accept-new" \
	"      - RequestTTY=force" \
	"      - StdinNull=yes" \
	"    groups: [access-external-e2e]" \
	"  external-unknown:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: audit" \
	"    key: $test_dir/access_key" \
	"    external: true" \
	"    proxy_command: $proxy_command" \
	"    ssh_options:" \
	"      - UserKnownHostsFile=$test_dir/external-unknown-known-hosts" \
	"      - GlobalKnownHostsFile=/dev/null" \
	"      - StrictHostKeyChecking=accept-new" \
	"    groups: [access-external-unknown-e2e]" \
	"  protected:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: audit" \
	"    key: $test_dir/access_key" \
	"    groups: [access-e2e]" \
	"  device-sim:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: device" \
	"    key: $test_dir/access_key" \
	"    groups: [device-e2e]" \
	>"$test_dir/config.yaml"

ssh-keyscan -p "$port" 127.0.0.1 >"$test_dir/known_hosts" 2>/dev/null
chmod 600 "$test_dir/known_hosts"
export SSHMGR_CONFIG="$test_dir/config.yaml"
export SSHMGR_STATE="$test_dir/state/state.yaml"
export SSHMGR_KNOWN_HOSTS="$test_dir/known_hosts"
export XDG_STATE_HOME="$test_dir/state"

dry_run=$("$sshmgr_bin" access scan --group access-e2e --exclude-host protected --dry-run 2>&1)
grep -Fq '1 selected, 1 excluded' <<<"$dry_run"
grep -Fq 'host: protected' <<<"$dry_run"
grep -Fq '  smoke' <<<"$dry_run"

multi_group_dry_run=$("$sshmgr_bin" access scan \
	--group access-external-e2e --group access-e2e --group access-e2e \
	--exclude-host protected --dry-run 2>&1)
grep -Fq '2 selected, 1 excluded' <<<"$multi_group_dry_run"
grep -Fq '  external-smoke' <<<"$multi_group_dry_run"
grep -Fq '  smoke' <<<"$multi_group_dry_run"
if "$sshmgr_bin" access scan --group access-e2e --group misspelled-group --dry-run >/dev/null 2>&1; then
	echo "repeated group selector ignored an unknown group" >&2
	exit 1
fi
"$sshmgr_bin" access scan --group access-external-e2e --group access-e2e \
	--exclude-host protected -p 2 --timeout 10s --out "$test_dir/multi-group.json" >/dev/null
jq -e '.scope.selector == "groups:access-e2e,access-external-e2e" and .summary.hosts_requested == 2 and .summary.hosts_failed == 0 and .summary.authorized_key_entries == 4 and .summary.unique_fingerprints == 1' \
	"$test_dir/multi-group.json" >/dev/null

# Authentication to a non-Unix SSH CLI succeeds, but neither SFTP nor the
# fixed read-only Unix collector protocol is available. Keep failed coverage
# and emit a distinct high-severity classification instead of scan_failed.
device_status=0
"$sshmgr_bin" access scan --host device-sim -p 1 --timeout 10s \
	--out "$test_dir/device.json" >/dev/null 2>"$test_dir/device.stderr" || device_status=$?
[[ "$device_status" -eq 1 ]]
[[ $(stat -c '%a' "$test_dir/device.json") == 600 ]]
jq -e '.summary.hosts_requested == 1 and .summary.hosts_failed == 1 and .summary.findings_high == 1' \
	"$test_dir/device.json" >/dev/null
if ! jq -e '.hosts[0].coverage == "failed" and ([.hosts[0].errors[].stage] as $stages | ($stages | index("sftp")) != null and ($stages | index("collector-unsupported")) != null)' \
	"$test_dir/device.json" >/dev/null; then
	jq '{summary, host: .hosts[0], findings}' "$test_dir/device.json" >&2
	exit 1
fi
jq -e '[.findings[].rule_id] == ["unsupported_ssh_target"]' "$test_dir/device.json" >/dev/null
"$sshmgr_bin" access report "$test_dir/device.json" | grep -Fq 'unsupported_ssh_target'

before_hash=$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')
"$sshmgr_bin" access scan --group access-e2e --exclude-host protected \
	--preflight -p 1 --timeout 10s --out "$test_dir/preflight.json" >/dev/null
after_preflight_hash=$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')
[[ "$before_hash" == "$after_preflight_hash" ]]
[[ $(stat -c '%a' "$test_dir/preflight.json") == 600 ]]
jq -e '.scope.preflight == true' "$test_dir/preflight.json" >/dev/null
jq -e '.scope.host_exclusions == ["protected"]' "$test_dir/preflight.json" >/dev/null
jq -e '.scope.excluded_matched_hosts == ["protected"]' "$test_dir/preflight.json" >/dev/null
jq -e '.summary.hosts_partial == 1 and .summary.hosts_failed == 0' "$test_dir/preflight.json" >/dev/null
jq -e '[.hosts[].accounts[].sources[] | select(.exists) | .content_inspected] == [false]' "$test_dir/preflight.json" >/dev/null

# The external backend must feed the same fixed collector protocol over stdin,
# override interactive/accept-new options, and still honor OpenSSH-only
# transport such as ProxyCommand.
: >"$proxy_count"
"$sshmgr_bin" access scan --host external-smoke --exclude-host protected \
	--preflight -p 1 --timeout 10s --out "$test_dir/external-preflight.json" >/dev/null
[[ $(wc -l <"$proxy_count") -eq 1 ]]
jq -e '.summary.hosts_partial == 1 and .summary.hosts_failed == 0' "$test_dir/external-preflight.json" >/dev/null
jq -e '[.hosts[0].accounts[0].sources[] | select(.exists) | .content_inspected] == [false]' "$test_dir/external-preflight.json" >/dev/null

: >"$proxy_count"
"$sshmgr_bin" access scan --host external-smoke --exclude-host protected \
	-p 1 --timeout 10s --out "$test_dir/external-current.json" >/dev/null
[[ $(wc -l <"$proxy_count") -eq 1 ]]
jq -e '.summary.authorized_key_entries == 2 and .summary.unique_fingerprints == 1 and .summary.hosts_failed == 0' "$test_dir/external-current.json" >/dev/null
if grep -Fq '"public_key"' "$test_dir/external-current.json"; then
	echo "external fingerprint-only snapshot contains raw public_key" >&2
	exit 1
fi

"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	--sudo --preflight -p 1 --timeout 10s --out "$test_dir/system-preflight.json" >/dev/null
[[ $(stat -c '%a' "$test_dir/system-preflight.json") == 600 ]]
jq -e '.scope.mode == "system" and .scope.preflight == true' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].system.privilege_mode == "sudo-n" and .hosts[0].system.root == true and .hosts[0].system.sudo_non_interactive == true' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].system.sshd.present == true and .hosts[0].system.sshd.config_valid == true and .hosts[0].system.sshd.effective_config == true' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].system.sshd.effective_user == "audit"' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].system.sshd.authorized_keys_files | index(".ssh/authorized_keys") != null' "$test_dir/system-preflight.json" >/dev/null
jq -e '.scope.account_mode == "local" and .scope.max_accounts == 4096' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].system.account_mode == "local" and .hosts[0].system.account_database == "etc-passwd"' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].system.accounts_enumerated == true and .hosts[0].system.accounts_truncated == false and .hosts[0].system.account_limit == 4096' "$test_dir/system-preflight.json" >/dev/null
jq -e '[.hosts[0].accounts[].username] | index("root") != null and index("audit") != null' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].accounts[] | select(.username == "root") | .uid == 0 and .gid == 0 and .home == "/root"' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].accounts[] | select(.username == "audit") | .uid == 1000 and .gid == 1000 and .home == "/home/audit" and .auth.effective_config == true' "$test_dir/system-preflight.json" >/dev/null
jq -e '.hosts[0].accounts[] | select(.username == "audit") | [.sources[].path] | index("/home/audit/.ssh/authorized_keys") != null and index("/etc/ssh/keys/audit-1000") != null' "$test_dir/system-preflight.json" >/dev/null
jq -e '[.hosts[0].accounts[].sources[] | .exists, .content_inspected] | all(. == false)' "$test_dir/system-preflight.json" >/dev/null
jq -e '.summary.authorized_key_entries == 0 and .summary.accounts_observed > 1 and .summary.key_sources_found == 0' "$test_dir/system-preflight.json" >/dev/null
if grep -Fq '"public_key"' "$test_dir/system-preflight.json"; then
	echo "system preflight contains key material" >&2
	exit 1
fi

before_system_key_hash=$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')
"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	--sudo --accounts explicit --account audit --max-source-mib 1 --max-total-mib 2 \
	-p 1 --timeout 10s --out "$test_dir/system-scan.json" >/dev/null
after_system_key_hash=$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')
[[ "$before_system_key_hash" == "$after_system_key_hash" ]]
[[ "$before_hash" == "$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')" ]]
[[ $(stat -c '%a' "$test_dir/system-scan.json") == 600 ]]
jq -e '.scope.mode == "system" and (.scope.preflight // false) == false and .scope.account_mode == "explicit"' "$test_dir/system-scan.json" >/dev/null
jq -e '.scope.max_source_bytes == 1048576 and .scope.max_total_source_bytes == 2097152' "$test_dir/system-scan.json" >/dev/null
jq -e '.hosts[0].system.sources_requested == 2 and .hosts[0].system.sources_inspected == 2 and .hosts[0].system.source_bytes_read > 0' "$test_dir/system-scan.json" >/dev/null
jq -e '.summary.accounts_observed == 1 and .summary.key_sources_found == 2 and .summary.authorized_key_entries == 3 and .summary.unique_fingerprints == 2 and .summary.key_bytes_inspected > 0' "$test_dir/system-scan.json" >/dev/null
jq -e '.hosts[0].accounts[0].sources[] | select(.path == "/home/audit/.ssh/authorized_keys") | .content_inspected == true and .mode == "0600" and .owner_uid == 1000 and .parent_mode == "0700"' "$test_dir/system-scan.json" >/dev/null
jq -e '.hosts[0].accounts[0].sources[] | select(.path == "/etc/ssh/keys/audit-1000") | .content_inspected == true and .mode == "0664"' "$test_dir/system-scan.json" >/dev/null
jq -e '[.findings[].rule_id] | index("unsafe_key_file_permissions") != null' "$test_dir/system-scan.json" >/dev/null
if grep -Fq '"public_key"' "$test_dir/system-scan.json"; then
	echo "fingerprint-only system snapshot contains raw public_key" >&2
	exit 1
fi

# The findings policy gate is opt-in and inclusive. It must write the complete
# private artifact before returning status 2, retain command errors as status
# 1, and never turn target-only dry-run into a scan.
"$sshmgr_bin" access report "$test_dir/system-scan.json" --fail-on critical >/dev/null
report_gate_status=0
"$sshmgr_bin" access report "$test_dir/system-scan.json" \
	--html "$test_dir/gated-report.html" --csv "$test_dir/gated-report.csv" \
	--fail-on high >/dev/null 2>"$test_dir/gated-report.stderr" || report_gate_status=$?
[[ "$report_gate_status" -eq 2 ]]
grep -Fq -- '--fail-on high matched 2 finding(s)' "$test_dir/gated-report.stderr"
[[ $(stat -c '%a' "$test_dir/gated-report.html") == 600 ]]
[[ $(stat -c '%a' "$test_dir/gated-report.csv") == 600 ]]
invalid_gate_status=0
"$sshmgr_bin" access report "$test_dir/system-scan.json" --fail-on warning \
	>/dev/null 2>&1 || invalid_gate_status=$?
[[ "$invalid_gate_status" -eq 1 ]]
dry_run_gate_status=0
"$sshmgr_bin" access scan --host smoke --dry-run --fail-on high \
	>/dev/null 2>&1 || dry_run_gate_status=$?
[[ "$dry_run_gate_status" -eq 1 ]]
scan_gate_status=0
"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	--sudo --accounts explicit --account audit --max-source-mib 1 --max-total-mib 2 \
	-p 1 --timeout 10s --out "$test_dir/system-scan-gated.json" --fail-on high \
	>/dev/null 2>"$test_dir/system-scan-gated.stderr" || scan_gate_status=$?
[[ "$scan_gate_status" -eq 2 ]]
grep -Fq -- '--fail-on high matched 2 finding(s)' "$test_dir/system-scan-gated.stderr"
[[ $(stat -c '%a' "$test_dir/system-scan-gated.json") == 600 ]]
[[ "$before_system_key_hash" == "$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')" ]]
[[ "$before_hash" == "$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')" ]]

# Identity ownership is an explicit local input. Template generation must not
# promote comments into claims, while review must distinguish unknown, shared,
# possession-verified, and offboarded access without touching the server.
"$sshmgr_bin" access identity-map "$test_dir/system-scan.json" \
	--out "$test_dir/identities-template.yaml" >/dev/null
[[ $(stat -c '%a' "$test_dir/identities-template.yaml") == 600 ]]
[[ $(grep -Ec '^[[:space:]]+claims: \[\]$' "$test_dir/identities-template.yaml") -eq 2 ]]
grep -Fq '# For a key, replace its claims: [] with:' "$test_dir/identities-template.yaml"
primary_fingerprint=$(jq -r '[.hosts[].accounts[].sources[].entries[] | select(.comment == "alice@laptop")][0].fingerprint' "$test_dir/system-scan.json")
system_fingerprint=$(jq -r '[.hosts[].accounts[].sources[].entries[] | select(.comment == "service@system-source")][0].fingerprint' "$test_dir/system-scan.json")
[[ "$primary_fingerprint" == SHA256:* && "$system_fingerprint" == SHA256:* && "$primary_fingerprint" != "$system_fingerprint" ]]
cat >"$test_dir/identities.yaml" <<EOF
schema_version: "1"
identities:
  - id: "=active@example.com"
    display_name: "<Active Operator>"
    kind: human
    status: active
  - id: former@example.com
    display_name: Former Operator
    kind: human
    status: offboarded
keys:
  - fingerprint: "$primary_fingerprint"
    claims:
      - identity: former@example.com
        status: claimed_by_identity
        source: manual-e2e
      - identity: "=active@example.com"
        status: possession_verified
        source: manual-e2e
        verified_at: "2026-08-12T00:00:00Z"
  - fingerprint: "$system_fingerprint"
    claims: []
EOF
chmod 600 "$test_dir/identities.yaml"
"$sshmgr_bin" access review "$test_dir/system-scan.json" --identities "$test_dir/identities.yaml" \
	--json "$test_dir/ownership-review.json" --html "$test_dir/ownership-review.html" \
	--csv "$test_dir/ownership-review.csv" >/dev/null
"$sshmgr_bin" access review "$test_dir/system-scan.json" --identities "$test_dir/identities.yaml" \
	--json "$test_dir/ownership-review-repeat.json" >/dev/null
cmp "$test_dir/ownership-review.json" "$test_dir/ownership-review-repeat.json"
for review_output in "$test_dir/ownership-review.json" "$test_dir/ownership-review.html" "$test_dir/ownership-review.csv"; do
	[[ $(stat -c '%a' "$review_output") == 600 ]]
done
jq -e '.summary.observed_keys == 2 and .summary.owned_keys == 1 and .summary.unknown_keys == 1 and .summary.shared_keys == 1' "$test_dir/ownership-review.json" >/dev/null
jq -e '.summary.offboarded_access_keys == 1 and .summary.possession_verified_keys == 1 and .summary.findings_high == 1 and .summary.findings_medium == 2' "$test_dir/ownership-review.json" >/dev/null
jq -e '[.findings[].rule_id] | index("unknown_key") != null and index("shared_key") != null and index("offboarded_identity_access") != null' "$test_dir/ownership-review.json" >/dev/null
"$sshmgr_bin" access review "$test_dir/system-scan.json" --identities "$test_dir/identities.yaml" \
	--fail-on critical >/dev/null
review_gate_status=0
"$sshmgr_bin" access review "$test_dir/system-scan.json" --identities "$test_dir/identities.yaml" \
	--json "$test_dir/ownership-review-gated.json" --fail-on medium \
	>/dev/null 2>"$test_dir/ownership-review-gated.stderr" || review_gate_status=$?
[[ "$review_gate_status" -eq 2 ]]
grep -Fq -- '--fail-on medium matched 3 finding(s)' "$test_dir/ownership-review-gated.stderr"
cmp "$test_dir/ownership-review.json" "$test_dir/ownership-review-gated.json"
grep -Fq "'=active@example.com" "$test_dir/ownership-review.csv"
grep -Fq '&lt;Active Operator&gt;' "$test_dir/ownership-review.html"
if grep -Eq 'https?://|<script[^>]+src=' "$test_dir/ownership-review.html"; then
	echo "ownership HTML unexpectedly depends on a remote asset" >&2
	exit 1
fi
if grep -Fq '"public_key"' "$test_dir/ownership-review.json"; then
	echo "ownership review contains raw public_key" >&2
	exit 1
fi

# Offboarding is a strict, deterministic evidence export over an exact
# snapshot/review pair. It must stay explicitly non-executable, preserve
# shared-key ambiguity, protect its inputs, and make no remote change.
offboarding_remote_hash=$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')
offboarding_system_hash=$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')
offboarding_text=$("$sshmgr_bin" access offboarding former@example.com \
	--scan "$test_dir/system-scan.json" --review "$test_dir/ownership-review.json" \
	--json "$test_dir/offboarding.json" --html "$test_dir/offboarding.html" \
	--csv "$test_dir/offboarding.csv")
"$sshmgr_bin" access offboarding former@example.com \
	--scan "$test_dir/system-scan.json" --review "$test_dir/ownership-review.json" \
	--json "$test_dir/offboarding-repeat.json" >/dev/null
cmp "$test_dir/offboarding.json" "$test_dir/offboarding-repeat.json"
for offboarding_output in "$test_dir/offboarding.json" "$test_dir/offboarding.html" "$test_dir/offboarding.csv"; do
	[[ $(stat -c '%a' "$offboarding_output") == 600 ]]
done
grep -Fq 'report_only; remote changes: false; executable: false' <<<"$offboarding_text"
grep -Fq 'not an executable removal plan' <<<"$offboarding_text"
jq -e '.schema_version == "1" and (.report_id | startswith("offboarding_"))' "$test_dir/offboarding.json" >/dev/null
[[ $(jq -r '.scan_id' "$test_dir/offboarding.json") == $(jq -r '.scan_id' "$test_dir/system-scan.json") ]]
[[ $(jq -r '.review_id' "$test_dir/offboarding.json") == $(jq -r '.review_id' "$test_dir/ownership-review.json") ]]
jq -e '.identity.id == "former@example.com" and .identity.status == "offboarded"' "$test_dir/offboarding.json" >/dev/null
jq -e '.safety == {mode:"report_only",remote_changes:false,executable:false,source_digests_included:false,requires_fresh_scan_before_remediation:true}' "$test_dir/offboarding.json" >/dev/null
jq -e '.summary.claimed_keys == 1 and .summary.observed_keys == 1 and .summary.access_edges == 2 and .summary.hosts == 1 and .summary.accounts == 1 and .summary.shared_keys == 1' "$test_dir/offboarding.json" >/dev/null
jq -e '[.warnings[].code] | index("offboarded_access_observed") != null and index("shared_key_claim") != null and index("claim_not_possession_verified") != null' "$test_dir/offboarding.json" >/dev/null
jq -e '.keys[0].selected_claim.identity == "former@example.com" and .keys[0].shared == true and (.keys[0].other_claims | length) == 1 and (.keys[0].access | length) == 2' "$test_dir/offboarding.json" >/dev/null
grep -Fq 'Not an executable removal plan' "$test_dir/offboarding.html"
grep -Fq 'former@example.com' "$test_dir/offboarding.html"
grep -Fq 'report_only' "$test_dir/offboarding.csv"
if grep -Eiq '<script|<(img|iframe|object|embed|link)[[:space:]>]|href="https?://|src="https?://|url\(' "$test_dir/offboarding.html"; then
	echo "offboarding HTML contains executable or remote markup" >&2
	exit 1
fi
if grep -Fq '"public_key"' "$test_dir/offboarding.json" || \
	grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/offboarding.json"; then
	echo "offboarding report contains raw public-key material" >&2
	exit 1
fi
[[ "$offboarding_remote_hash" == "$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')" ]]
[[ "$offboarding_system_hash" == "$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')" ]]
if "$sshmgr_bin" access offboarding missing@example.com \
	--scan "$test_dir/system-scan.json" --review "$test_dir/ownership-review.json" >/dev/null 2>&1; then
	echo "offboarding accepted an identity absent from the review" >&2
	exit 1
fi
if "$sshmgr_bin" access offboarding former@example.com \
	--scan "$test_dir/system-scan.json" --review "$test_dir/ownership-review.json" \
	--json "$test_dir/system-scan.json" >/dev/null 2>&1; then
	echo "offboarding overwrote its input snapshot" >&2
	exit 1
fi
if "$sshmgr_bin" access offboarding former@example.com \
	--scan "$test_dir/system-scan.json" --review "$test_dir/ownership-review.json" \
	--json "$test_dir/offboarding-collision" --html "$test_dir/offboarding-collision" >/dev/null 2>&1; then
	echo "offboarding accepted colliding output paths" >&2
	exit 1
fi
review_input_hash=$(sha256sum "$test_dir/system-scan.json" | awk '{print $1}')
if "$sshmgr_bin" access review "$test_dir/system-scan.json" --identities "$test_dir/identities.yaml" \
	--json "$test_dir/system-scan.json" >/dev/null 2>&1; then
	echo "ownership review overwrote an input snapshot" >&2
	exit 1
fi
[[ "$review_input_hash" == "$(sha256sum "$test_dir/system-scan.json" | awk '{print $1}')" ]]

# Cloud preparation remains entirely offline. The transport candidate is
# deterministic and strict, strips raw public keys unconditionally, strips
# unverified comments by default, and exposes a field-level privacy preview.
"$sshmgr_bin" cloud upload-plan "$test_dir/system-scan.json" \
	--workspace client-a --out "$test_dir/upload-plan.json" >/dev/null
"$sshmgr_bin" cloud upload-plan "$test_dir/system-scan.json" \
	--workspace client-a --out "$test_dir/upload-plan-repeat.json" >/dev/null
cmp "$test_dir/upload-plan.json" "$test_dir/upload-plan-repeat.json"
[[ $(stat -c '%a' "$test_dir/upload-plan.json") == 600 ]]
jq -e '.schema_version == "1" and .workspace == "client-a" and .artifact_type == "access_snapshot"' "$test_dir/upload-plan.json" >/dev/null
jq -e '.artifact_id == .snapshot.scan_id and (.idempotency_key | startswith("upload_")) and (.plan_id | startswith("plan_"))' "$test_dir/upload-plan.json" >/dev/null
jq -e '.privacy.public_keys_included == false and .privacy.credentials_included == false and .privacy.identity_hints_included == false' "$test_dir/upload-plan.json" >/dev/null
jq -e '.preview.hosts == 1 and .preview.unique_fingerprints == 2 and .preview.raw_public_keys == 0 and .preview.identity_hints == 0' "$test_dir/upload-plan.json" >/dev/null
jq -e '.payload_bytes > 0 and (.payload_sha256 | startswith("SHA256:"))' "$test_dir/upload-plan.json" >/dev/null
"$sshmgr_bin" cloud inspect "$test_dir/upload-plan.json" | grep -Fq 'Network activity:          none'
if grep -Eq 'alice@laptop|contractor@old-device|service@system-source|"public_key"' "$test_dir/upload-plan.json"; then
	echo "default offline upload plan leaked identity hints or raw public key fields" >&2
	exit 1
fi
"$sshmgr_bin" cloud upload-plan "$test_dir/system-scan.json" \
	--workspace client-a --include-identity-hints --out "$test_dir/upload-plan-with-hints.json" >/dev/null
jq -e '.privacy.identity_hints_included == true and .preview.identity_hints == 3' "$test_dir/upload-plan-with-hints.json" >/dev/null
grep -Fq 'alice@laptop' "$test_dir/upload-plan-with-hints.json"

# A local workspace history models WebPanel ingestion without a client or
# network call. Repeat scans with equal scope are comparable, input order is
# normalized, and retrying the exact same plan is idempotently deduplicated.
"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	--sudo --accounts explicit --account audit --max-source-mib 1 --max-total-mib 2 \
	-p 1 --timeout 10s --out "$test_dir/system-scan-repeat.json" >/dev/null
"$sshmgr_bin" access review "$test_dir/system-scan-repeat.json" --identities "$test_dir/identities.yaml" \
	--json "$test_dir/ownership-review-next.json" >/dev/null

# A post-scan check must classify unchanged observed access as still present,
# bind the baseline report to its original inputs, and remain local/read-only.
offboarding_check_remote_hash=$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')
offboarding_check_system_hash=$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')
offboarding_check_text=$("$sshmgr_bin" access offboarding-check \
	--baseline "$test_dir/offboarding.json" \
	--before-scan "$test_dir/system-scan.json" --before-review "$test_dir/ownership-review.json" \
	--after-scan "$test_dir/system-scan-repeat.json" --after-review "$test_dir/ownership-review-next.json" \
	--json "$test_dir/offboarding-check.json" --html "$test_dir/offboarding-check.html" \
	--csv "$test_dir/offboarding-check.csv")
"$sshmgr_bin" access offboarding-check \
	--baseline "$test_dir/offboarding.json" \
	--before-scan "$test_dir/system-scan.json" --before-review "$test_dir/ownership-review.json" \
	--after-scan "$test_dir/system-scan-repeat.json" --after-review "$test_dir/ownership-review-next.json" \
	--json "$test_dir/offboarding-check-repeat.json" >/dev/null
cmp "$test_dir/offboarding-check.json" "$test_dir/offboarding-check-repeat.json"
for check_output in "$test_dir/offboarding-check.json" "$test_dir/offboarding-check.html" "$test_dir/offboarding-check.csv"; do
	[[ $(stat -c '%a' "$check_output") == 600 ]]
done
grep -Fq 'Outcome:         still_present' <<<"$offboarding_check_text"
grep -Fq 'remote changes: false; executable: false' <<<"$offboarding_check_text"
jq -e '.schema_version == "1" and (.check_id | startswith("offboarding_check_")) and .outcome == "still_present"' "$test_dir/offboarding-check.json" >/dev/null
jq -e '.comparison.comparable == true and .comparison.fresh_after_snapshot == true and .comparison.claims_unchanged == true and .comparison.identity_offboarded_after == true' "$test_dir/offboarding-check.json" >/dev/null
jq -e '.summary.baseline_access_edges == 1 and .summary.still_observed_edges == 1 and .summary.not_observed_edges == 0 and .summary.newly_observed_edges == 0' "$test_dir/offboarding-check.json" >/dev/null
jq -e '([.reasons[].code] | sort) == ["access_still_observed"] and .summary.blocking_reasons == 1' "$test_dir/offboarding-check.json" >/dev/null
grep -Fq 'read-only post-scan verification' "$test_dir/offboarding-check.html"
grep -Fq 'still_present' "$test_dir/offboarding-check.csv"
if grep -Eiq '<script|<(img|iframe|object|embed|link)[[:space:]>]|href="https?://|src="https?://|url\(' "$test_dir/offboarding-check.html"; then
	echo "offboarding check HTML contains executable or remote markup" >&2
	exit 1
fi
if grep -Fq '"public_key"' "$test_dir/offboarding-check.json" || \
	grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/offboarding-check.json"; then
	echo "offboarding check contains raw public-key material" >&2
	exit 1
fi
[[ "$offboarding_check_remote_hash" == "$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')" ]]
[[ "$offboarding_check_system_hash" == "$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')" ]]
if "$sshmgr_bin" access offboarding-check \
	--baseline "$test_dir/offboarding.json" \
	--before-scan "$test_dir/system-scan-repeat.json" --before-review "$test_dir/ownership-review-next.json" \
	--after-scan "$test_dir/system-scan-repeat.json" --after-review "$test_dir/ownership-review-next.json" >/dev/null 2>&1; then
	echo "offboarding check accepted a baseline report with mismatched original inputs" >&2
	exit 1
fi
if "$sshmgr_bin" access offboarding-check \
	--baseline "$test_dir/offboarding.json" \
	--before-scan "$test_dir/system-scan.json" --before-review "$test_dir/ownership-review.json" \
	--after-scan "$test_dir/system-scan-repeat.json" --after-review "$test_dir/ownership-review-next.json" \
	--json "$test_dir/system-scan-repeat.json" >/dev/null 2>&1; then
	echo "offboarding check overwrote an input snapshot" >&2
	exit 1
fi
"$sshmgr_bin" cloud upload-plan "$test_dir/system-scan-repeat.json" \
	--workspace client-a --out "$test_dir/upload-plan-next.json" >/dev/null
"$sshmgr_bin" cloud history-build \
	"$test_dir/upload-plan-next.json" "$test_dir/upload-plan.json" "$test_dir/upload-plan.json" \
	--out "$test_dir/workspace-history.json" >/dev/null
"$sshmgr_bin" cloud history-build \
	"$test_dir/upload-plan.json" "$test_dir/upload-plan-next.json" \
	--out "$test_dir/workspace-history-repeat.json" >/dev/null
cmp "$test_dir/workspace-history.json" "$test_dir/workspace-history-repeat.json"
[[ $(stat -c '%a' "$test_dir/workspace-history.json") == 600 ]]
jq -e '.schema_version == "1" and .workspace == "client-a" and (.history_id | startswith("history_"))' "$test_dir/workspace-history.json" >/dev/null
jq -e '(.plans | length) == 2 and (.artifacts | length) == 2 and (.transitions | length) == 1' "$test_dir/workspace-history.json" >/dev/null
jq -e '.latest_scan_id == .artifacts[-1].scan_id and .transitions[0].comparable == true' "$test_dir/workspace-history.json" >/dev/null
jq -e '(.transitions[0].added | length) == 0 and (.transitions[0].removed | length) == 0' "$test_dir/workspace-history.json" >/dev/null
"$sshmgr_bin" cloud history-inspect "$test_dir/workspace-history.json" | grep -Fq 'Network activity: none'
if grep -Eq 'alice@laptop|contractor@old-device|service@system-source|"public_key"' "$test_dir/workspace-history.json"; then
	echo "offline workspace history leaked identity hints or raw public key fields" >&2
	exit 1
fi

# Ownership reviews are bound to the same immutable workspace timeline. The
# companion retains exact review digests for audit joins but removes all
# unverified authorized_keys comments from its embedded reviews.
"$sshmgr_bin" cloud ownership-history-build "$test_dir/workspace-history.json" \
	"$test_dir/ownership-review-next.json" "$test_dir/ownership-review.json" "$test_dir/ownership-review.json" \
	--out "$test_dir/workspace-ownership-history.json" >/dev/null
"$sshmgr_bin" cloud ownership-history-build "$test_dir/workspace-history.json" \
	"$test_dir/ownership-review.json" "$test_dir/ownership-review-next.json" \
	--out "$test_dir/workspace-ownership-history-repeat.json" >/dev/null
cmp "$test_dir/workspace-ownership-history.json" "$test_dir/workspace-ownership-history-repeat.json"
[[ $(stat -c '%a' "$test_dir/workspace-ownership-history.json") == 600 ]]
jq -e '.schema_version == "1" and .workspace == "client-a" and (.ownership_history_id | startswith("ownership_history_"))' "$test_dir/workspace-ownership-history.json" >/dev/null
jq -e '.summary == {scans:2,reviewed_scans:2,missing_scans:0,current_review:true}' "$test_dir/workspace-ownership-history.json" >/dev/null
jq -e '.latest.current == true and .latest.scan_id == .latest_scan_id and (.latest.review_sha256 | startswith("SHA256:"))' "$test_dir/workspace-ownership-history.json" >/dev/null
jq -e '(.reviews | length) == 2 and (.transitions | length) == 1 and ([.scans[].reviewed] | all)' "$test_dir/workspace-ownership-history.json" >/dev/null
"$sshmgr_bin" cloud ownership-history-inspect "$test_dir/workspace-ownership-history.json" | grep -Fq 'Network activity:  none'
if grep -Eq 'alice@laptop|contractor@old-device|service@system-source|"public_key"' "$test_dir/workspace-ownership-history.json" || \
	grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/workspace-ownership-history.json"; then
	echo "offline workspace ownership history contains comments or raw public-key material" >&2
	exit 1
fi
if "$sshmgr_bin" cloud ownership-history-build "$test_dir/workspace-history.json" \
	"$test_dir/ownership-review.json" --out "$test_dir/ownership-review.json" >/dev/null 2>&1; then
	echo "offline workspace ownership history overwrote an input review" >&2
	exit 1
fi

# Bind the validated post-scan result to the exact offline workspace timeline.
# Exact retries deduplicate, while the latest scan makes this identity current.
"$sshmgr_bin" cloud offboarding-history-build "$test_dir/workspace-history.json" \
	"$test_dir/offboarding-check.json" "$test_dir/offboarding-check.json" \
	--out "$test_dir/workspace-offboarding-history.json" >/dev/null
"$sshmgr_bin" cloud offboarding-history-build "$test_dir/workspace-history.json" \
	"$test_dir/offboarding-check.json" \
	--out "$test_dir/workspace-offboarding-history-repeat.json" >/dev/null
cmp "$test_dir/workspace-offboarding-history.json" "$test_dir/workspace-offboarding-history-repeat.json"
[[ $(stat -c '%a' "$test_dir/workspace-offboarding-history.json") == 600 ]]
jq -e '.schema_version == "1" and .workspace == "client-a" and (.offboarding_history_id | startswith("offboarding_history_"))' "$test_dir/workspace-offboarding-history.json" >/dev/null
jq -e '.summary == {identities:1,checks:1,current_complete:0,current_still_present:1,current_inconclusive:0,stale:0}' "$test_dir/workspace-offboarding-history.json" >/dev/null
jq -e '.latest[0].identity.id == "former@example.com" and .latest[0].outcome == "still_present" and .latest[0].current == true and .latest[0].after_scan_id == .latest_scan_id' "$test_dir/workspace-offboarding-history.json" >/dev/null
"$sshmgr_bin" cloud offboarding-history-inspect "$test_dir/workspace-offboarding-history.json" | grep -Fq 'Network activity:  none'
if grep -Fq '"public_key"' "$test_dir/workspace-offboarding-history.json" || \
	grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/workspace-offboarding-history.json"; then
	echo "offline workspace offboarding history contains raw public-key material" >&2
	exit 1
fi
if "$sshmgr_bin" cloud offboarding-history-build "$test_dir/workspace-history.json" \
	"$test_dir/offboarding-check.json" --out "$test_dir/offboarding-check.json" >/dev/null 2>&1; then
	echo "offline workspace offboarding history overwrote an input check" >&2
	exit 1
fi

# Freeze the complete, strictly joined review evidence into the single
# deterministic transport envelope a future SaaS ingestion endpoint accepts.
# This remains a private local artifact and does not perform an upload.
"$sshmgr_bin" cloud bundle-build "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--out "$test_dir/workspace-bundle.json" >/dev/null
"$sshmgr_bin" cloud bundle-build "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--out "$test_dir/workspace-bundle-repeat.json" >/dev/null
cmp "$test_dir/workspace-bundle.json" "$test_dir/workspace-bundle-repeat.json"
[[ $(stat -c '%a' "$test_dir/workspace-bundle.json") == 600 ]]
jq -e '.schema_version == "1" and .artifact_type == "workspace_access_review" and .workspace == "client-a" and (.bundle_id | startswith("bundle_")) and (.idempotency_key | startswith("bundle_upload_"))' "$test_dir/workspace-bundle.json" >/dev/null
jq -e '(.payload_sha256 | startswith("SHA256:")) and .payload_bytes > 0 and (.digests.workspace_history_sha256 | startswith("SHA256:")) and (.digests.ownership_review_sha256 | startswith("SHA256:")) and (.digests.ownership_review_source_sha256 | startswith("SHA256:")) and (.digests.ownership_history_sha256 | startswith("SHA256:")) and (.digests.offboarding_history_sha256 | startswith("SHA256:"))' "$test_dir/workspace-bundle.json" >/dev/null
jq -e '.preview.snapshots == 2 and .preview.ownership_review_attached == true and .preview.ownership_reviews == 2 and .preview.offboarding_checks == 1 and .preview.tracked_offboarding_identities == 1 and .preview.raw_public_keys == 0' "$test_dir/workspace-bundle.json" >/dev/null
jq -e '.privacy.public_keys_included == false and .privacy.credentials_included == false and .payload.workspace_history.latest_scan_id == .payload.ownership_review.scan_id' "$test_dir/workspace-bundle.json" >/dev/null
jq -e '([.payload.ownership_review.keys[].identity_hints?] | map(select(. != null and length > 0)) | length) == 0' "$test_dir/workspace-bundle.json" >/dev/null
"$sshmgr_bin" cloud bundle-inspect "$test_dir/workspace-bundle.json" | grep -Fq 'Network activity:           none'
if grep -Eq 'alice@laptop|contractor@old-device|service@system-source|"public_key"' "$test_dir/workspace-bundle.json" || \
	grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/workspace-bundle.json"; then
	echo "offline workspace ingestion bundle leaked comments or raw public-key material" >&2
	exit 1
fi
if "$sshmgr_bin" cloud bundle-build "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--out "$test_dir/workspace-history.json" >/dev/null 2>&1; then
	echo "offline workspace ingestion bundle overwrote an input artifact" >&2
	exit 1
fi
if "$sshmgr_bin" cloud bundle-build "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review.json" \
	--out "$test_dir/stale-workspace-bundle.json" >/dev/null 2>&1; then
	echo "offline workspace ingestion bundle accepted a stale ownership review" >&2
	exit 1
fi
jq '.preview.latest_hosts += 1' "$test_dir/workspace-bundle.json" >"$test_dir/workspace-bundle-tampered.json"
if "$sshmgr_bin" cloud bundle-inspect "$test_dir/workspace-bundle-tampered.json" >/dev/null 2>&1; then
	echo "offline workspace ingestion bundle accepted a tampered preview" >&2
	exit 1
fi

# The local WebPanel preview is a deterministic, self-contained projection of
# the validated history. It must not create network-capable markup or promote
# default-redacted comments back into identity hints.
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--html "$test_dir/workspace-dashboard.html" --csv "$test_dir/workspace-access-review.csv" >/dev/null
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--html "$test_dir/workspace-dashboard-repeat.html" --csv "$test_dir/workspace-access-review-repeat.csv" >/dev/null
cmp "$test_dir/workspace-dashboard.html" "$test_dir/workspace-dashboard-repeat.html"
cmp "$test_dir/workspace-access-review.csv" "$test_dir/workspace-access-review-repeat.csv"
[[ $(stat -c '%a' "$test_dir/workspace-dashboard.html") == 600 ]]
[[ $(stat -c '%a' "$test_dir/workspace-access-review.csv") == 600 ]]
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--csv "$test_dir/workspace-access-review-csv-only.csv" >/dev/null
cmp "$test_dir/workspace-access-review.csv" "$test_dir/workspace-access-review-csv-only.csv"

# The complete workspace gate reuses these exact joins. It writes requested
# artifacts before status 2 and can independently require current ownership,
# complete coverage, and complete tracked offboarding outcomes.
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--html "$test_dir/workspace-dashboard-policy-pass.html" \
	--fail-on critical --require-current-ownership >/dev/null
cmp "$test_dir/workspace-dashboard.html" "$test_dir/workspace-dashboard-policy-pass.html"
workspace_gate_status=0
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--html "$test_dir/workspace-dashboard-gated.html" --csv "$test_dir/workspace-access-review-gated.csv" \
	--fail-on high --require-full --require-current-ownership --require-complete-offboarding \
	>/dev/null 2>"$test_dir/workspace-gate.stderr" || workspace_gate_status=$?
[[ "$workspace_gate_status" -eq 2 ]]
cmp "$test_dir/workspace-dashboard.html" "$test_dir/workspace-dashboard-gated.html"
cmp "$test_dir/workspace-access-review.csv" "$test_dir/workspace-access-review-gated.csv"
grep -Fq 'workspace review gate failed' "$test_dir/workspace-gate.stderr"
grep -Fq 'finding(s) meet severity high or higher' "$test_dir/workspace-gate.stderr"
grep -Fq 'tracked offboarding outcome(s) are stale, still present, or inconclusive' "$test_dir/workspace-gate.stderr"
missing_ownership_gate_status=0
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--csv "$test_dir/workspace-missing-ownership.csv" --require-current-ownership \
	>/dev/null 2>"$test_dir/workspace-missing-ownership.stderr" || missing_ownership_gate_status=$?
[[ "$missing_ownership_gate_status" -eq 2 ]]
[[ $(stat -c '%a' "$test_dir/workspace-missing-ownership.csv") == 600 ]]
grep -Fq 'current ownership review is missing' "$test_dir/workspace-missing-ownership.stderr"
missing_offboarding_gate_status=0
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--html "$test_dir/workspace-missing-offboarding.html" --require-complete-offboarding \
	>/dev/null 2>"$test_dir/workspace-missing-offboarding.stderr" || missing_offboarding_gate_status=$?
[[ "$missing_offboarding_gate_status" -eq 2 ]]
[[ $(stat -c '%a' "$test_dir/workspace-missing-offboarding.html") == 600 ]]
grep -Fq 'offboarding history is missing' "$test_dir/workspace-missing-offboarding.stderr"
invalid_workspace_gate_status=0
"$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--html "$test_dir/workspace-invalid-gate.html" --fail-on warning \
	>/dev/null 2>&1 || invalid_workspace_gate_status=$?
[[ "$invalid_workspace_gate_status" -eq 1 ]]
[[ ! -e "$test_dir/workspace-invalid-gate.html" ]]
[[ $(head -n 1 "$test_dir/workspace-access-review.csv") == 'row_type,workspace,history_id,scan_id,completed_at,current,review_id,check_id,action,severity,rule_id,identity,identity_status,verification,fingerprint,algorithm,bits,host,coverage,account,source,line,before_value,after_value,outcome,details' ]]
for row_type in workspace_summary host_coverage finding ownership_finding access_edge ownership_review_coverage ownership_review offboarding_outcome offboarding_evidence; do
	grep -Fq "${row_type}," "$test_dir/workspace-access-review.csv"
done
grep -Fq 'former@example.com' "$test_dir/workspace-access-review.csv"
grep -Fq 'still_present' "$test_dir/workspace-access-review.csv"
for section in 'Overview' 'Findings' 'Ownership &amp; Offboarding' 'Ownership findings' 'Identity ownership' \
	'Offboarding evidence' 'Access Graph' 'Explicit path: identity' 'Timeline' \
	'Ownership review coverage' 'Ownership review history' 'Ownership changes' 'ownership review:' \
	'Offboarding outcome history' 'Current offboarding outcomes' 'still_present' 'access_still_observed' \
	'offboarded_identity_access' 'client-a' 'former@example.com' '=active@example.com' 'Network activity: none'; do
	grep -Fq "$section" "$test_dir/workspace-dashboard.html"
done
if grep -Eiq '<script|<(img|iframe|object|embed|link)[[:space:]>]|href="https?://|src="https?://|url\(' "$test_dir/workspace-dashboard.html"; then
	echo "offline workspace dashboard contains executable or remote markup" >&2
	exit 1
fi
if grep -Eq 'alice@laptop|contractor@old-device|service@system-source|"public_key"' "$test_dir/workspace-dashboard.html"; then
	echo "offline workspace dashboard leaked identity hints or raw public key fields" >&2
	exit 1
fi
if grep -Eq 'alice@laptop|contractor@old-device|service@system-source|"public_key"' "$test_dir/workspace-access-review.csv" || \
	grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/workspace-access-review.csv"; then
	echo "offline workspace access-review CSV leaked comments or raw public-key material" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--html "$test_dir/workspace-history.json" >/dev/null 2>&1; then
	echo "offline workspace dashboard overwrote its input history" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--html "$test_dir/dashboard-collision" --csv "$test_dir/dashboard-collision" >/dev/null 2>&1; then
	echo "offline workspace dashboard accepted colliding HTML/CSV outputs" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--csv "$test_dir/workspace-history.json" >/dev/null 2>&1; then
	echo "offline workspace dashboard CSV overwrote its input history" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review.json" \
	--html "$test_dir/stale-ownership-dashboard.html" >/dev/null 2>&1; then
	echo "offline workspace dashboard accepted ownership from an older scan" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-review "$test_dir/ownership-review-next.json" \
	--html "$test_dir/ownership-review-next.json" >/dev/null 2>&1; then
	echo "offline workspace dashboard overwrote its input ownership review" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--ownership-history "$test_dir/workspace-ownership-history.json" \
	--html "$test_dir/workspace-ownership-history.json" >/dev/null 2>&1; then
	echo "offline workspace dashboard overwrote its input ownership history" >&2
	exit 1
fi
if "$sshmgr_bin" cloud dashboard "$test_dir/workspace-history.json" \
	--offboarding-history "$test_dir/workspace-offboarding-history.json" \
	--html "$test_dir/workspace-offboarding-history.json" >/dev/null 2>&1; then
	echo "offline workspace dashboard overwrote its input offboarding history" >&2
	exit 1
fi
if "$sshmgr_bin" cloud history-build "$test_dir/upload-plan.json" \
	--out "$test_dir/upload-plan.json" >/dev/null 2>&1; then
	echo "offline workspace history overwrote its input plan" >&2
	exit 1
fi
upload_input_hash=$(sha256sum "$test_dir/system-scan.json" | awk '{print $1}')
if "$sshmgr_bin" cloud upload-plan "$test_dir/system-scan.json" --workspace client-a \
	--out "$test_dir/system-scan.json" >/dev/null 2>&1; then
	echo "offline upload plan overwrote its input snapshot" >&2
	exit 1
fi
[[ "$upload_input_hash" == "$(sha256sum "$test_dir/system-scan.json" | awk '{print $1}')" ]]
[[ "$offboarding_check_remote_hash" == "$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')" ]]
[[ "$offboarding_check_system_hash" == "$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')" ]]
if "$sshmgr_bin" cloud upload "$test_dir/upload-plan.json" >/dev/null 2>&1; then
	echo "disabled Cloud upload unexpectedly succeeded" >&2
	exit 1
fi

before_external_hash=$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')
before_external_system_hash=$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')
: >"$proxy_count"
"$sshmgr_bin" access scan --host external-smoke --exclude-host protected \
	--sudo --accounts explicit --account audit --max-source-mib 1 --max-total-mib 2 \
	-p 1 --timeout 10s --out "$test_dir/external-system-scan.json" >/dev/null
[[ $(wc -l <"$proxy_count") -eq 2 ]]
[[ "$before_external_hash" == "$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')" ]]
[[ "$before_external_system_hash" == "$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')" ]]
jq -e '.summary.authorized_key_entries == 3 and .summary.unique_fingerprints == 2 and .summary.hosts_failed == 0' "$test_dir/external-system-scan.json" >/dev/null
jq -e '.hosts[0].system.sources_requested == 2 and .hosts[0].system.sources_inspected == 2' "$test_dir/external-system-scan.json" >/dev/null
diff -u \
	<(jq -S '.hosts[0] | del(.alias, .groups, .duration_ms)' "$test_dir/system-scan.json") \
	<(jq -S '.hosts[0] | del(.alias, .groups, .duration_ms)' "$test_dir/external-system-scan.json")

# shellcheck disable=SC2016 # Deliberate literal command-substitution injection probe.
"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	--sudo --preflight --account 'audit,root,missing-user,$(touch /tmp/sshmgr-account-injection)' -p 1 --timeout 10s \
	--out "$test_dir/explicit-preflight.json" >/dev/null
jq -e '.scope.account_mode == "explicit" and (.scope.requested_accounts | length) == 4 and .scope.max_accounts == 4' "$test_dir/explicit-preflight.json" >/dev/null
jq -e '.scope.requested_accounts | index("$(touch /tmp/sshmgr-account-injection)") != null' "$test_dir/explicit-preflight.json" >/dev/null
jq -e '.hosts[0].system.account_mode == "explicit" and .hosts[0].system.account_database == "getent-keyed"' "$test_dir/explicit-preflight.json" >/dev/null
jq -e '.hosts[0].system.missing_accounts | index("missing-user") != null and index("$(touch /tmp/sshmgr-account-injection)") != null' "$test_dir/explicit-preflight.json" >/dev/null
jq -e '[.hosts[0].accounts[].username] | sort == ["audit", "root"]' "$test_dir/explicit-preflight.json" >/dev/null
jq -e '[.findings[].rule_id] | index("requested_account_missing") != null' "$test_dir/explicit-preflight.json" >/dev/null
jq -e '[.hosts[0].accounts[].sources[] | .exists, .content_inspected] | all(. == false)' "$test_dir/explicit-preflight.json" >/dev/null
ssh -F /dev/null -i "$test_dir/access_key" -p "$port" \
	-o BatchMode=yes -o StrictHostKeyChecking=no \
	-o UserKnownHostsFile="$test_dir/openssh-known-hosts" \
	audit@127.0.0.1 test ! -e /tmp/sshmgr-account-injection

"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	--sudo --preflight --accounts nss --max-accounts 2 -p 1 --timeout 10s \
	--out "$test_dir/nss-preflight.json" >/dev/null
jq -e '.scope.account_mode == "nss" and .scope.max_accounts == 2' "$test_dir/nss-preflight.json" >/dev/null
jq -e '.hosts[0].system.account_mode == "nss" and .hosts[0].system.account_database == "getent"' "$test_dir/nss-preflight.json" >/dev/null
jq -e '.hosts[0].system.accounts_enumerated == true and .hosts[0].system.accounts_truncated == true and .hosts[0].system.account_limit == 2' "$test_dir/nss-preflight.json" >/dev/null
jq -e '.summary.accounts_observed == 2 and .summary.authorized_key_entries == 0' "$test_dir/nss-preflight.json" >/dev/null
jq -e '[.findings[].rule_id] | index("account_enumeration_truncated") != null' "$test_dir/nss-preflight.json" >/dev/null

all_failed_gate_status=0
"$sshmgr_bin" access scan --host smoke --scope system --preflight \
	--out "$test_dir/direct-system.json" --fail-on info \
	>/dev/null 2>&1 || all_failed_gate_status=$?
[[ "$all_failed_gate_status" -eq 1 ]]
jq -e '.hosts[0].coverage == "failed" and .hosts[0].errors[0].stage == "privilege"' "$test_dir/direct-system.json" >/dev/null

"$sshmgr_bin" access scan --group access-e2e --exclude-host protected \
	-p 1 --timeout 10s --out "$test_dir/scan-before.json" >/dev/null
after_scan_hash=$(sha256sum "$test_dir/remote-ssh/authorized_keys" | awk '{print $1}')
[[ "$before_hash" == "$after_scan_hash" ]]
[[ $(stat -c '%a' "$test_dir/scan-before.json") == 600 ]]
jq -e '.summary.authorized_key_entries == 2 and .summary.unique_fingerprints == 1' "$test_dir/scan-before.json" >/dev/null
jq -e '[.findings[].rule_id] | index("duplicate_key_entry") != null' "$test_dir/scan-before.json" >/dev/null
jq -e '[.findings[].rule_id] | index("ambiguous_identity_hint") != null' "$test_dir/scan-before.json" >/dev/null
if grep -Fq '"public_key"' "$test_dir/scan-before.json"; then
	echo "fingerprint-only snapshot contains raw public_key" >&2
	exit 1
fi
if grep -Fq "$(awk '{print $2}' "$test_dir/access_key.pub")" "$test_dir/scan-before.json"; then
	echo "fingerprint-only snapshot contains public key blob" >&2
	exit 1
fi

# Disjoint snapshots can be assembled into one fleet baseline locally. The
# producer is deterministic, retains source lineage, recomputes cross-host
# findings, and refuses to guess how duplicate host observations should merge.
"$sshmgr_bin" access merge \
	"$test_dir/scan-before.json" "$test_dir/external-current.json" \
	--out "$test_dir/merged.json" >/dev/null
"$sshmgr_bin" access merge \
	"$test_dir/external-current.json" "$test_dir/scan-before.json" \
	--out "$test_dir/merged-reverse.json" >/dev/null
cmp "$test_dir/merged.json" "$test_dir/merged-reverse.json"
[[ $(stat -c '%a' "$test_dir/merged.json") == 600 ]]
jq -e '.schema_version == "1" and (.source_scan_ids | length) == 2' "$test_dir/merged.json" >/dev/null
jq -e '.summary.hosts_requested == 2 and .summary.accounts_observed == 2 and .summary.authorized_key_entries == 4 and .summary.unique_fingerprints == 1' "$test_dir/merged.json" >/dev/null
jq -e '[.findings[] | select(.rule_id == "reused_key")][0].evidence | any(contains("2 hosts"))' "$test_dir/merged.json" >/dev/null
if grep -Fq '"public_key"' "$test_dir/merged.json"; then
	echo "fingerprint-only merged snapshot contains raw public_key" >&2
	exit 1
fi
if "$sshmgr_bin" access merge \
	"$test_dir/scan-before.json" "$test_dir/scan-before.json" \
	--out "$test_dir/invalid-merge.json" >/dev/null 2>&1; then
	echo "merge accepted duplicate source/host observations" >&2
	exit 1
fi
merge_input_hash=$(sha256sum "$test_dir/scan-before.json" | awk '{print $1}')
if "$sshmgr_bin" access merge \
	"$test_dir/scan-before.json" "$test_dir/external-current.json" \
	--out "$test_dir/scan-before.json" >/dev/null 2>&1; then
	echo "merge overwrote an input snapshot" >&2
	exit 1
fi
[[ "$merge_input_hash" == "$(sha256sum "$test_dir/scan-before.json" | awk '{print $1}')" ]]

"$sshmgr_bin" access report "$test_dir/scan-before.json" \
	--html "$test_dir/report.html" --csv "$test_dir/access.csv" >/dev/null
[[ $(stat -c '%a' "$test_dir/report.html") == 600 ]]
[[ $(stat -c '%a' "$test_dir/access.csv") == 600 ]]
grep -Fq 'ambiguous_identity_hint' "$test_dir/report.html"
grep -Fq 'scan_id,host,host_coverage,groups,tags,account' "$test_dir/access.csv"
[[ $(wc -l <"$test_dir/access.csv") -eq 3 ]]
if grep -Eq 'https?://|<script[^>]+src=' "$test_dir/report.html"; then
	echo "HTML report unexpectedly depends on a remote asset" >&2
	exit 1
fi

graph_text=$("$sshmgr_bin" access graph "$test_dir/scan-before.json" --json "$test_dir/access-graph.json")
grep -Fq 'Identity hints: 2 (all unverified comments)' <<<"$graph_text"
grep -Fq 'Observed access edges: 2' <<<"$graph_text"
[[ $(stat -c '%a' "$test_dir/access-graph.json") == 600 ]]
jq -e '.schema_version == "1" and .summary.hosts == 1 and .summary.accounts == 1 and .summary.keys == 1 and .summary.identity_hints == 2 and .summary.access_edges == 2 and .summary.claim_edges == 2' "$test_dir/access-graph.json" >/dev/null
jq -e '[.nodes[] | select(.kind == "identity_hint") | .verification] | all(. == "unverified_comment")' "$test_dir/access-graph.json" >/dev/null
if grep -Fq '"public_key"' "$test_dir/access-graph.json"; then
	echo "access graph contains raw public_key" >&2
	exit 1
fi

fingerprint=$(jq -r '.hosts[0].accounts[0].sources[].entries[0].fingerprint // empty' "$test_dir/scan-before.json")
[[ "$fingerprint" == SHA256:* ]]
"$sshmgr_bin" access where-is-key "$fingerprint" --scan "$test_dir/scan-before.json" | grep -Fq 'audit@smoke'
"$sshmgr_bin" access who-has smoke --scan "$test_dir/scan-before.json" | grep -Fq "$fingerprint"

"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	-p 1 --timeout 10s --out "$test_dir/scan-same.json" >/dev/null
same_diff=$("$sshmgr_bin" access diff "$test_dir/scan-before.json" "$test_dir/scan-same.json")
grep -Fq 'Added:   0' <<<"$same_diff"
grep -Fq 'Removed: 0' <<<"$same_diff"

printf '%s %s\n' "$extra_key" "new-owner@device" >>"$test_dir/remote-ssh/authorized_keys"
chmod 600 "$test_dir/remote-ssh/authorized_keys"
"$sshmgr_bin" access scan --host smoke --exclude-host protected \
	-p 1 --timeout 10s --out "$test_dir/scan-after.json" >/dev/null
changed_diff=$("$sshmgr_bin" access diff "$test_dir/scan-before.json" "$test_dir/scan-after.json")
grep -Fq 'Added:   1' <<<"$changed_diff"
grep -Fq 'Removed: 0' <<<"$changed_diff"

: >"$test_dir/unknown_known_hosts"
if SSHMGR_KNOWN_HOSTS="$test_dir/unknown_known_hosts" \
	"$sshmgr_bin" access scan --host smoke --out "$test_dir/unknown-host.json" >/dev/null 2>&1; then
	echo "batch scanner trusted an unknown host key" >&2
	exit 1
fi
[[ ! -s "$test_dir/unknown_known_hosts" ]]

: >"$proxy_count"
if "$sshmgr_bin" access scan --host external-unknown --exclude-host protected \
	--out "$test_dir/external-unknown-host.json" >/dev/null 2>&1; then
	echo "external batch scanner trusted an unknown host key" >&2
	exit 1
fi
[[ $(wc -l <"$proxy_count") -eq 1 ]]
[[ ! -e "$test_dir/external-unknown-known-hosts" || ! -s "$test_dir/external-unknown-known-hosts" ]]
jq -e '.hosts[0].coverage == "failed" and .hosts[0].errors[0].stage == "external-command" and (.hosts[0].errors[0].message | contains("host-key verification failed"))' \
	"$test_dir/external-unknown-host.json" >/dev/null

if "$sshmgr_bin" access scan --host smoke --exclude-host typo --dry-run >/dev/null 2>&1; then
	echo "unknown exclusion alias was accepted" >&2
	exit 1
fi
if "$sshmgr_bin" access scan --host smoke --scope system --accounts explicit --account audit \
	--out "$test_dir/direct-system-scan.json" >/dev/null 2>&1; then
	echo "non-root direct system scan unexpectedly succeeded" >&2
	exit 1
fi
jq -e '.hosts[0].coverage == "failed" and .hosts[0].errors[0].stage == "privilege"' "$test_dir/direct-system-scan.json" >/dev/null

echo "sshmgr access integration: PASS"
