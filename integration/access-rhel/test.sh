#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
sshmgr_bin=${SSHMGR_CLOUD_BIN:-"$repo_dir/sshmgr-cloud"}
test_dir=$(mktemp -d)
container="sshmgr-access-rhel-$RANDOM-$$"
image="sshmgr-access-rhel-integration:local"

cleanup() {
	if [[ "$container" == sshmgr-access-rhel-* ]]; then
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

mkdir -p "$test_dir/audit-ssh" "$test_dir/denied-ssh" "$test_dir/system-keys" "$test_dir/state"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/access_key"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/extra_key"
primary_key=$(awk '{print $1 " " $2}' "$test_dir/access_key.pub")
extra_key=$(awk '{print $1 " " $2}' "$test_dir/extra_key.pub")
printf '%s %s\n' "$primary_key" "audit@rhel-home" >"$test_dir/audit-ssh/authorized_keys"
printf '%s %s\n' "$primary_key" "denied@rhel-home" >"$test_dir/denied-ssh/authorized_keys"
printf '%s %s\n' "$extra_key" "service@rhel-system" >"$test_dir/system-keys/audit-1000"
printf '%s %s\n' "$extra_key" "root@real-target" >"$test_dir/system-keys/real-root-keys"
ln -s real-root-keys "$test_dir/system-keys/root-0"
chmod 700 "$test_dir/audit-ssh"
chmod 600 "$test_dir/audit-ssh/authorized_keys"
chmod 755 "$test_dir/denied-ssh"
chmod 644 "$test_dir/denied-ssh/authorized_keys"
chmod 664 "$test_dir/system-keys/audit-1000"
chmod 600 "$test_dir/system-keys/real-root-keys"

docker build -t "$image" "$repo_dir/integration/access-rhel" >/dev/null
docker run -d --name "$container" \
	-p 127.0.0.1::22 \
	-v "$test_dir/audit-ssh:/home/audit/.ssh" \
	-v "$test_dir/denied-ssh:/home/denied/.ssh" \
	-v "$test_dir/system-keys:/etc/ssh/keys:ro" \
	-v "$test_dir/extra_key.pub:/etc/ssh/user_ca.pub:ro" \
	"$image" >/dev/null

port=""
ready=0
for _ in $(seq 1 80); do
	mapping=$(docker port "$container" 22/tcp 2>/dev/null || true)
	port=${mapping##*:}
	if [[ -n "$port" ]] && ssh -F /dev/null -i "$test_dir/access_key" -p "$port" \
		-o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile="$test_dir/readiness-known-hosts" \
		audit@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 0.1
done
if [[ "$ready" != 1 ]]; then
	echo "RHEL-compatible isolated sshd did not become ready" >&2
	docker logs "$container" >&2 || true
	exit 1
fi

ssh-keyscan -p "$port" 127.0.0.1 >"$test_dir/known_hosts" 2>/dev/null
chmod 600 "$test_dir/known_hosts"
printf '%s\n' \
	"hosts:" \
	"  rhel-native:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: audit" \
	"    key: $test_dir/access_key" \
	"    groups: [access-rhel-e2e]" \
	"  rhel-external:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: audit" \
	"    key: $test_dir/access_key" \
	"    external: true" \
	"    ssh_options:" \
	"      - UserKnownHostsFile=$test_dir/known_hosts" \
	"      - GlobalKnownHostsFile=/dev/null" \
	"      - StrictHostKeyChecking=yes" \
	"    groups: [access-rhel-external-e2e]" \
	"  rhel-denied:" \
	"    host: 127.0.0.1" \
	"    port: $port" \
	"    user: denied" \
	"    key: $test_dir/access_key" \
	"    groups: [access-rhel-denied-e2e]" \
	>"$test_dir/config.yaml"

export SSHMGR_CONFIG="$test_dir/config.yaml"
export SSHMGR_STATE="$test_dir/state/state.yaml"
export SSHMGR_KNOWN_HOSTS="$test_dir/known_hosts"
export XDG_STATE_HOME="$test_dir/state"

before_home_hash=$(sha256sum "$test_dir/audit-ssh/authorized_keys" | awk '{print $1}')
before_system_hash=$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')

"$sshmgr_bin" access scan --host rhel-native --sudo --preflight \
	--accounts explicit --account audit,root,ghost --max-accounts 3 \
	-p 1 --timeout 15s --out "$test_dir/rhel-preflight.json" >/dev/null
jq -e '.summary.hosts_failed == 0 and .scope.account_mode == "explicit" and .scope.max_accounts == 3' "$test_dir/rhel-preflight.json" >/dev/null
jq -e '.hosts[0].system.os == "Linux" and .hosts[0].system.account_database == "getent-keyed"' "$test_dir/rhel-preflight.json" >/dev/null
jq -e '.hosts[0].system.missing_accounts == ["ghost"]' "$test_dir/rhel-preflight.json" >/dev/null
jq -e '.hosts[0].system.sshd.authorized_keys_command == "/bin/false" and .hosts[0].system.sshd.authorized_keys_command_user == "nobody"' "$test_dir/rhel-preflight.json" >/dev/null
jq -e '.hosts[0].system.sshd.trusted_user_ca_keys == "/etc/ssh/user_ca.pub"' "$test_dir/rhel-preflight.json" >/dev/null
jq -e '.hosts[0].system.sshd.authorized_principals_file == "/etc/ssh/principals/%u" and .hosts[0].system.sshd.authorized_principals_command == "/bin/false"' "$test_dir/rhel-preflight.json" >/dev/null
jq -e '[.findings[].rule_id] | index("requested_account_missing") != null and index("external_key_source") != null and index("trusted_ssh_ca_detected") != null and index("external_principals_source") != null' "$test_dir/rhel-preflight.json" >/dev/null

"$sshmgr_bin" access scan --host rhel-native --sudo \
	--accounts explicit --account audit,root --max-accounts 2 \
	--max-source-mib 1 --max-total-mib 2 -p 1 --timeout 15s \
	--out "$test_dir/rhel-native-system.json" >/dev/null
jq -e '.summary.hosts_failed == 0 and .summary.accounts_observed == 2 and .summary.authorized_key_entries == 2 and .summary.unique_fingerprints == 2' "$test_dir/rhel-native-system.json" >/dev/null
jq -e '.hosts[0].system.sources_requested == 4 and .hosts[0].system.sources_inspected == 2' "$test_dir/rhel-native-system.json" >/dev/null
jq -e '.hosts[0].accounts[] | select(.username == "audit") | .sources[] | select(.path == "/etc/ssh/keys/audit-1000") | .mode == "0664" and .content_inspected == true' "$test_dir/rhel-native-system.json" >/dev/null
jq -e '.hosts[0].accounts[] | select(.username == "root") | .sources[] | select(.path == "/etc/ssh/keys/root-0") | .symlink == true and .content_inspected == false' "$test_dir/rhel-native-system.json" >/dev/null
jq -e '[.findings[].rule_id] | index("unsafe_key_file_permissions") != null and index("symlinked_key_source") != null and index("key_source_not_inspected") != null' "$test_dir/rhel-native-system.json" >/dev/null

"$sshmgr_bin" access scan --host rhel-external --sudo \
	--accounts explicit --account audit,root --max-accounts 2 \
	--max-source-mib 1 --max-total-mib 2 -p 1 --timeout 15s \
	--out "$test_dir/rhel-external-system.json" >/dev/null
diff -u \
	<(jq -S '.hosts[0] | del(.alias, .groups, .duration_ms)' "$test_dir/rhel-native-system.json") \
	<(jq -S '.hosts[0] | del(.alias, .groups, .duration_ms)' "$test_dir/rhel-external-system.json")

if "$sshmgr_bin" access scan --host rhel-denied --sudo --preflight \
	--accounts explicit --account denied -p 1 --timeout 10s \
	--out "$test_dir/rhel-sudo-denied.json" >/dev/null 2>&1; then
	echo "RHEL-compatible sudo denial unexpectedly succeeded" >&2
	exit 1
fi
jq -e '.hosts[0].coverage == "failed" and .hosts[0].errors[0].stage == "sudo-n"' "$test_dir/rhel-sudo-denied.json" >/dev/null

[[ "$before_home_hash" == "$(sha256sum "$test_dir/audit-ssh/authorized_keys" | awk '{print $1}')" ]]
[[ "$before_system_hash" == "$(sha256sum "$test_dir/system-keys/audit-1000" | awk '{print $1}')" ]]
[[ $(stat -c '%a' "$test_dir/rhel-preflight.json") == 600 ]]
[[ $(stat -c '%a' "$test_dir/rhel-native-system.json") == 600 ]]
[[ $(stat -c '%a' "$test_dir/rhel-external-system.json") == 600 ]]
if grep -Fq '"public_key"' "$test_dir/rhel-native-system.json" || \
	grep -Fq '"public_key"' "$test_dir/rhel-external-system.json"; then
	echo "RHEL-compatible fingerprint-only snapshot contains raw public_key" >&2
	exit 1
fi

echo "sshmgr access RHEL-compatible integration: PASS"
