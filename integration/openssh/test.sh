#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=$(mktemp -d)
container="sshmgr-openssh-$RANDOM-$$"
image="sshmgr-openssh-integration:local"
go_bin=$(command -v go 2>/dev/null || true)
sshmgr_bin="$test_dir/sshmgr"
forward_id=""

if [[ -z "$go_bin" && -x /home/destine/.local/go/bin/go ]]; then
	go_bin=/home/destine/.local/go/bin/go
fi
if [[ -z "$go_bin" ]]; then
	echo "go toolchain not found" >&2
	exit 1
fi

cleanup() {
	if [[ -n "$forward_id" && -x "$sshmgr_bin" ]]; then
		"$sshmgr_bin" fwd stop "$forward_id" >/dev/null 2>&1 || true
	fi
	docker rm -f "$container" >/dev/null 2>&1 || true
	case "$test_dir" in
		/tmp/tmp.*) rm -rf -- "$test_dir" ;;
		*) echo "refusing to remove unexpected test dir: $test_dir" >&2 ;;
	esac
}
trap cleanup EXIT

mkdir -p "$test_dir/remote-ssh" "$test_dir/xdg-state"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/key"
cp "$test_dir/key.pub" "$test_dir/remote-ssh/authorized_keys"
chmod 700 "$test_dir/remote-ssh"
chmod 600 "$test_dir/remote-ssh/authorized_keys"

docker build -t "$image" "$repo_dir/integration/rotate" >/dev/null
docker run -d --name "$container" \
	-p 127.0.0.1::22 \
	-v "$test_dir/remote-ssh:/root/.ssh" \
	"$image" >/dev/null

port=""
ready=0
for _ in $(seq 1 50); do
	mapping=$(docker port "$container" 22/tcp 2>/dev/null || true)
	port=${mapping##*:}
	if [[ -n "$port" ]] && ssh -F /dev/null -i "$test_dir/key" -p "$port" \
		-o BatchMode=yes -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile="$test_dir/openssh-known-hosts" \
		root@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 0.1
done
if [[ "$ready" != 1 ]]; then
	echo "sshd did not become ready" >&2
	exit 1
fi

cat >"$test_dir/config.yaml" <<EOF
groups:
  demo:
    user: root
    key: $test_dir/key
    auto_accept_host_key: true
    snippets:
      - name: health
        command: "echo snippet-ok"
hosts:
  smoke:
    host: 127.0.0.1
    port: $port
    groups: [demo]
EOF

export SSHMGR_CONFIG="$test_dir/config.yaml"
export SSHMGR_STATE="$test_dir/state.yaml"
export SSHMGR_KNOWN_HOSTS="$test_dir/sshmgr-known-hosts"
export XDG_STATE_HOME="$test_dir/xdg-state"

(cd "$repo_dir" && "$go_bin" build -buildvcs=false -trimpath \
	-ldflags="-X main.version=integration-test -X main.commit=integration -X main.buildDate=2026-08-05T00:00:00Z" \
	-o "$sshmgr_bin" .)

# Build metadata must not depend on a valid operational configuration.
version_json=$(SSHMGR_CONFIG="$test_dir/does-not-exist.yaml" "$sshmgr_bin" version --json)
grep -Fq '"version": "integration-test"' <<<"$version_json"
grep -Fq '"commit": "integration"' <<<"$version_json"

lint_json=$("$sshmgr_bin" lint --json)
grep -Fq '"errors": 0' <<<"$lint_json"
"$sshmgr_bin" list | grep -Fq smoke

cat >"$test_dir/bad-config.yaml" <<'EOF'
hosts:
  invalid:
    host: 127.0.0.1
    misspelled_option: true
EOF
if SSHMGR_CONFIG="$test_dir/bad-config.yaml" "$sshmgr_bin" lint --json >/dev/null 2>&1; then
	echo "lint accepted an unknown config field" >&2
	exit 1
fi

[[ $("$sshmgr_bin" smoke "echo oneshot-ok") == "oneshot-ok" ]]
[[ $("$sshmgr_bin" smoke :health) == "snippet-ok" ]]

exec_json=$("$sshmgr_bin" exec --host smoke --json "echo fleet-ok")
grep -Fq '"alias": "smoke"' <<<"$exec_json"
grep -Fq '"output": "fleet-ok\n"' <<<"$exec_json"
grep -Fq '"exit_code": 0' <<<"$exec_json"

printf 'atomic-transfer-ok\n' >"$test_dir/upload.txt"
"$sshmgr_bin" scp "$test_dir/upload.txt" smoke:/tmp/sshmgr-upload.txt
"$sshmgr_bin" scp smoke:/tmp/sshmgr-upload.txt "$test_dir/download.txt"
cmp "$test_dir/upload.txt" "$test_dir/download.txt"

local_port=""
for candidate in $(seq 32100 32200); do
	if ! timeout 0.1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$candidate" 2>/dev/null; then
		local_port=$candidate
		break
	fi
done
if [[ -z "$local_port" ]]; then
	echo "could not find a free local test port" >&2
	exit 1
fi

"$sshmgr_bin" fwd smoke -L "$local_port:127.0.0.1:22" -d
banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$local_port; IFS= read -r line <&3; printf '%s' \"\$line\"")
[[ "$banner" == SSH-2.0-* ]]
active=$("$sshmgr_bin" fwd active)
forward_id=$(awk '$2 == "smoke" {print $1; exit}' <<<"$active")
[[ -n "$forward_id" ]]
"$sshmgr_bin" fwd stop "$forward_id"
forward_id=""
if "$sshmgr_bin" fwd active 2>&1 | grep -Fq smoke; then
	echo "forward remained active after stop" >&2
	exit 1
fi

echo "OpenSSH product integration: PASS"
