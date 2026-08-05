#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=$(mktemp -d)
container="sshmgr-rotate-$RANDOM-$$"
go_bin=$(command -v go 2>/dev/null || true)
if [[ -z "$go_bin" && -x /home/destine/.local/go/bin/go ]]; then
  go_bin=/home/destine/.local/go/bin/go
fi
if [[ -z "$go_bin" ]]; then
  echo "go toolchain not found" >&2
  exit 1
fi

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  case "$test_dir" in
    /tmp/tmp.*) rm -rf -- "$test_dir" ;;
    *) echo "refusing to remove unexpected test dir: $test_dir" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$test_dir/remote-ssh"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/old_key"
ssh-keygen -q -t ed25519 -N '' -f "$test_dir/new_key"
cp "$test_dir/old_key.pub" "$test_dir/remote-ssh/authorized_keys"
chmod 700 "$test_dir/remote-ssh"
chmod 600 "$test_dir/remote-ssh/authorized_keys"

docker build -t sshmgr-rotate-integration:local "$repo_dir/integration/rotate" >/dev/null
docker run -d --name "$container" \
  -p 127.0.0.1::22 \
  -v "$test_dir/remote-ssh:/root/.ssh" \
  sshmgr-rotate-integration:local >/dev/null

port=""
ready=0
for _ in $(seq 1 50); do
  mapping=$(docker port "$container" 22/tcp 2>/dev/null || true)
  port=${mapping##*:}
  if [[ -n "$port" ]] && ssh -F /dev/null -i "$test_dir/old_key" -p "$port" \
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
hosts:
  rotate-test:
    host: 127.0.0.1
    port: $port
    user: root
    key: $test_dir/old_key
    auto_accept_host_key: true
EOF

export SSHMGR_CONFIG="$test_dir/config.yaml"
export SSHMGR_STATE="$test_dir/state.yaml"
export SSHMGR_KNOWN_HOSTS="$test_dir/sshmgr-known-hosts"

(cd "$repo_dir" && "$go_bin" build -buildvcs=false -o "$test_dir/sshmgr" .)

# Phase 1: append and verify, but keep both the old key and old config path.
"$test_dir/sshmgr" rotate-key --host rotate-test --new-key "$test_dir/new_key"
old_blob=$(awk '{print $2}' "$test_dir/old_key.pub")
new_blob=$(awk '{print $2}' "$test_dir/new_key.pub")
docker exec "$container" grep -Fq "$old_blob" /root/.ssh/authorized_keys
docker exec "$container" grep -Fq "$new_blob" /root/.ssh/authorized_keys
grep -Fq "key: $test_dir/old_key" "$test_dir/config.yaml"

# Phase 2: verify again, persist the new key path, reconnect with only that
# key, remove the old key, and prove the resulting config still connects.
"$test_dir/sshmgr" rotate-key --host rotate-test --new-key "$test_dir/new_key" --remove-old
if docker exec "$container" grep -Fq "$old_blob" /root/.ssh/authorized_keys; then
  echo "old key is still authorized" >&2
  exit 1
fi
docker exec "$container" grep -Fq "$new_blob" /root/.ssh/authorized_keys
grep -Fq "key: $test_dir/new_key" "$test_dir/config.yaml"
"$test_dir/sshmgr" rotate-test true

if ssh -F /dev/null -i "$test_dir/old_key" -p "$port" \
    -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile="$test_dir/openssh-known-hosts" \
    root@127.0.0.1 true 2>/dev/null; then
  echo "old key still authenticates" >&2
  exit 1
fi

echo "rotate-key Docker integration: PASS"
