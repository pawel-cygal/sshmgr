#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d)
install_dir="$test_dir/lib/sshmgr"
install_link="$test_dir/bin/sshmgr"
installer="$repo_dir/scripts/install-versioned.sh"

cleanup() {
	case "$test_dir" in
		/tmp/tmp.*) rm -rf -- "$test_dir" ;;
		*) echo "refusing to remove unexpected test dir: $test_dir" >&2 ;;
	esac
}
trap cleanup EXIT

mkdir -p "$install_dir" "$(dirname "$install_link")"
install -m 0755 /bin/true "$install_dir/sshmgr-old"
ln -s "$install_dir/sshmgr-old" "$install_link"

export SSHMGR_INSTALL_DIR="$install_dir"
export SSHMGR_INSTALL_LINK="$install_link"

"$installer" install /bin/false rc-test >/dev/null
[[ $(readlink "$install_link") == "$install_dir/sshmgr-rc-test" ]]
[[ $(readlink "$install_dir/.sshmgr-previous") == "$install_dir/sshmgr-old" ]]
[[ $(readlink "$install_dir/.sshmgr-current") == "$install_dir/sshmgr-rc-test" ]]
[[ -f "$install_dir/sshmgr-rc-test.manifest" ]]
[[ $(readlink "$install_dir/install-versioned.sh") == "$install_dir/install-versioned-rc-test.sh" ]]
[[ -x "$install_dir/install-versioned-rc-test.sh" ]]
if "$install_link"; then
	echo "new test version did not become active" >&2
	exit 1
fi

status=$("$installer" status)
grep -Fq "active: $install_dir/sshmgr-rc-test" <<<"$status"
grep -Fq "rollback: $install_dir/sshmgr-old" <<<"$status"

"$install_dir/install-versioned.sh" rollback >/dev/null
[[ $(readlink "$install_link") == "$install_dir/sshmgr-old" ]]
"$install_link"

"$installer" activate rc-test >/dev/null
[[ $(readlink "$install_link") == "$install_dir/sshmgr-rc-test" ]]
if "$install_link"; then
	echo "activate did not restore the selected test version" >&2
	exit 1
fi

if "$installer" install /bin/true rc-test >/dev/null 2>&1; then
	echo "installer overwrote an existing version with different contents" >&2
	exit 1
fi

echo "versioned installer integration: PASS"
