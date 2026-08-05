#!/usr/bin/env bash
set -euo pipefail

# Versioned, non-destructive sshmgr installer.
#
# Defaults can be overridden for an unprivileged test installation:
#   SSHMGR_INSTALL_DIR=/tmp/lib SSHMGR_INSTALL_LINK=/tmp/bin/sshmgr \
#     ./scripts/install-versioned.sh install ./sshmgr v0.1.0

install_dir=${SSHMGR_INSTALL_DIR:-/usr/local/lib/sshmgr}
install_link=${SSHMGR_INSTALL_LINK:-/usr/local/bin/sshmgr}
current_link="$install_dir/.sshmgr-current"
previous_link="$install_dir/.sshmgr-previous"

fail() {
	echo "install-versioned: $*" >&2
	exit 1
}

validate_layout() {
	case "$install_dir" in
		/*) ;;
		*) fail "SSHMGR_INSTALL_DIR must be an absolute path" ;;
	esac
	case "$install_link" in
		/*) ;;
		*) fail "SSHMGR_INSTALL_LINK must be an absolute path" ;;
	esac
	[[ "$install_dir" != "/" ]] || fail "refusing install directory /"
	[[ "$install_link" != "/" ]] || fail "refusing install link /"
}

validate_label() {
	local label=$1
	[[ -n "$label" ]] || fail "version label cannot be empty"
	[[ "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] ||
		fail "version label may contain only letters, digits, dot, underscore, plus and hyphen"
}

resolve_path() {
	local path=$1 target dir base
	while [[ -L "$path" ]]; do
		target=$(readlink "$path") || return 1
		case "$target" in
			/*) path=$target ;;
			*) path=$(dirname "$path")/$target ;;
		esac
	done
	dir=$(cd -P "$(dirname "$path")" 2>/dev/null && pwd) || return 1
	base=$(basename "$path")
	printf '%s/%s\n' "$dir" "$base"
}

validate_managed_target() {
	local target=$1
	case "$target" in
		"$install_dir"/*) ;;
		*) fail "target is outside $install_dir: $target" ;;
	esac
	[[ -f "$target" && -x "$target" ]] || fail "target is not an executable regular file: $target"
}

checksum() {
	local path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$path" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$path" | awk '{print $1}'
	else
		fail "sha256sum or shasum is required"
	fi
}

atomic_link() {
	local target=$1 link=$2 tmp
	tmp="${link}.tmp.$$.$RANDOM"
	[[ ! -e "$tmp" && ! -L "$tmp" ]] || fail "temporary link already exists: $tmp"
	ln -s "$target" "$tmp"
	mv -f "$tmp" "$link"
}

install_helper() {
	local label=$1 source=${BASH_SOURCE[0]} target tmp source_sha target_sha
	[[ -f "$source" && -r "$source" ]] || fail "cannot preserve installer source: $source"
	target="$install_dir/install-versioned-$label.sh"
	source_sha=$(checksum "$source")
	if [[ -e "$target" || -L "$target" ]]; then
		[[ -f "$target" && ! -L "$target" ]] || fail "existing installer helper is not a regular file: $target"
		target_sha=$(checksum "$target")
		[[ "$source_sha" == "$target_sha" ]] || fail "installer helper for $label already exists with different contents"
	else
		tmp="${target}.tmp.$$.$RANDOM"
		[[ ! -e "$tmp" && ! -L "$tmp" ]] || fail "temporary helper already exists: $tmp"
		install -m 0755 "$source" "$tmp"
		target_sha=$(checksum "$tmp")
		[[ "$source_sha" == "$target_sha" ]] || fail "checksum changed while staging the installer helper"
		mv "$tmp" "$target"
	fi
	atomic_link "$target" "$install_dir/install-versioned.sh"
}

activate_target() {
	local target=$1 old_target=""
	validate_managed_target "$target"
	if [[ -L "$install_link" ]]; then
		old_target=$(resolve_path "$install_link") || fail "cannot resolve active target"
	elif [[ -e "$install_link" ]]; then
		fail "$install_link exists but is not a symlink; refusing to replace it"
	fi
	if [[ -n "$old_target" && "$old_target" == "$target" ]]; then
		atomic_link "$target" "$current_link"
		echo "already active: $target"
		return
	fi
	if [[ -n "$old_target" ]]; then
		validate_managed_target "$old_target"
		atomic_link "$old_target" "$previous_link"
	fi
	# The public link is the source of truth. Replace it atomically only after
	# both targets have been validated and the rollback pointer has been saved.
	atomic_link "$target" "$install_link"
	atomic_link "$target" "$current_link"
	echo "active: $target"
	if [[ -n "$old_target" ]]; then
		echo "rollback: $old_target"
	fi
}

install_version() {
	local source=$1 label=$2 target tmp manifest manifest_tmp source_sha target_sha
	validate_label "$label"
	[[ -f "$source" && -x "$source" ]] || fail "source is not an executable regular file: $source"
	mkdir -p "$install_dir" "$(dirname "$install_link")"
	target="$install_dir/sshmgr-$label"
	case "$target" in
		"$install_dir"/*) ;;
		*) fail "unexpected installation target: $target" ;;
	esac

	source_sha=$(checksum "$source")
	if [[ -e "$target" || -L "$target" ]]; then
		[[ -f "$target" && ! -L "$target" ]] || fail "existing target is not a regular file: $target"
		target_sha=$(checksum "$target")
		[[ "$source_sha" == "$target_sha" ]] || fail "version $label already exists with different contents"
	else
		tmp="${target}.tmp.$$.$RANDOM"
		[[ ! -e "$tmp" && ! -L "$tmp" ]] || fail "temporary file already exists: $tmp"
		install -m 0755 "$source" "$tmp"
		target_sha=$(checksum "$tmp")
		[[ "$source_sha" == "$target_sha" ]] || fail "checksum changed while staging the binary"
		mv "$tmp" "$target"
	fi

	manifest="${target}.manifest"
	manifest_tmp="${manifest}.tmp.$$.$RANDOM"
	{
		printf 'label=%s\n' "$label"
		printf 'path=%s\n' "$target"
		printf 'sha256=%s\n' "$source_sha"
		printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$manifest_tmp"
	chmod 0644 "$manifest_tmp"
	mv -f "$manifest_tmp" "$manifest"
	install_helper "$label"
	activate_target "$target"
}

activate_version() {
	local label=$1
	validate_label "$label"
	activate_target "$install_dir/sshmgr-$label"
}

rollback_version() {
	local target
	[[ -L "$previous_link" ]] || fail "no rollback target has been recorded"
	target=$(resolve_path "$previous_link") || fail "cannot resolve rollback target"
	validate_managed_target "$target"
	atomic_link "$target" "$install_link"
	atomic_link "$target" "$current_link"
	echo "rolled back to: $target"
}

show_status() {
	local target previous=""
	if [[ -L "$install_link" ]]; then
		target=$(resolve_path "$install_link") || fail "cannot resolve active target"
		validate_managed_target "$target"
		echo "active: $target"
		echo "sha256: $(checksum "$target")"
	elif [[ -e "$install_link" ]]; then
		fail "$install_link exists but is not a symlink"
	else
		echo "active: none"
	fi
	if [[ -L "$previous_link" ]]; then
		previous=$(resolve_path "$previous_link") || fail "cannot resolve rollback target"
		validate_managed_target "$previous"
		echo "rollback: $previous"
		echo "rollback-sha256: $(checksum "$previous")"
	else
		echo "rollback: none"
	fi
}

usage() {
	cat >&2 <<'EOF'
Usage:
  install-versioned.sh install <binary> <version-label>
  install-versioned.sh activate <version-label>
  install-versioned.sh rollback
  install-versioned.sh status

Versions are retained under /usr/local/lib/sshmgr by default. Installation and
activation never delete an older binary.
EOF
}

validate_layout
command=${1:-}
case "$command" in
	install)
		[[ $# == 3 ]] || { usage; exit 2; }
		install_version "$2" "$3"
		;;
	activate)
		[[ $# == 2 ]] || { usage; exit 2; }
		mkdir -p "$install_dir" "$(dirname "$install_link")"
		activate_version "$2"
		;;
	rollback)
		[[ $# == 1 ]] || { usage; exit 2; }
		rollback_version
		;;
	status)
		[[ $# == 1 ]] || { usage; exit 2; }
		show_status
		;;
	*)
		usage
		exit 2
		;;
esac
