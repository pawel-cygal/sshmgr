package access

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/systeampl/sshmgr/internal/config"
	"golang.org/x/crypto/ssh"
)

const (
	systemCollectionMagic        = "SSHMGR_SYSTEM_COLLECTION_V1"
	systemCollectionRequestMagic = "SSHMGR_SYSTEM_COLLECTION_REQUEST_V1"
	defaultMaxSourceBytes        = int64(4 << 20)
	defaultMaxTotalSourceBytes   = int64(16 << 20)
	hardMaxSourceBytes           = int64(16 << 20)
	hardMaxTotalSourceBytes      = int64(64 << 20)
	maxSystemKeySources          = 50_000
	maxCollectionMetadataBytes   = int64(8 << 20)
)

type systemCollectionTarget struct {
	ID           int
	AccountIndex int
	SourceIndex  int
}

type systemCollectionStats struct {
	SourcesInspected int
	BytesRead        int64
	ContentBudgetHit bool
}

type boundedRemoteInputRunner func(command, input string, limit int64) ([]byte, error)

// NormalizeSystemCollectionLimits resolves the bounded, per-host read budget.
// Zero means the documented default; hard caps protect both the remote host
// and the local snapshot process from an unexpectedly huge authorized_keys
// source.
func NormalizeSystemCollectionLimits(maxSourceBytes, maxTotalBytes int64) (int64, int64, error) {
	if maxSourceBytes == 0 {
		maxSourceBytes = defaultMaxSourceBytes
	}
	if maxTotalBytes == 0 {
		maxTotalBytes = defaultMaxTotalSourceBytes
	}
	if maxSourceBytes < 1 || maxSourceBytes > hardMaxSourceBytes {
		return 0, 0, fmt.Errorf("--max-source-mib must resolve to between 1 byte and %d MiB", hardMaxSourceBytes>>20)
	}
	if maxTotalBytes < 1 || maxTotalBytes > hardMaxTotalSourceBytes {
		return 0, 0, fmt.Errorf("--max-total-mib must resolve to between 1 byte and %d MiB", hardMaxTotalSourceBytes>>20)
	}
	if maxSourceBytes > maxTotalBytes {
		return 0, 0, errors.New("per-source read limit cannot exceed the per-host total read limit")
	}
	return maxSourceBytes, maxTotalBytes, nil
}

// ScanSystem discovers effective static AuthorizedKeysFile sources and then
// inspects them through the already-established root/sudo-n channel. It never
// invokes AuthorizedKeysCommand, follows symlinked key sources, or changes a
// remote file.
func ScanSystem(ctx context.Context, cfg *config.Config, aliases []string, options ScanOptions) *Snapshot {
	options.Preflight = false
	mode, accounts, accountLimit, err := NormalizeSystemAccountSelection(options.AccountMode, options.Accounts, options.MaxAccounts)
	if err == nil {
		options.MaxSourceBytes, options.MaxTotalBytes, err = NormalizeSystemCollectionLimits(options.MaxSourceBytes, options.MaxTotalBytes)
	}
	if err != nil {
		return scanWith(ctx, cfg, aliases, "system", options, func(_ context.Context, _ *config.Config, alias string, _ ScanOptions) HostSnapshot {
			return failedHost(alias, nil, "system-selection", err, 0)
		})
	}
	options.AccountMode = mode
	options.Accounts = accounts
	options.MaxAccounts = accountLimit
	return scanWith(ctx, cfg, aliases, "system", options, collectSystemKeyHost)
}

func buildSystemCollectionRequest(accounts []AccountSnapshot) (string, []systemCollectionTarget, int, bool) {
	var request strings.Builder
	request.WriteString(systemCollectionRequestMagic)
	request.WriteByte('\n')
	targets := make([]systemCollectionTarget, 0)
	total := 0
	truncated := false
	for accountIndex := range accounts {
		for sourceIndex := range accounts[accountIndex].Sources {
			source := &accounts[accountIndex].Sources[sourceIndex]
			if source.Type != "authorized_keys_file" {
				continue
			}
			total++
			if len(targets) >= maxSystemKeySources {
				truncated = true
				source.Error = fmt.Sprintf("source count exceeds the per-host safety limit of %d", maxSystemKeySources)
				continue
			}
			if !path.IsAbs(source.Path) || !validSystemAccountField(source.Path, 16<<10) || strings.ContainsRune(source.Path, '\t') {
				source.Error = "expanded key source path is not a safe absolute path"
				continue
			}
			target := systemCollectionTarget{ID: len(targets) + 1, AccountIndex: accountIndex, SourceIndex: sourceIndex}
			targets = append(targets, target)
			fmt.Fprintf(&request, "%d\t%s\n", target.ID, source.Path)
		}
	}
	request.WriteString("END\n")
	return request.String(), targets, total, truncated
}

// systemCollectionScript is executed as a fixed sh -c program. Untrusted
// source paths arrive only through stdin and are used exclusively as quoted
// file operands. The collector is read-only and refuses symlinked files or
// any source path with a symlinked ancestor.
const systemCollectionScript = `set -u
source_limit=$1
total_limit=$2
tab=$(printf '\t')
emit_source() { printf 'SOURCE\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"; }
printf 'SSHMGR_SYSTEM_COLLECTION_V1\n'
if ! IFS= read -r request_header || [ "$request_header" != 'SSHMGR_SYSTEM_COLLECTION_REQUEST_V1' ]; then exit 64; fi
total_read=0
budget_hit=false
while IFS="$tab" read -r source_id source_path extra; do
  if [ "$source_id" = END ]; then break; fi
  case "$source_id" in ''|*[!0-9]*) exit 64 ;; esac
  if [ -z "$source_path" ] || [ -n "${extra:-}" ]; then emit_source "$source_id" invalid - - - - missing - - -; continue; fi
  case "$source_path" in /*) ;; *) emit_source "$source_id" invalid - - - - missing - - -; continue ;; esac

  parent_path=${source_path%/*}
  if [ -z "$parent_path" ]; then parent_path=/; fi
  ancestor_symlink=false
  walk_path=$source_path
  while [ "$walk_path" != / ]; do
    walk_path=${walk_path%/*}
    if [ -z "$walk_path" ]; then walk_path=/; fi
    if [ -L "$walk_path" ]; then ancestor_symlink=true; break; fi
  done

  parent_status=missing
  parent_mode=-
  parent_uid=-
  parent_gid=-
  if [ -L "$parent_path" ]; then
    parent_status=symlink
  elif [ -d "$parent_path" ]; then
    parent_meta=$(stat -c '%a %u %g' "$parent_path" 2>/dev/null || stat -f '%Lp %u %g' "$parent_path" 2>/dev/null || true)
    set -- $parent_meta
    if [ "$#" -eq 3 ]; then parent_status=directory; parent_mode=$1; parent_uid=$2; parent_gid=$3; else parent_status=stat-error; fi
  elif [ -e "$parent_path" ]; then
    parent_status=non-directory
  fi

  if [ -L "$source_path" ]; then emit_source "$source_id" symlink - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  if [ ! -e "$source_path" ]; then emit_source "$source_id" missing - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  if [ "$ancestor_symlink" = true ]; then emit_source "$source_id" ancestor-symlink - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  if [ ! -f "$source_path" ]; then emit_source "$source_id" non-regular - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  if [ ! -r "$source_path" ]; then emit_source "$source_id" unreadable - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi

  file_meta=$(stat -c '%a %u %g %s' "$source_path" 2>/dev/null || stat -f '%Lp %u %g %z' "$source_path" 2>/dev/null || true)
  set -- $file_meta
  if [ "$#" -ne 4 ]; then emit_source "$source_id" stat-error - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  file_mode=$1
  file_uid=$2
  file_gid=$3
  file_size=$4
  case "$file_size" in ''|*[!0-9]*) emit_source "$source_id" stat-error - - - - "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue ;; esac
  if [ "$file_size" -gt "$source_limit" ]; then emit_source "$source_id" source-limit "$file_mode" "$file_uid" "$file_gid" "$file_size" "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  remaining=$((total_limit - total_read))
  if [ "$file_size" -gt "$remaining" ]; then budget_hit=true; emit_source "$source_id" total-limit "$file_mode" "$file_uid" "$file_gid" "$file_size" "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi
  if ! command -v base64 >/dev/null 2>&1; then emit_source "$source_id" encoder-unavailable "$file_mode" "$file_uid" "$file_gid" "$file_size" "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"; continue; fi

  emit_source "$source_id" file "$file_mode" "$file_uid" "$file_gid" "$file_size" "$parent_status" "$parent_mode" "$parent_uid" "$parent_gid"
  printf 'CONTENT\t%s\t' "$source_id"
  base64 < "$source_path" | tr -d '\n'
  printf '\n'
  total_read=$((total_read + file_size))
done
printf 'CAP\ttotal_read\t%s\n' "$total_read"
printf 'CAP\tbudget_hit\t%s\n' "$budget_hit"
printf 'END\n'
`

func systemCollectionRemoteCommand(options ScanOptions, useSudo bool) string {
	prefix := ""
	if useSudo {
		prefix = "sudo -n "
	}
	return fmt.Sprintf("%ssh -c %s sshmgr-system-collection %d %d", prefix,
		quoteShellArgument(systemCollectionScript), options.MaxSourceBytes, options.MaxTotalBytes)
}

func collectSystemKeySources(client *ssh.Client, accounts []AccountSnapshot, options ScanOptions) (systemCollectionStats, int, bool, error) {
	return collectSystemKeySourcesWith(accounts, options, func(command, input string, limit int64) ([]byte, error) {
		return runBoundedSSHInput(client, command, input, limit)
	})
}

func collectSystemKeySourcesWith(accounts []AccountSnapshot, options ScanOptions, run boundedRemoteInputRunner) (systemCollectionStats, int, bool, error) {
	request, targets, requested, truncated := buildSystemCollectionRequest(accounts)
	if len(targets) == 0 {
		return systemCollectionStats{}, requested, truncated, nil
	}
	command := systemCollectionRemoteCommand(options, options.UseSudo)
	outputLimit := base64.StdEncoding.EncodedLen(int(options.MaxTotalBytes))
	maxOutput := int64(outputLimit) + int64(len(targets))*160 + maxCollectionMetadataBytes
	data, err := run(command, request, maxOutput)
	if err != nil {
		return systemCollectionStats{}, requested, truncated, err
	}
	stats, err := applySystemCollection(data, accounts, targets, options.IncludePublicKeys, options.MaxSourceBytes)
	return stats, requested, truncated, err
}

func applySystemCollection(data []byte, accounts []AccountSnapshot, targets []systemCollectionTarget, includePublicKeys bool, maxSourceBytes int64) (systemCollectionStats, error) {
	targetByID := make(map[int]systemCollectionTarget, len(targets))
	for _, target := range targets {
		targetByID[target.ID] = target
	}
	seen := make(map[int]bool, len(targets))
	reader := bufio.NewReaderSize(bytes.NewReader(data), 64<<10)
	header, err := readSystemCollectionLine(reader, 4096)
	if err != nil || header != systemCollectionMagic {
		return systemCollectionStats{}, errors.New("invalid system collection protocol header")
	}
	stats := systemCollectionStats{}
	ended := false
	seenTotalRead := false
	seenBudgetState := false
	observedBudgetLimit := false
	for {
		line, err := readSystemCollectionLine(reader, int(maxSourceBytes*2)+4096)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return stats, err
		}
		if line == "END" {
			ended = true
			break
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 && (len(fields) == 0 || fields[0] == "CAP") {
			return stats, errors.New("invalid system collection capability record")
		}
		if len(fields) == 3 && fields[0] == "CAP" {
			switch fields[1] {
			case "total_read":
				if seenTotalRead {
					return stats, errors.New("duplicate system collection byte count")
				}
				seenTotalRead = true
				remoteBytes, parseErr := strconv.ParseInt(fields[2], 10, 64)
				if parseErr != nil || remoteBytes < 0 || remoteBytes > hardMaxTotalSourceBytes {
					return stats, errors.New("invalid system collection byte count")
				}
				if remoteBytes != stats.BytesRead {
					return stats, errors.New("system collection byte count mismatch")
				}
			case "budget_hit":
				if seenBudgetState {
					return stats, errors.New("duplicate system collection budget state")
				}
				seenBudgetState = true
				if fields[2] != "true" && fields[2] != "false" {
					return stats, errors.New("invalid system collection budget state")
				}
				stats.ContentBudgetHit = fields[2] == "true"
			}
			continue
		}
		if len(fields) != 11 || fields[0] != "SOURCE" {
			return stats, errors.New("invalid system collection source record")
		}
		id, parseErr := strconv.Atoi(fields[1])
		target, ok := targetByID[id]
		if parseErr != nil || !ok || seen[id] {
			return stats, errors.New("invalid or duplicate system collection source id")
		}
		seen[id] = true
		source := &accounts[target.AccountIndex].Sources[target.SourceIndex]
		status := fields[2]
		if status == "total-limit" {
			observedBudgetLimit = true
		}
		if err := applySystemSourceMetadata(source, status, fields[3:]); err != nil {
			return stats, err
		}
		if status != "file" {
			continue
		}
		contentLine, err := readSystemCollectionLine(reader, base64.StdEncoding.EncodedLen(int(maxSourceBytes))+128)
		if err != nil {
			return stats, errors.New("incomplete system collection content record")
		}
		prefix := "CONTENT\t" + strconv.Itoa(id) + "\t"
		if !strings.HasPrefix(contentLine, prefix) {
			return stats, errors.New("system collection content does not match its source")
		}
		content, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(contentLine, prefix))
		if err != nil {
			return stats, errors.New("invalid base64 in system collection content")
		}
		// The remote budget is charged from the metadata size captured before
		// reading. Keep the same accounting even if the file changes between
		// stat and read; that source is then retained as uninspected evidence.
		stats.BytesRead += source.Size
		if int64(len(content)) != source.Size {
			source.Error = fmt.Sprintf("source changed during inspection: metadata size %d, content size %d", source.Size, len(content))
			continue
		}
		source.ContentInspected = true
		source.ContentSHA256 = ContentDigest(content)
		entries, parseErr := ParseAuthorizedKeys(content, includePublicKeys)
		source.Entries = entries
		if parseErr != nil {
			source.Error = parseErr.Error()
		}
		stats.SourcesInspected++
	}
	if !ended {
		return stats, errors.New("system collection protocol is incomplete")
	}
	if len(seen) != len(targets) {
		return stats, errors.New("system collection omitted one or more requested sources")
	}
	if !seenTotalRead || !seenBudgetState {
		return stats, errors.New("system collection protocol is missing final accounting")
	}
	if stats.ContentBudgetHit != observedBudgetLimit {
		return stats, errors.New("system collection budget state does not match source records")
	}
	return stats, nil
}

func applySystemSourceMetadata(source *KeySource, status string, fields []string) error {
	if len(fields) != 8 {
		return errors.New("invalid system collection metadata field count")
	}
	mode, uid, gid, size := fields[0], fields[1], fields[2], fields[3]
	parentStatus, parentMode, parentUID, parentGID := fields[4], fields[5], fields[6], fields[7]
	source.ParentPath = path.Dir(source.Path)
	if parentStatus == "symlink" {
		source.AncestorSymlink = true
	} else if parentStatus == "directory" {
		var err error
		if source.ParentMode, err = parseSystemMode(parentMode); err != nil {
			return err
		}
		if source.ParentOwnerUID, err = parseSystemID(parentUID); err != nil {
			return err
		}
		if source.ParentOwnerGID, err = parseSystemID(parentGID); err != nil {
			return err
		}
	}

	switch status {
	case "missing":
		return nil
	case "symlink":
		source.Exists = true
		source.Symlink = true
		source.Error = "symlinked authorized_keys source was not followed"
		return nil
	case "ancestor-symlink":
		source.Exists = true
		source.AncestorSymlink = true
		source.Error = "authorized_keys source with a symlinked ancestor was not followed"
		return nil
	case "invalid":
		source.Error = "collector rejected an invalid source path"
		return nil
	case "non-regular":
		source.Exists = true
		source.Error = "key source is not a regular file"
		return nil
	case "unreadable":
		source.Exists = true
		source.Error = "key source is not readable"
		return nil
	case "stat-error":
		source.Exists = true
		source.Error = "could not stat key source"
		return nil
	case "source-limit", "total-limit", "encoder-unavailable", "file":
		source.Exists = true
	default:
		return fmt.Errorf("unsupported system collection source status %q", status)
	}
	var err error
	if source.Mode, err = parseSystemMode(mode); err != nil {
		return err
	}
	if source.OwnerUID, err = parseSystemID(uid); err != nil {
		return err
	}
	if source.OwnerGID, err = parseSystemID(gid); err != nil {
		return err
	}
	if source.Size, err = strconv.ParseInt(size, 10, 64); err != nil || source.Size < 0 {
		return errors.New("invalid system collection source size")
	}
	switch status {
	case "source-limit":
		source.Error = "key source exceeds the per-file read budget"
	case "total-limit":
		source.Error = "key source exceeds the remaining per-host read budget"
	case "encoder-unavailable":
		source.Error = "remote base64 encoder is unavailable"
	}
	return nil
}

func parseSystemMode(value string) (string, error) {
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || parsed > 0o7777 {
		return "", errors.New("invalid system collection file mode")
	}
	return fmt.Sprintf("%04o", parsed), nil
}

func parseSystemID(value string) (*uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return nil, errors.New("invalid system collection owner id")
	}
	return &parsed, nil
}

func readSystemCollectionLine(reader *bufio.Reader, limit int) (string, error) {
	line, err := reader.ReadString('\n')
	if len(line) > limit {
		return "", fmt.Errorf("system collection record exceeds %d bytes", limit)
	}
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func runBoundedSSHInput(client *ssh.Client, command, input string, limit int64) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("open system collection session failed")
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, errors.New("open system collection output failed")
	}
	session.Stdin = strings.NewReader(input)
	stderr := &cappedBuffer{limit: 8192}
	session.Stderr = stderr
	if err := session.Start(command); err != nil {
		return nil, errors.New("remote server rejected the system collection request")
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(data)) > limit {
		_ = session.Close()
		_ = session.Wait()
		return nil, fmt.Errorf("system collection output exceeds %d bytes", limit)
	}
	waitErr := session.Wait()
	if readErr != nil {
		return nil, errors.New("read system collection output failed")
	}
	if waitErr != nil {
		return nil, errors.New("system collection command returned a non-zero status")
	}
	return data, nil
}
