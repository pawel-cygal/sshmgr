package access

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/systeampl/sshmgr/internal/config"
)

const externalCurrentCollectionMagic = "SSHMGR_CURRENT_COLLECTION_V1"

// externalCurrentCollectionScript inspects both fixed current-account key
// sources in one OpenSSH session. It receives no host, account, or path data;
// only a validated mode and numeric byte cap are passed as arguments. The
// script is streamed over stdin to sh -s and never changes remote state.
const externalCurrentCollectionScript = `set -u
scan_kind=${1:-}
scan_mode=${2:-}
source_limit=${3:-}
if [ "$scan_kind" != current ]; then exit 64; fi
case "$scan_mode" in metadata|content) ;; *) exit 64 ;; esac
case "$source_limit" in ''|*[!0-9]*) exit 64 ;; esac
if [ "$source_limit" -lt 1 ] || [ "$source_limit" -gt 16777216 ]; then exit 64; fi
printf 'SSHMGR_CURRENT_COLLECTION_V1\n'
inspect_source() {
  source_id=$1
  source_path=$2
  if [ ! -e "$source_path" ]; then printf 'SOURCE\t%s\tmissing\t-\t-\n' "$source_id"; return; fi
  if [ ! -f "$source_path" ]; then printf 'SOURCE\t%s\tnon-regular\t-\t-\n' "$source_id"; return; fi
  if [ ! -r "$source_path" ]; then printf 'SOURCE\t%s\tunreadable\t-\t-\n' "$source_id"; return; fi
  source_mode=$(stat -c '%a' "$source_path" 2>/dev/null || stat -f '%Lp' "$source_path" 2>/dev/null || true)
  source_size=$(wc -c < "$source_path" 2>/dev/null | tr -d '[:space:]')
  case "$source_mode" in ''|*[!0-7]*) printf 'SOURCE\t%s\tstat-error\t-\t-\n' "$source_id"; return ;; esac
  case "$source_size" in ''|*[!0-9]*) printf 'SOURCE\t%s\tstat-error\t-\t-\n' "$source_id"; return ;; esac
  if [ "$source_size" -gt "$source_limit" ]; then
    printf 'SOURCE\t%s\tsource-limit\t%s\t%s\n' "$source_id" "$source_mode" "$source_size"
    return
  fi
  if [ "$scan_mode" = content ] && ! command -v base64 >/dev/null 2>&1; then
    printf 'SOURCE\t%s\tencoder-unavailable\t%s\t%s\n' "$source_id" "$source_mode" "$source_size"
    return
  fi
  printf 'SOURCE\t%s\tfile\t%s\t%s\n' "$source_id" "$source_mode" "$source_size"
  if [ "$scan_mode" = content ]; then
    printf 'CONTENT\t%s\t' "$source_id"
    base64 < "$source_path" | tr -d '\n'
    printf '\n'
  fi
}
inspect_source 1 '.ssh/authorized_keys'
inspect_source 2 '.ssh/authorized_keys2'
printf 'END\n'
`

func externalCurrentRemoteCommand(preflight bool) string {
	mode := "content"
	if preflight {
		mode = "metadata"
	}
	return fmt.Sprintf("sh -s -- current %s %d", mode, maxAuthorizedKeysFileBytes)
}

func collectExternalCurrentSources(ctx context.Context, host config.HostConfig, includePublicKeys, preflight bool) ([]KeySource, error) {
	encodedPerSource := base64.StdEncoding.EncodedLen(maxAuthorizedKeysFileBytes)
	outputLimit := int64(encodedPerSource*len(defaultCurrentAccountSources) + 16<<10)
	data, err := runBoundedExternalInput(ctx, host, externalCurrentRemoteCommand(preflight), externalCurrentCollectionScript, outputLimit)
	if err != nil {
		return nil, err
	}
	return parseExternalCurrentCollection(data, includePublicKeys, preflight)
}

func parseExternalCurrentCollection(data []byte, includePublicKeys, preflight bool) ([]KeySource, error) {
	sources := make([]KeySource, len(defaultCurrentAccountSources))
	for index, sourcePath := range defaultCurrentAccountSources {
		sources[index] = KeySource{Type: "authorized_keys_file", Path: sourcePath}
	}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 64<<10)
	header, err := readSystemCollectionLine(reader, 4096)
	if err != nil || header != externalCurrentCollectionMagic {
		return nil, errors.New("invalid external current collection protocol header")
	}
	seenSource := make([]bool, len(sources))
	seenContent := make([]bool, len(sources))
	ended := false
	contentLineLimit := base64.StdEncoding.EncodedLen(maxAuthorizedKeysFileBytes) + 4096
	for {
		line, readErr := readSystemCollectionLine(reader, contentLineLimit)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, readErr
		}
		if line == "END" {
			ended = true
			break
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 5 && len(fields) != 3 {
			return nil, errors.New("invalid external current collection record")
		}
		id, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil || id < 1 || id > len(sources) {
			return nil, errors.New("invalid external current collection source id")
		}
		index := id - 1
		switch fields[0] {
		case "SOURCE":
			if len(fields) != 5 || seenSource[index] {
				return nil, errors.New("invalid or duplicate external current source record")
			}
			seenSource[index] = true
			if err := applyExternalCurrentSource(&sources[index], fields[2], fields[3], fields[4]); err != nil {
				return nil, err
			}
		case "CONTENT":
			if len(fields) != 3 || preflight || !seenSource[index] || seenContent[index] || !sources[index].Exists || sources[index].Error != "" {
				return nil, errors.New("unexpected external current content record")
			}
			decoded, decodeErr := base64.StdEncoding.DecodeString(fields[2])
			if decodeErr != nil {
				return nil, errors.New("invalid external current key content encoding")
			}
			if int64(len(decoded)) != sources[index].Size {
				return nil, errors.New("external current key content size mismatch")
			}
			sources[index].ContentInspected = true
			sources[index].ContentSHA256 = ContentDigest(decoded)
			entries, keyErr := ParseAuthorizedKeys(decoded, includePublicKeys)
			sources[index].Entries = entries
			if keyErr != nil {
				sources[index].Error = keyErr.Error()
			}
			seenContent[index] = true
		default:
			return nil, errors.New("unsupported external current collection record")
		}
	}
	if !ended {
		return nil, errors.New("external current collection did not terminate")
	}
	for index := range sources {
		if !seenSource[index] {
			return nil, errors.New("external current collection omitted a source")
		}
		if !preflight && sources[index].Exists && sources[index].Error == "" && !seenContent[index] {
			return nil, errors.New("external current collection omitted key content")
		}
	}
	return sources, nil
}

func applyExternalCurrentSource(source *KeySource, status, mode, size string) error {
	switch status {
	case "missing":
		if mode != "-" || size != "-" {
			return errors.New("invalid missing external current source metadata")
		}
		return nil
	case "non-regular":
		if mode != "-" || size != "-" {
			return errors.New("invalid non-regular external current source metadata")
		}
		source.Exists = true
		source.Error = "key source is not a regular file"
		return nil
	case "unreadable":
		if mode != "-" || size != "-" {
			return errors.New("invalid unreadable external current source metadata")
		}
		source.Exists = true
		source.Error = "key source is not readable"
		return nil
	case "stat-error":
		if mode != "-" || size != "-" {
			return errors.New("invalid stat-error external current source metadata")
		}
		source.Exists = true
		source.Error = "could not determine key source metadata"
		return nil
	case "file", "source-limit", "encoder-unavailable":
		source.Exists = true
	default:
		return fmt.Errorf("unsupported external current source status %q", status)
	}
	parsedMode, err := parseSystemMode(mode)
	if err != nil {
		return errors.New("invalid external current source mode")
	}
	source.Mode = parsedMode
	parsedSize, err := strconv.ParseInt(size, 10, 64)
	if err != nil || parsedSize < 0 {
		return errors.New("invalid external current source size")
	}
	source.Size = parsedSize
	switch status {
	case "source-limit":
		source.Error = fmt.Sprintf("file is %d bytes; limit is %d", parsedSize, maxAuthorizedKeysFileBytes)
	case "encoder-unavailable":
		source.Error = "remote base64 encoder is unavailable"
	}
	return nil
}
