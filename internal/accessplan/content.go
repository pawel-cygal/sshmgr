package accessplan

import (
	"bytes"
	"errors"
	"strings"

	"github.com/systeampl/sshmgr/internal/access"
	"golang.org/x/crypto/ssh"
)

// ApplyContent performs the byte-oriented managed-entry edit. Every unmanaged
// line, including blank, comment, malformed, options, and newline bytes, is
// copied verbatim. A removal matches both grant marker and fingerprint.
func ApplyContent(before []byte, change FileChange) ([]byte, error) {
	if access.ContentDigest(before) != change.PreconditionSHA256 {
		return nil, errors.New("authorized_keys changed after the plan was created")
	}
	remove := map[string]Operation{}
	additions := []Operation{}
	for _, operation := range change.Operations {
		switch operation.Action {
		case "remove":
			remove[operation.Marker] = operation
		case "add":
			additions = append(additions, operation)
		default:
			return nil, errors.New("unsupported access plan operation")
		}
	}
	segments := splitLinesVerbatim(before)
	after := make([]byte, 0, len(before)+len(additions)*256)
	for _, segment := range segments {
		fingerprint, comment, ok := parsedLine(segment)
		removeLine := false
		if ok {
			for marker, operation := range remove {
				if fingerprint == operation.Fingerprint && hasMarker(comment, marker) {
					removeLine = true
					break
				}
			}
		}
		if !removeLine {
			after = append(after, segment...)
		}
	}
	for _, operation := range additions {
		if contentHasFingerprint(after, operation.Fingerprint) {
			continue
		}
		if len(after) > 0 && after[len(after)-1] != '\n' {
			after = append(after, '\n')
		}
		line := strings.TrimSpace(operation.PublicKey) + " " + operation.Marker + "\n"
		after = append(after, line...)
	}
	return after, nil
}

func splitLinesVerbatim(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	result := [][]byte{}
	for len(data) > 0 {
		index := bytes.IndexByte(data, '\n')
		if index < 0 {
			result = append(result, data)
			break
		}
		result = append(result, data[:index+1])
		data = data[index+1:]
	}
	return result
}

func parsedLine(line []byte) (fingerprint, comment string, ok bool) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] == '#' {
		return "", "", false
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey(trimmed)
	if err != nil {
		return "", "", false
	}
	return ssh.FingerprintSHA256(key), comment, true
}

func contentHasFingerprint(data []byte, wanted string) bool {
	for _, line := range splitLinesVerbatim(data) {
		fingerprint, _, ok := parsedLine(line)
		if ok && fingerprint == wanted {
			return true
		}
	}
	return false
}
