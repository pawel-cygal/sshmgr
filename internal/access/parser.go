package access

import (
	"bufio"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxAuthorizedKeyLineBytes = 1 << 20

// ParseAuthorizedKeys normalizes every non-comment entry. Malformed entries
// remain represented by their line number and parse error so a scan cannot
// silently turn an unreadable access rule into a clean result.
func ParseAuthorizedKeys(data []byte, includePublicKeys bool) ([]KeyObservation, error) {
	var observations []KeyObservation
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), maxAuthorizedKeyLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		observation := KeyObservation{Line: lineNumber}
		publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
			if err == nil {
				err = fmt.Errorf("unexpected trailing data")
			}
			observation.ParseError = err.Error()
			observations = append(observations, observation)
			continue
		}

		observation.Fingerprint = ssh.FingerprintSHA256(publicKey)
		observation.Algorithm = publicKey.Type()
		observation.Bits = publicKeyBits(publicKey)
		observation.Options = append([]string(nil), options...)
		observation.Comment = comment
		if includePublicKeys {
			observation.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
		}
		observations = append(observations, observation)
	}
	if err := scanner.Err(); err != nil {
		return observations, fmt.Errorf("authorized_keys line exceeds %d bytes: %w", maxAuthorizedKeyLineBytes, err)
	}
	return observations, nil
}

func publicKeyBits(publicKey ssh.PublicKey) int {
	if certificate, ok := publicKey.(*ssh.Certificate); ok {
		return publicKeyBits(certificate.Key)
	}
	cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch key := cryptoKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *dsa.PublicKey:
		return key.P.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}
