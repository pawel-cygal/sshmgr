package accessplan

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func ReadSigningPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("plan signing key must be a private regular non-symlink file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse plan signing key: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch typed := value.(type) {
	case ed25519.PrivateKey:
		privateKey = typed
	case *ed25519.PrivateKey:
		if typed != nil {
			privateKey = *typed
		}
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("plan signing key must be Ed25519")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func ReadTrustedPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse trusted plan signer: %w", err)
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("trusted plan signer is not a cryptographic public key")
	}
	publicKey, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("trusted plan signer must be Ed25519")
	}
	return publicKey, nil
}

func PublicKeyLine(publicKey ed25519.PublicKey) (string, error) {
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
}
