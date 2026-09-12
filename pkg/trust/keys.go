package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Names of the key files inside the state directory's keys folder. All keys
// are ECDSA P-256, the curve all SCION signature algorithms build on.
const (
	// ASKeyFile holds the AS key that certifies control-plane messages.
	ASKeyFile = "cp-as.key"
	// SensitiveKeyFile holds the sensitive voting key of the founding core.
	SensitiveKeyFile = "sensitive-voting.key"
	// RegularKeyFile holds the regular voting key of the founding core.
	RegularKeyFile = "regular-voting.key"
	// RootKeyFile holds the CP root key of the founding core. It signs CP
	// CA certificates and is part of the TRC's anchor set.
	RootKeyFile = "cp-root.key"
	// CAKeyFile holds the CP CA key of the founding core. It signs AS
	// certificates; the matching certificate is never placed in the TRC.
	CAKeyFile = "cp-ca.key"
)

// CoreKeys is the key material of the founding core.
type CoreKeys struct {
	// Sensitive signs TRC updates with the sensitive voting certificate.
	Sensitive crypto.Signer
	// Regular signs TRC updates with the regular voting certificate.
	Regular crypto.Signer
	// Root signs CP CA certificates.
	Root crypto.Signer
	// CA signs AS certificate chains.
	CA crypto.Signer
}

// LoadOrCreateASKey returns the node's AS key, generating and persisting a
// new one on first start. Keys live in the keys subdirectory of the state
// directory, created if needed.
func LoadOrCreateASKey(stateDir string) (crypto.Signer, error) {
	return loadOrCreateKey(keyDir(stateDir), ASKeyFile)
}

// LoadOrCreateCoreKeys returns the founding core's key material, generating
// and persisting any missing keys on first start.
func LoadOrCreateCoreKeys(stateDir string) (CoreKeys, error) {
	dir := keyDir(stateDir)
	sensitive, err := loadOrCreateKey(dir, SensitiveKeyFile)
	if err != nil {
		return CoreKeys{}, fmt.Errorf("sensitive voting key: %w", err)
	}
	regular, err := loadOrCreateKey(dir, RegularKeyFile)
	if err != nil {
		return CoreKeys{}, fmt.Errorf("regular voting key: %w", err)
	}
	root, err := loadOrCreateKey(dir, RootKeyFile)
	if err != nil {
		return CoreKeys{}, fmt.Errorf("CP root key: %w", err)
	}
	ca, err := loadOrCreateKey(dir, CAKeyFile)
	if err != nil {
		return CoreKeys{}, fmt.Errorf("CP CA key: %w", err)
	}
	return CoreKeys{Sensitive: sensitive, Regular: regular, Root: root, CA: ca}, nil
}

func keyDir(stateDir string) string {
	return filepath.Join(stateDir, "keys")
}

// loadOrCreateKey returns the private key stored under dir/name, generating
// and persisting a new ECDSA P-256 key if the file does not exist yet.
func loadOrCreateKey(dir, name string) (crypto.Signer, error) {
	path := filepath.Join(dir, name)
	if raw, err := os.ReadFile(path); err == nil {
		return parseKey(raw, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(path, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: der},
	)); err != nil {
		return nil, err
	}
	return key, nil
}

func parseKey(raw []byte, path string) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: key of type %T is not a signer", path, key)
	}
	return signer, nil
}

// writeFile creates or replaces the file with restrictive permissions, so a
// fresh key never appears world-readable even for a moment.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
