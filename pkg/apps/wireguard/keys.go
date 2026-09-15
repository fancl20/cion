package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFile holds the node's WireGuard private key inside the application's
// state directory, hex-encoded with restrictive permissions.
const KeyFile = "wireguard.key"

// PrivateKey is the node's WireGuard (curve25519) private key, generated on
// first start and persisted in the application's own state — never in the
// configuration file.
type PrivateKey [32]byte

// PublicKey is a WireGuard peer public key.
type PublicKey [32]byte

// PublicKey derives the public key of the private key.
func (k PrivateKey) PublicKey() PublicKey {
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		// A clamped 32-byte scalar always derives a public key; the error
		// path exists only for malformed input lengths.
		return PublicKey{}
	}
	var pub PublicKey
	copy(pub[:], priv.PublicKey().Bytes())
	return pub
}

// String returns the key in the hexadecimal form IPC configuration uses.
func (k PublicKey) String() string { return hex.EncodeToString(k[:]) }

// ParsePublicKey decodes a peer public key from its hexadecimal form.
func ParsePublicKey(s string) (PublicKey, error) {
	var key PublicKey
	raw, err := hex.DecodeString(s)
	if err != nil {
		return PublicKey{}, fmt.Errorf("decoding public key: %w", err)
	}
	if len(raw) != len(key) {
		return PublicKey{}, errors.New("public key must be 32 bytes")
	}
	copy(key[:], raw)
	return key, nil
}

// LoadOrCreateKey returns the gateway's WireGuard private key, generating and
// persisting a new one on first start, following pkg/trust/keys.go's pattern
// into the application's own state directory.
func LoadOrCreateKey(stateDir string) (PrivateKey, error) {
	path := filepath.Join(stateDir, KeyFile)
	if raw, err := os.ReadFile(path); err == nil {
		return parseKey(raw, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return PrivateKey{}, err
	}
	var key PrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return PrivateKey{}, fmt.Errorf("generating key: %w", err)
	}
	// Clamped the way WireGuard clamps its scalars (RFC 7748, section 5).
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return PrivateKey{}, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key[:])), 0o600); err != nil {
		return PrivateKey{}, err
	}
	return key, nil
}

func parseKey(raw []byte, path string) (PrivateKey, error) {
	var key PrivateKey
	encoded := string(raw)
	if len(encoded) > 0 && encoded[len(encoded)-1] == '\n' {
		encoded = encoded[:len(encoded)-1]
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(decoded) != len(key) {
		return PrivateKey{}, fmt.Errorf("%s: key must be 32 bytes", path)
	}
	copy(key[:], decoded)
	return key, nil
}
