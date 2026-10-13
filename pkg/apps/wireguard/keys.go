package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/fancl20/cion/pkg/libs/statefile"
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
		panic(fmt.Sprintf("deriving the public key: %v", err))
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

// LoadOrCreateKey returns the application's WireGuard private key, generating
// and persisting a new one on first start in the application's own state
// directory.
func LoadOrCreateKey(stateDir string) (PrivateKey, error) {
	return statefile.LoadOrCreate(filepath.Join(stateDir, KeyFile), parseKey,
		func() (PrivateKey, []byte, error) {
			var key PrivateKey
			if _, err := rand.Read(key[:]); err != nil {
				return PrivateKey{}, nil, fmt.Errorf("generating key: %w", err)
			}
			// Clamped the way WireGuard clamps its scalars (RFC 7748,
			// section 5).
			key[0] &= 248
			key[31] = (key[31] & 127) | 64
			return key, []byte(hex.EncodeToString(key[:])), nil
		})
}

func parseKey(raw []byte) (PrivateKey, error) {
	var key PrivateKey
	encoded := string(raw)
	if len(encoded) > 0 && encoded[len(encoded)-1] == '\n' {
		encoded = encoded[:len(encoded)-1]
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return PrivateKey{}, err
	}
	if len(decoded) != len(key) {
		return PrivateKey{}, errors.New("key must be 32 bytes")
	}
	copy(key[:], decoded)
	return key, nil
}
