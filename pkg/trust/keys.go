package trust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Names of the key files inside the state directory's keys folder. All keys
// are ECDSA P-256, the curve all SCION signature algorithms build on.
const (
	// ASKeyFile holds the AS key that certifies control-plane messages.
	ASKeyFile = "cp-as.key"
	// SensitiveKeyFile holds the sensitive voting key of the founding core.
	SensitiveKeyFile = "sensitive-voting.key"
	// RegularKeyFile holds the regular voting key of the founding core, and
	// of an authoritative core beside it — a node is one tier or the other
	// for its lifetime, never both.
	RegularKeyFile = "regular-voting.key"
	// RegularVotingCertFile holds the self-signed regular voting certificate
	// of an authoritative core, created once its provisional identity
	// completes so retries, restarts, and operators all see the same bytes.
	RegularVotingCertFile = "regular-voting.crt"
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

// IAFile holds the node's ISD-AS in the state directory's root;
// ForwardingKeyFile holds the forwarding key beside the AS keys. Both are
// generated on first start and persisted for the node's lifetime.
const (
	// IAFile is the node's ISD-AS, one line, e.g. "20-fd00:0:123".
	IAFile = "ia"
	// ForwardingKeyFile holds the hex-encoded forwarding key MACing the
	// node's own hop fields.
	ForwardingKeyFile = "fwd.key"
)

// LoadIA returns the persisted ISD-AS, the zero one when none is persisted
// yet — a first start.
func LoadIA(stateDir string) (addr.IA, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, IAFile))
	if errors.Is(err, os.ErrNotExist) {
		return addr.IA(0), nil
	}
	if err != nil {
		return addr.IA(0), err
	}
	ia, err := addr.ParseIA(strings.TrimSpace(string(raw)))
	if err != nil {
		return addr.IA(0), err
	}
	return ia, nil
}

// GenerateIA draws an ISD-AS from the private ranges: ISD from the private
// ISD range and AS from the private AS range (control plane draft,
// Section 1.5.1). The draw is provisional until persisted — a joiner's ISD
// completes with the network's.
func GenerateIA() (addr.IA, error) {
	isd := make([]byte, 8)
	as := make([]byte, 8)
	if _, err := rand.Read(isd); err != nil {
		return addr.IA(0), err
	}
	if _, err := rand.Read(as); err != nil {
		return addr.IA(0), err
	}
	return addr.IAFrom(addr.ISD(minPrivateISD+
		binary.BigEndian.Uint64(isd)%uint64(maxPrivateISD-minPrivateISD+1)),
		addr.AS(0xfd0000000000|binary.BigEndian.Uint64(as)&0xffffffffff))
}

// LoadOrCreateForwardingKey returns the node's forwarding key, generating and
// persisting a new one on first start. The key MACs only the node's own hop
// fields, so it needs no coordination.
func LoadOrCreateForwardingKey(stateDir string) ([]byte, error) {
	path := filepath.Join(keyDir(stateDir), ForwardingKeyFile)
	if raw, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(key) == 0 {
			return nil, fmt.Errorf("%s: key must not be empty", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(keyDir(stateDir), 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(path, []byte(hex.EncodeToString(key)+"\n")); err != nil {
		return nil, err
	}
	return key, nil
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

// LoadOrCreateVotingKey returns the authoritative core's regular voting key,
// generating and persisting it on first start. It occupies the file the
// founder's regular voting key occupies — the tiers never share a state
// directory — and nothing else is created: no sensitive, root, or CA key.
func LoadOrCreateVotingKey(stateDir string) (crypto.Signer, error) {
	return loadOrCreateKey(keyDir(stateDir), RegularKeyFile)
}

// LoadOrCreateVotingCert returns the authoritative core's self-signed regular
// voting certificate, minting and persisting it beside the key when none is
// persisted yet. The certificate names the completed ISD-AS, so it is created
// only after the provisional identity completes; a persisted certificate that
// does not match the key or name the ISD-AS is refused, not silently replaced.
func LoadOrCreateVotingCert(
	stateDir string,
	ia addr.IA,
	key crypto.Signer,
) (*x509.Certificate, error) {

	path := filepath.Join(keyDir(stateDir), RegularVotingCertFile)
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s: no PEM block", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := checkVotingCert(cert, ia, key); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return cert, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Whole seconds and the signing backdate, the genesis certificates'
	// own shape, so the certificate covers the successor TRC's validity from
	// its first second.
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	cert, err := createVotingCert(ia, key, false, now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(keyDir(stateDir), 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(path, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})); err != nil {
		return nil, err
	}
	return cert, nil
}

// checkVotingCert checks that the persisted voting certificate is the regular
// shape naming the ISD-AS over the key's public half.
func checkVotingCert(cert *x509.Certificate, ia addr.IA, key crypto.Signer) error {
	if ct, err := cppki.ValidateCert(cert); err != nil || ct != cppki.Regular {
		return fmt.Errorf("not a regular voting certificate")
	}
	if certIA, err := cppki.ExtractIA(cert.Subject); err != nil || !certIA.Equal(ia) {
		return fmt.Errorf("certificate names %s, want %s", cert.Subject, ia)
	}
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(cert.SubjectKeyId, skid) {
		return fmt.Errorf("certificate does not cover the voting key")
	}
	return nil
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
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := persistKey(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// generateKey mints a fresh ECDSA P-256 signing key, the curve all SCION
// signature algorithms build on.
func generateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

// generateCoreKeys mints the founding core's four fresh keys in memory alone:
// the rotation's staged set, persisted only once the successor carrying its
// certificates is pinned.
func generateCoreKeys() (CoreKeys, error) {
	sensitive, err := generateKey()
	if err != nil {
		return CoreKeys{}, err
	}
	regular, err := generateKey()
	if err != nil {
		return CoreKeys{}, err
	}
	root, err := generateKey()
	if err != nil {
		return CoreKeys{}, err
	}
	ca, err := generateKey()
	if err != nil {
		return CoreKeys{}, err
	}
	return CoreKeys{Sensitive: sensitive, Regular: regular, Root: root, CA: ca}, nil
}

// persistKey writes the key under path, replacing whatever file held the
// predecessor.
func persistKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeFile(path, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: der},
	))
}

// PersistCoreKeys replaces the founding core's persisted key material as a
// set — the rotation's completed pin landing on disk, the fresh voting and
// root keys beside the CA key rotating with them. A crash ahead of the
// replacement leaves the predecessor's keys serving, and the next pass rolls
// again; nothing references the fresh keys until the TRC carrying their
// certificates is pinned.
func PersistCoreKeys(stateDir string, keys CoreKeys) error {
	dir := keyDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, entry := range []struct {
		file string
		key  crypto.Signer
	}{
		{SensitiveKeyFile, keys.Sensitive},
		{RegularKeyFile, keys.Regular},
		{RootKeyFile, keys.Root},
		{CAKeyFile, keys.CA},
	} {
		if err := persistKey(filepath.Join(dir, entry.file), entry.key); err != nil {
			return fmt.Errorf("%s: %w", entry.file, err)
		}
	}
	return nil
}

// PersistVotingPair replaces the authoritative core's persisted voting pair,
// the fresh certificate beside the fresh key exactly as the joiner's first
// pair persisted.
func PersistVotingPair(stateDir string, key crypto.Signer, cert *x509.Certificate) error {
	dir := keyDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := persistKey(filepath.Join(dir, RegularKeyFile), key); err != nil {
		return err
	}
	return writeFile(votingCertPath(stateDir), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
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

// PersistIA rewrites the persisted ISD-AS — the completion of a joiner's
// identity, whose first ISD was a provisional draw replaced by the network's
// once a neighbor answered.
func PersistIA(stateDir string, ia addr.IA) error {
	return writeFile(filepath.Join(stateDir, IAFile), []byte(ia.String()+"\n"))
}
