package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// TestIdentityPersistence checks the generated identity's lifecycle: a fresh
// state directory holds none, a draw comes from the private ranges, and the
// persisted name reads back unchanged — identity survives restarts through the
// same persistence the trust material uses.
func TestIdentityPersistence(t *testing.T) {
	dir := t.TempDir()

	if ia, err := LoadIA(dir); err != nil || !ia.IsZero() {
		t.Fatalf("LoadIA of a fresh directory = %v (%v), want unset", ia, err)
	}

	ia, err := GenerateIA()
	if err != nil {
		t.Fatal(err)
	}
	if isd := ia.ISD(); isd < 16 || isd > 63 {
		t.Errorf("ISD = %d, want the private range [16, 63]", isd)
	}
	if as := uint64(ia.AS()); as < 0xfd0000000000 || as > 0xfdffffffffff {
		t.Errorf("AS = %x, want the private range", as)
	}

	if err := PersistIA(dir, ia); err != nil {
		t.Fatal(err)
	}
	back, err := LoadIA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(ia) {
		t.Fatalf("identity after persistence = %v, want %v", back, ia)
	}

	// The forwarding key loads and recreates beside it.
	key, err := LoadOrCreateForwardingKey(dir)
	if err != nil || len(key) == 0 {
		t.Fatalf("forwarding key = %v (%v)", key, err)
	}
	again, err := LoadOrCreateForwardingKey(dir)
	if err != nil || string(again) != string(key) {
		t.Fatalf("forwarding key after reload = %v (%v), want the same", again, err)
	}
}

// TestGenerateIADraws checks the draw varies: two draws name different ASes.
func TestGenerateIADraws(t *testing.T) {
	first, err := GenerateIA()
	if err != nil {
		t.Fatal(err)
	}
	for range 16 { // a collision of forty-bit draws is beyond unlikely
		second, err := GenerateIA()
		if err != nil {
			t.Fatal(err)
		}
		if !second.Equal(first) {
			return
		}
	}
	t.Error("repeated draws named the same ISD-AS")
}

// TestLoadOrCreateVotingMaterial checks the authoritative core's voting
// material: the loader creates the regular voting key alone — no sensitive,
// root, or CA key beside it — and the self-signed certificate over it names
// the completed ISD-AS and persists, so retries and restarts see the same
// bytes.
func TestLoadOrCreateVotingMaterial(t *testing.T) {
	dir := t.TempDir()

	key, err := LoadOrCreateVotingKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != RegularKeyFile {
		t.Fatalf("the keys directory holds %v, want %s alone", entries, RegularKeyFile)
	}
	reloaded, err := LoadOrCreateVotingKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKIXPublicKey(reloaded.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("the voting key changed across reloads")
	}

	cert, err := LoadOrCreateVotingCert(dir, joinerIA, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cppki.ExtractIA(cert.Subject); err != nil || !got.Equal(joinerIA) {
		t.Fatalf("certificate subject names %v (%v), want %v", cert.Subject, err, joinerIA)
	}
	again, err := LoadOrCreateVotingCert(dir, joinerIA, key)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Equal(cert) {
		t.Error("the voting certificate changed across reloads")
	}

	// A persisted certificate that does not match the key or the identity is
	// refused, not silently replaced.
	if _, err := LoadOrCreateVotingCert(dir, coreIA, key); err == nil {
		t.Error("a certificate naming another ISD-AS loaded")
	}
	other := t.TempDir()
	otherKey, err := LoadOrCreateVotingKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(other, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "keys", RegularVotingCertFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateVotingCert(other, joinerIA, otherKey); err == nil {
		t.Error("a certificate over another key loaded")
	}
}
