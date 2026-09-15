package wireguard

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateKeyPersists(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A clamped curve25519 scalar carries the clamp marks.
	if key[0]&7 != 0 || key[31]&128 != 0 || key[31]&64 == 0 {
		t.Errorf("key is not clamped: %x", key)
	}
	again, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if key != again {
		t.Error("reloading the state directory produced a different key")
	}
	if _, err := LoadOrCreateKey(filepath.Join(dir, "nested")); err != nil {
		t.Fatalf("creating a nested state directory: %v", err)
	}
}

func TestPublicKeyDerivation(t *testing.T) {
	// A private key of all clamped bytes derives the public key Go's X25519
	// and wireguard-go agree on: the base point multiplication of the
	// clamped scalar.
	var key PrivateKey
	for i := range key {
		key[i] = 0xff
	}
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	pub := key.PublicKey()
	if pub == (PublicKey{}) {
		t.Fatal("derived the zero public key")
	}
	if pub == PublicKey(key) {
		t.Error("public key equals the private key")
	}
	if parsed, err := ParsePublicKey(pub.String()); err != nil || parsed != pub {
		t.Errorf("public key %s did not round-trip: %v", pub, err)
	}
	if _, err := ParsePublicKey("nothex"); err == nil {
		t.Error("parsing garbage as a public key succeeded")
	}
	if _, err := ParsePublicKey("0102"); err == nil {
		t.Error("parsing a short public key succeeded")
	}
}
