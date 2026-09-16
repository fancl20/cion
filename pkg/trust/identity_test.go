package trust

import (
	"testing"
)

// TestIdentityPersistence checks the generated identity's lifecycle: a fresh
// state directory holds none, a draw comes from the private ranges, and the
// persisted name reads back unchanged — identity survives restarts through
// the same persistence the trust material uses (ADR-0006).
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
