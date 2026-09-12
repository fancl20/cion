package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

var coreIA = addr.MustIAFrom(20, 0xff0000000001)

// newTestCoreKeys returns the core key material in dir, generated on first
// use.
func newTestCoreKeys(t *testing.T, dir string) CoreKeys {
	t.Helper()
	keys, err := LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func newTestDB(t *testing.T) DB {
	t.Helper()
	return newMemDB()
}

// genesisFixture is a DB and key material with a genesis TRC in place.
type genesisFixture struct {
	db   DB
	keys CoreKeys
	trc  cppki.SignedTRC
}

func newGenesisFixture(t *testing.T) *genesisFixture {
	t.Helper()
	dir := t.TempDir()
	db := newTestDB(t)
	keys := newTestCoreKeys(t, dir)
	trc, err := Genesis(context.Background(), db, coreIA, keys)
	if err != nil {
		t.Fatal(err)
	}
	return &genesisFixture{db: db, keys: keys, trc: trc}
}

// TestGenesis checks that genesis produces a base TRC that passes cppki
// validation with the genesis-mandated fields.
func TestGenesis(t *testing.T) {
	f := newGenesisFixture(t)
	trc := f.trc

	if have := trc.TRC.ID; have != (cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 1}) {
		t.Fatalf("TRC ID = %v, want ISD%d-B1-S1", have, coreIA.ISD())
	}
	if got := trc.TRC.GracePeriod; got != 0 {
		t.Errorf("grace period = %v, want 0", got)
	}
	if got := trc.TRC.Votes; len(got) != 0 {
		t.Errorf("votes = %v, want none", got)
	}
	if got := trc.TRC.Quorum; got != 1 {
		t.Errorf("voting quorum = %d, want 1", got)
	}
	if got := len(trc.TRC.Certificates); got != 3 {
		t.Fatalf("certificates = %d, want 3 (sensitive, regular, root)", got)
	}
	// Verify checks the payload and that every voting certificate signed.
	if err := trc.Verify(nil); err != nil {
		t.Fatalf("generated TRC does not verify: %v", err)
	}
	if got := len(trc.SignerInfos); got != 2 {
		t.Errorf("signer infos = %d, want one per voting certificate", got)
	}

	// The TRC is in the DB.
	stored, err := f.db.SignedTRC(context.Background(), trc.TRC.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Raw, trc.Raw) {
		t.Error("stored TRC differs from generated TRC")
	}
}

// TestGenesisIdempotent checks that a second genesis run returns the stored
// TRC instead of replacing it.
func TestGenesisIdempotent(t *testing.T) {
	f := newGenesisFixture(t)
	// Fresh keys would produce a different TRC; they must be ignored.
	otherKeys := newTestCoreKeys(t, t.TempDir())
	second, err := Genesis(context.Background(), f.db, coreIA, otherKeys)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.trc.Raw, second.Raw) {
		t.Error("genesis replaced an existing TRC")
	}
}

// TestGenesisTampered checks that a TRC with flipped bytes is rejected: it
// either fails to parse or fails verification.
func TestGenesisTampered(t *testing.T) {
	f := newGenesisFixture(t)
	for _, off := range []int{len(f.trc.Raw) - 1, len(f.trc.Raw) / 2, 64} {
		tampered := bytes.Clone(f.trc.Raw)
		tampered[off] ^= 0xff
		parsed, err := cppki.DecodeSignedTRC(tampered)
		if err != nil {
			continue
		}
		if err := parsed.Verify(nil); err == nil {
			t.Errorf("tampered TRC (offset %d) passed verification", off)
		}
	}
}

// TestGenesisRejectsCAInTRC checks that a CA certificate in the TRC is
// rejected, per the PKI draft's certificate list restrictions.
func TestGenesisRejectsCAInTRC(t *testing.T) {
	dir := t.TempDir()
	keys := newTestCoreKeys(t, dir)
	now := time.Now()
	sensitive, err := createVotingCert(coreIA, keys.Sensitive, true, now)
	if err != nil {
		t.Fatal(err)
	}
	regular, err := createVotingCert(coreIA, keys.Regular, false, now)
	if err != nil {
		t.Fatal(err)
	}
	root, err := createRootCert(coreIA, keys.Root, now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := createCACert(coreIA, keys.CA, root, keys.Root, now)
	if err != nil {
		t.Fatal(err)
	}
	trc := cppki.TRC{
		Version:           1,
		ID:                cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 1},
		Validity:          cppki.Validity{NotBefore: now, NotAfter: now.Add(TRCValidity)},
		Quorum:            1,
		CoreASes:          []addr.AS{coreIA.AS()},
		AuthoritativeASes: []addr.AS{coreIA.AS()},
		Certificates:      []*x509.Certificate{sensitive, regular, root, ca},
	}
	if _, err := trc.Encode(); err == nil {
		t.Fatal("encoding TRC with CA certificate succeeded, want rejection")
	}
}

// TestGenesisISDRange checks that ISDs outside the private range are
// rejected at genesis.
func TestGenesisISDRange(t *testing.T) {
	dir := t.TempDir()
	db := newTestDB(t)
	keys := newTestCoreKeys(t, dir)
	for _, isd := range []int{1, 15, 64, 4095} {
		ia := addr.MustIAFrom(addr.ISD(isd), coreIA.AS())
		if _, err := Genesis(context.Background(), db, ia, keys); err == nil {
			t.Errorf("genesis with ISD %d succeeded, want rejection", isd)
		}
	}
}

// TestLoadOrCreateCoreKeys checks that keys persist across restarts.
func TestLoadOrCreateCoreKeys(t *testing.T) {
	dir := t.TempDir()
	first := newTestCoreKeys(t, dir)
	second := newTestCoreKeys(t, dir)
	for name, keys := range map[string][2]crypto.Signer{
		"sensitive": {first.Sensitive, second.Sensitive},
		"regular":   {first.Regular, second.Regular},
		"root":      {first.Root, second.Root},
		"ca":        {first.CA, second.CA},
	} {
		a, err := x509.MarshalPKIXPublicKey(keys[0].Public())
		if err != nil {
			t.Fatal(err)
		}
		b, err := x509.MarshalPKIXPublicKey(keys[1].Public())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("key %q changed across restarts", name)
		}
	}
}

// memDB is an in-memory trust.DB for the package's own tests; importing the
// bbolt implementation from here would be an import cycle.
type memDB struct {
	mtx    sync.Mutex
	trcs   map[cppki.TRCID]cppki.SignedTRC
	chains [][]*x509.Certificate
}

func newMemDB() *memDB {
	return &memDB{trcs: make(map[cppki.TRCID]cppki.SignedTRC)}
}

func (d *memDB) Chains(ctx context.Context, q ChainQuery) ([][]*x509.Certificate, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	var out [][]*x509.Certificate
	for _, chain := range d.chains {
		if !q.IA.IsZero() {
			ia, err := cppki.ExtractIA(chain[0].Subject)
			if err != nil || !ia.Equal(q.IA) {
				continue
			}
		}
		if len(q.SubjectKeyID) != 0 && !bytes.Equal(chain[0].SubjectKeyId, q.SubjectKeyID) {
			continue
		}
		if !q.Validity.NotBefore.IsZero() || !q.Validity.NotAfter.IsZero() {
			v := cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter}
			if !v.Covers(q.Validity) {
				continue
			}
		}
		out = append(out, chain)
	}
	return out, nil
}

func (d *memDB) InsertChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	for _, existing := range d.chains {
		if existing[0].Equal(chain[0]) && existing[1].Equal(chain[1]) {
			return false, nil
		}
	}
	d.chains = append(d.chains, chain)
	return true, nil
}

func (d *memDB) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if trc, ok := d.trcs[id]; ok {
		return trc, nil
	}
	if id.Base.IsLatest() && id.Serial.IsLatest() {
		var latest cppki.SignedTRC
		for _, trc := range d.trcs {
			if trc.TRC.ID.ISD != id.ISD {
				continue
			}
			if latest.IsZero() || trc.TRC.ID.Base > latest.TRC.ID.Base ||
				(trc.TRC.ID.Base == latest.TRC.ID.Base &&
					trc.TRC.ID.Serial > latest.TRC.ID.Serial) {
				latest = trc
			}
		}
		return latest, nil
	}
	return cppki.SignedTRC{}, nil
}

func (d *memDB) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if existing, ok := d.trcs[trc.TRC.ID]; ok {
		if !bytes.Equal(existing.TRC.Raw, trc.TRC.Raw) {
			return false, fmt.Errorf("insert conflicted TRC")
		}
		return false, nil
	}
	d.trcs[trc.TRC.ID] = trc
	return true, nil
}

func (d *memDB) Close() error { return nil }
