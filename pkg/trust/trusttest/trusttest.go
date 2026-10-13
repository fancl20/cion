// Package trusttest founds an ISD for other packages' tests: a founding
// core's keys in a temporary directory, its genesis TRC pinned in the
// caller's trust database, its issuer, and the enrollment of ISD-ASes under
// it. A test-support library: the caller opens the database, for no library
// imports a module's implementation, and pkg/trust's in-package tests cannot
// import it, for it imports pkg/trust.
package trusttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
)

// Founder is a founding core's trust material.
type Founder struct {
	IA addr.IA
	// Dir is the state directory whose keys folder holds the core keys.
	Dir    string
	DB     trustdb.DB
	Keys   trust.CoreKeys
	TRC    cppki.SignedTRC
	Issuer *trust.Issuer
}

// NewFounder founds ia's ISD on db: the core keys in a fresh temporary
// directory, the genesis TRC naming the fellow cores beside ia pinned in db,
// and the issuer.
func NewFounder(t testing.TB, db trustdb.DB, ia addr.IA, fellows ...addr.IA) *Founder {
	t.Helper()
	dir := t.TempDir()
	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(t.Context(), db, ia, keys, fellows...)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(ia, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	return &Founder{IA: ia, Dir: dir, DB: db, Keys: keys, TRC: trc, Issuer: issuer}
}

// Enroll issues ia a chain over a fresh key and inserts the chain into the
// founder's database, returning the key and the chain.
func (f *Founder) Enroll(t testing.TB, ia addr.IA) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := f.Issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.DB.InsertChain(t.Context(), chain); err != nil {
		t.Fatal(err)
	}
	return key, chain
}

// Engine enrolls ia and returns its engine over the founder's database.
func (f *Founder) Engine(t testing.TB, ia addr.IA) *trust.Engine {
	t.Helper()
	key, _ := f.Enroll(t, ia)
	return trust.NewEngine(ia, key, &trust.NetworkProvider{DB: f.DB})
}
