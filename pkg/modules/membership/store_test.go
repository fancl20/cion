package membership_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/membership"
)

// chainOf builds a two-certificate chain whose AS certificate names ia and
// was issued at notBefore; the second certificate stands in for the CA's.
// The store judges neither signature.
func chainOf(t *testing.T, ia addr.IA, notBefore time.Time) []*x509.Certificate {
	t.Helper()
	cert := func(subject pkix.Name) *x509.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      subject,
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(membership.Window),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	return []*x509.Certificate{
		cert(pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: cppki.OIDNameIA, Value: ia.String()},
		}}),
		cert(pkix.Name{CommonName: "CA"}),
	}
}

// TestStoreKeepsTheNewest checks the store's one rule: a membership replaces
// its ISD-AS's only when issued later, an earlier or equal one leaves it,
// and a chain that is not two certificates is refused.
func TestStoreKeepsTheNewest(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000011)
	now := time.Now().Truncate(time.Second)
	older, newer := chainOf(t, ia, now.Add(-time.Hour)), chainOf(t, ia, now)
	s := membership.NewStore()

	for _, step := range []struct {
		name  string
		chain []*x509.Certificate
		kept  bool
		held  []*x509.Certificate
	}{
		{"the first", older, true, older},
		{"a newer", newer, true, newer},
		{"an older", older, false, newer},
		{"an equal", chainOf(t, ia, now), false, newer},
	} {
		kept, err := s.Put(step.chain)
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if kept != step.kept {
			t.Errorf("%s: kept = %t, want %t", step.name, kept, step.kept)
		}
		if held := s.Get(ia); !held[0].Equal(step.held[0]) {
			t.Errorf("%s: the store holds another membership than the newest", step.name)
		}
	}
	if _, err := s.Put(newer[:1]); err == nil {
		t.Error("kept a chain of one certificate")
	}
}

// TestStorePersists checks the store's database: the memberships a store
// keeps are held again by the store reopened on its file, listed in ISD-AS
// order.
func TestStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "membership.db")
	s, err := membership.OpenStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	high, low := addr.MustIAFrom(20, 0xff0000000012), addr.MustIAFrom(20, 0xff0000000011)
	for _, ia := range []addr.IA{high, low} {
		if _, err := s.Put(chainOf(t, ia, now)); err != nil {
			t.Fatal(err)
		}
	}
	want := s.All()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := membership.OpenStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got := reopened.All()
	if len(got) != 2 || !got[0][0].Equal(want[0][0]) || !got[1][0].Equal(want[1][0]) {
		t.Fatalf("the reopened store holds %d memberships, not the two kept", len(got))
	}
	for i, ia := range []addr.IA{low, high} {
		if held, err := cppki.ExtractIA(got[i][0].Subject); err != nil || !held.Equal(ia) {
			t.Errorf("membership %d is of %s, want %s: the ISD-AS order", i, held, ia)
		}
	}
}
