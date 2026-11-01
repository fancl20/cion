package founder_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/modules/membership"
	"github.com/fancl20/cion/pkg/modules/membership/impl/founder"
	"github.com/fancl20/cion/pkg/modules/membership/impl/membershiptest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

// The tests' ISD-ASes: the founder, another core, a checking node, and the
// nodes it judges.
var (
	founderIA  = addr.MustIAFrom(20, 0xff0000000001)
	otherIA    = addr.MustIAFrom(20, 0xff0000000002)
	checkerIA  = addr.MustIAFrom(20, 0xff0000000010)
	nodeIA     = addr.MustIAFrom(20, 0xff0000000011)
	unadmitted = addr.MustIAFrom(20, 0xff0000000099)
)

// openDB opens a fresh trust database, closed when the test ends.
func openDB(t *testing.T) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newFounder builds the founder method over env.
func newFounder(env membership.Env) membership.Method { return founder.New(env) }

// TestContract runs the membership contract suite against the founder
// method.
func TestContract(t *testing.T) {
	membershiptest.Run(t, newFounder, openDB)
}

// TestWindowIsTheASValidity checks that the membership window is the AS
// certificate validity, so the memberships of the nodes renewing on time lie
// within it of each other.
func TestWindowIsTheASValidity(t *testing.T) {
	if membership.Window != trust.ASValidity {
		t.Errorf("window = %v, want the AS validity %v", membership.Window, trust.ASValidity)
	}
}

// fixture is a founded ISD beside another core's issuer, whose chains no
// founder root certifies: the issuer of a node's chain after the founder's
// first, or a leaked key's.
type fixture struct {
	founder *trusttest.Founder
	other   *trusttest.Founder
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	return fixture{
		founder: trusttest.NewFounder(t, openDB(t), founderIA),
		other:   trusttest.NewFounder(t, openDB(t), otherIA),
	}
}

// issue issues ia a chain for key at the issuer.
func issue(t *testing.T, issuer *trust.Issuer, ia addr.IA, key crypto.Signer) []*x509.Certificate {
	t.Helper()
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// newKey returns a fresh AS key.
func newKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// handshake returns the handshake's facts for chain with presented beside
// it.
func handshake(chain []*x509.Certificate, presented ...[]*x509.Certificate) membership.Facts {
	f := membership.Facts{Boundary: membership.BoundaryHandshake, Chain: chain}
	if len(presented) != 0 {
		f.Presented = presented[0]
	}
	return f
}

// TestAdmitsOnlyWhereAMembershipBacks checks the decision on another core's
// chains: one for an admitted node's key is refused alone, admitted beside
// the node's membership, which is kept, and admitted alone from then on;
// one for a name the founder never admitted, or for the admitted name under
// another key, is refused beside the node's membership; and another core's
// chain backs nothing.
func TestAdmitsOnlyWhereAMembershipBacks(t *testing.T) {
	x := newFixture(t)
	x.founder.Enroll(t, checkerIA)
	key, member := x.founder.Enroll(t, nodeIA)
	renewed := issue(t, x.other.Issuer, nodeIA, key)
	env := membershiptest.Env(x.founder.DB, checkerIA, false)
	m := founder.New(env)
	ctx := t.Context()

	if err := m.Admit(ctx, handshake(renewed)); err == nil {
		t.Error("admitted another core's chain no membership backs")
	}
	if err := m.Admit(ctx, handshake(renewed, member)); err != nil {
		t.Errorf("refused another core's chain beside the node's membership: %v", err)
	}
	if held := env.Store.Get(nodeIA); held == nil || !held[0].Equal(member[0]) {
		t.Error("the presented membership is not kept")
	}
	if err := m.Admit(ctx, handshake(renewed)); err != nil {
		t.Errorf("refused the chain the kept membership backs: %v", err)
	}

	forged := map[string][]*x509.Certificate{
		"an unadmitted name": issue(t, x.other.Issuer, unadmitted, newKey(t)),
		"another key":        issue(t, x.other.Issuer, nodeIA, newKey(t)),
	}
	for name, chain := range forged {
		if err := m.Admit(ctx, handshake(chain, member)); err == nil {
			t.Errorf("%s: admitted beside the node's membership", name)
		}
	}
	if err := m.Admit(ctx, handshake(issue(t, x.other.Issuer, unadmitted, key), renewed)); err == nil {
		t.Error("admitted a chain beside another core's chain as its membership")
	}
	if err := m.Admit(ctx, handshake(claimingKeyID(t, x.other, renewed, member), member)); err == nil {
		t.Error("admitted a chain claiming the member's key ID over another key")
	}
}

// claimingKeyID returns a chain the other core's CA key signs for the
// member's ISD-AS over a fresh key, its subject key ID extension claiming
// the member's: what a leaked key mints to borrow a membership by its key
// ID. issued is a chain the other core issued, whose CA certificate signs.
func claimingKeyID(t *testing.T, other *trusttest.Founder, issued, member []*x509.Certificate) []*x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		RawSubject:   member[0].RawSubject,
		SubjectKeyId: member[0].SubjectKeyId,
		NotBefore:    member[0].NotBefore,
		NotAfter:     member[0].NotAfter,
		KeyUsage:     member[0].KeyUsage,
		ExtKeyUsage:  member[0].ExtKeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issued[1], newKey(t).Public(),
		other.Keys.CA)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert, issued[1]}
}

// TestJudgesByTheCheckersOwn checks the window against the checker's own
// membership, through the ages a founder outage leaves: a membership issued
// more than the window before the checker's own lapses; one issued within
// it counts though expired; one issued after it counts; and a node holding
// no membership judges by the founder's signature alone.
func TestJudgesByTheCheckersOwn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		x := newFixture(t)
		oldIA := addr.MustIAFrom(20, 0xff0000000021)
		withinIA := addr.MustIAFrom(20, 0xff0000000022)
		newerIA := addr.MustIAFrom(20, 0xff0000000023)
		oldKey, old := x.founder.Enroll(t, oldIA)
		time.Sleep(36 * time.Hour)
		withinKey, within := x.founder.Enroll(t, withinIA)
		time.Sleep(48 * time.Hour)
		x.founder.Enroll(t, checkerIA)
		time.Sleep(48 * time.Hour)
		newerKey, newer := x.founder.Enroll(t, newerIA)

		// judged is the checker's decision on ia's chain from another core,
		// its membership presented beside it.
		judged := func(checker, ia addr.IA, key crypto.Signer, member []*x509.Certificate) error {
			env := membershiptest.Env(x.founder.DB, checker, false)
			return founder.New(env).Admit(t.Context(),
				handshake(issue(t, x.other.Issuer, ia, key), member))
		}
		if err := judged(checkerIA, oldIA, oldKey, old); err == nil {
			t.Error("admitted a membership issued more than the window before the checker's own")
		}
		if err := judged(checkerIA, withinIA, withinKey, within); err != nil {
			t.Errorf("refused an expired membership issued within the window: %v", err)
		}
		if err := judged(checkerIA, newerIA, newerKey, newer); err != nil {
			t.Errorf("refused a membership issued after the checker's own: %v", err)
		}
		if err := judged(unadmitted, oldIA, oldKey, old); err != nil {
			t.Errorf("a node holding no membership refused a founder's: %v", err)
		}

		env := membershiptest.Env(x.founder.DB, checkerIA, false)
		for _, m := range [][]*x509.Certificate{old, within, newer} {
			if _, err := env.Store.Put(m); err != nil {
				t.Fatal(err)
			}
		}
		list, err := founder.New(env).List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		listed := make(map[addr.IA]bool, len(list))
		for _, m := range list {
			listed[m.IA] = true
		}
		if listed[oldIA] || !listed[withinIA] || !listed[newerIA] {
			t.Errorf("the checker lists %v, want the counting memberships and not the lapsed",
				list)
		}
	})
}

// TestRenewalAtTheFounderRestsOnTheBinding checks the renewal boundary: the
// founding core renews a key its ISD-AS is bound to on any core's chain,
// whatever the membership, and refuses another key and an unbound name;
// another issuer renews where a kept membership backs the chain.
func TestRenewalAtTheFounderRestsOnTheBinding(t *testing.T) {
	x := newFixture(t)
	ctx := t.Context()
	key, member := x.founder.Enroll(t, nodeIA)
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := x.founder.DB.BindKey(ctx, nodeIA, skid); err != nil {
		t.Fatal(err)
	}
	renewal := func(chain []*x509.Certificate) membership.Facts {
		return membership.Facts{Boundary: membership.BoundaryRenewal, Chain: chain}
	}

	m := founder.New(membershiptest.Env(x.founder.DB, founderIA, true))
	if err := m.Admit(ctx, renewal(issue(t, x.other.Issuer, nodeIA, key))); err != nil {
		t.Errorf("the founder refused a bound key on another core's chain: %v", err)
	}
	if err := m.Admit(ctx, renewal(issue(t, x.other.Issuer, nodeIA, newKey(t)))); err == nil {
		t.Error("the founder renewed another key than the bound one")
	}
	if err := m.Admit(ctx, renewal(issue(t, x.founder.Issuer, unadmitted, newKey(t)))); err == nil {
		t.Error("the founder renewed an unbound name")
	}

	env := membershiptest.Env(x.founder.DB, otherIA, false)
	issuer := founder.New(env)
	renewed := issue(t, x.other.Issuer, nodeIA, key)
	if err := issuer.Admit(ctx, renewal(renewed)); err == nil {
		t.Error("another issuer renewed a chain no kept membership backs")
	}
	if _, err := env.Store.Put(member); err != nil {
		t.Fatal(err)
	}
	if err := issuer.Admit(ctx, renewal(renewed)); err != nil {
		t.Errorf("another issuer refused a chain the kept membership backs: %v", err)
	}
}

// TestRemovedNodeIsRenewedNoMore checks the founding core's removal of a
// node: it frees the node's name, so the founder refuses the key's renewal
// from then on, while another issuer still renews where the kept membership
// backs the chain; the founder's listing keeps the membership until it
// lapses; and a core's removal under the method keeps no grace period.
func TestRemovedNodeIsRenewedNoMore(t *testing.T) {
	x := newFixture(t)
	ctx := t.Context()
	key, member := x.founder.Enroll(t, nodeIA)
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := x.founder.DB.BindKey(ctx, nodeIA, skid); err != nil {
		t.Fatal(err)
	}
	env := membershiptest.Env(x.founder.DB, founderIA, true)
	if _, err := env.Store.Put(member); err != nil {
		t.Fatal(err)
	}
	m := founder.New(env)
	if err := m.Remove(ctx, nodeIA); err != nil {
		t.Fatal(err)
	}
	if bound, err := x.founder.DB.BoundKey(ctx, nodeIA); err != nil || bound != nil {
		t.Errorf("the removed node's name is bound to %x (%v), want no key", bound, err)
	}
	renewal := membership.Facts{Boundary: membership.BoundaryRenewal,
		Chain: issue(t, x.other.Issuer, nodeIA, key)}
	if err := m.Admit(ctx, renewal); err == nil {
		t.Error("the founder renewed a removed node")
	}
	issuerEnv := membershiptest.Env(x.founder.DB, otherIA, false)
	if _, err := issuerEnv.Store.Put(member); err != nil {
		t.Fatal(err)
	}
	if err := founder.New(issuerEnv).Admit(ctx, renewal); err != nil {
		t.Errorf("another issuer refused the removed node while its membership counts: %v", err)
	}
	list, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(list, func(listed membership.Membership) bool {
		return listed.IA.Equal(nodeIA)
	}) {
		t.Errorf("the listing %v drops the removed node's membership at once", list)
	}
	if grace := m.RemovalGrace(); grace != 0 {
		t.Errorf("the removal grace period = %v, want none", grace)
	}
}

// TestRunReanchorsTheMembership checks the renewal loop past a founder
// roll: the membership under the root the roll replaces, still counting in
// the roll's grace period and far from its threshold, renews at the next
// pass, and the membership under the fresh root renews no more.
func TestRunReanchorsTheMembership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		x := newFixture(t)
		key, _ := x.founder.Enroll(t, nodeIA)
		var mtx sync.Mutex
		issuer, renewals := x.founder.Issuer, 0
		env := membershiptest.Env(x.founder.DB, nodeIA, false)
		env.Pacing = membership.Pacing{Inspect: time.Hour, Retry: time.Second}
		env.Renew = func(context.Context) ([]*x509.Certificate, error) {
			mtx.Lock()
			defer mtx.Unlock()
			renewals++
			chain := issue(t, issuer, nodeIA, key)
			if _, err := x.founder.DB.InsertChain(t.Context(), chain); err != nil {
				t.Error(err)
			}
			return chain, nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			founder.New(env).Run(ctx)
			close(done)
		}()
		count := func() int {
			mtx.Lock()
			defer mtx.Unlock()
			return renewals
		}

		synctest.Wait()
		if n := count(); n != 0 {
			t.Fatalf("renewed %d times under the newest root above the threshold, want none", n)
		}
		fresh, rolled, err := trust.RotateCoreKeys(t.Context(), x.founder.DB, x.founder.Dir,
			founderIA, x.founder.TRC)
		if err != nil {
			t.Fatal(err)
		}
		rolledIssuer, err := trust.NewIssuer(founderIA, fresh.IssuerKeys, rolled)
		if err != nil {
			t.Fatal(err)
		}
		mtx.Lock()
		issuer = rolledIssuer
		mtx.Unlock()
		time.Sleep(time.Hour)
		synctest.Wait()
		if n := count(); n != 1 {
			t.Errorf("renewed %d times under the replaced root, want once", n)
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if n := count(); n != 1 {
			t.Errorf("renewed %d times under the fresh root, want no more", n)
		}
		cancel()
		<-done
	})
}

// TestPresentsTheOwnMembership checks what a node presents beside its chain:
// nothing beside a chain the founder issued, its membership beside another
// core's, and nothing while it holds no membership.
func TestPresentsTheOwnMembership(t *testing.T) {
	x := newFixture(t)
	ctx := t.Context()
	key, member := x.founder.Enroll(t, nodeIA)
	m := founder.New(membershiptest.Env(x.founder.DB, nodeIA, false))

	if got, err := m.Present(ctx, member); err != nil || len(got) != 0 {
		t.Errorf("presented %d certificates beside the founder's chain (err %v), want none",
			len(got), err)
	}
	got, err := m.Present(ctx, issue(t, x.other.Issuer, nodeIA, key))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Equal(member[0]) || !got[1].Equal(member[1]) {
		t.Error("another core's chain is not presented beside the node's membership")
	}

	stranger := addr.MustIAFrom(20, 0xff0000000031)
	alone := founder.New(membershiptest.Env(x.founder.DB, stranger, false))
	if got, err := alone.Present(ctx, issue(t, x.other.Issuer, stranger, newKey(t))); err != nil ||
		len(got) != 0 {

		t.Errorf("a node holding no membership presented %d certificates (err %v), want none",
			len(got), err)
	}
}

// TestIssuedKeepsTheFoundersAlone checks that the chains the founding core
// issues are kept as memberships, and another core's are not.
func TestIssuedKeepsTheFoundersAlone(t *testing.T) {
	x := newFixture(t)
	_, chain := x.founder.Enroll(t, nodeIA)
	for _, tc := range []struct {
		name     string
		founding bool
		kept     bool
	}{{"the founding core", true, true}, {"another core", false, false}} {
		env := membershiptest.Env(x.founder.DB, founderIA, tc.founding)
		if err := founder.New(env).Issued(t.Context(), chain); err != nil {
			t.Fatal(err)
		}
		if kept := env.Store.Get(nodeIA) != nil; kept != tc.kept {
			t.Errorf("%s: kept the issued chain = %t, want %t", tc.name, kept, tc.kept)
		}
	}
}

// TestRunRenewsAtTheFounder checks the renewal loop: it renews once less
// than the threshold remains of the node's membership and keeps the renewed
// one, and while the founder does not answer it retries, renewing within a
// minute of the founder's return.
func TestRunRenewsAtTheFounder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		x := newFixture(t)
		key, _ := x.founder.Enroll(t, nodeIA)
		var mtx sync.Mutex
		down, renewals := false, 0
		env := membershiptest.Env(x.founder.DB, nodeIA, false)
		env.Pacing = membership.Pacing{
			RenewalThreshold: 48 * time.Hour,
			Inspect:          time.Hour,
			Retry:            time.Second,
		}
		env.Renew = func(context.Context) ([]*x509.Certificate, error) {
			mtx.Lock()
			defer mtx.Unlock()
			if down {
				return nil, errors.New("the founder does not answer")
			}
			renewals++
			chain := issue(t, x.founder.Issuer, nodeIA, key)
			if _, err := x.founder.DB.InsertChain(t.Context(), chain); err != nil {
				t.Error(err)
			}
			return chain, nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			founder.New(env).Run(ctx)
			close(done)
		}()
		count := func() int {
			mtx.Lock()
			defer mtx.Unlock()
			return renewals
		}

		synctest.Wait()
		if n := count(); n != 0 {
			t.Errorf("renewed %d times above the threshold, want none", n)
		}
		time.Sleep(25 * time.Hour)
		synctest.Wait()
		if n := count(); n != 1 {
			t.Errorf("renewed %d times once below the threshold, want once", n)
		}
		if held := env.Store.Get(nodeIA); held == nil ||
			time.Since(held[0].NotBefore) > 2*time.Hour {

			t.Error("the renewed membership is not kept")
		}

		mtx.Lock()
		down = true
		mtx.Unlock()
		time.Sleep(26 * time.Hour)
		synctest.Wait()
		mtx.Lock()
		down = false
		mtx.Unlock()
		time.Sleep(founder.RetryCap)
		synctest.Wait()
		if n := count(); n != 2 {
			t.Errorf("renewed %d times a minute after the founder's return, want twice", n)
		}
		cancel()
		<-done
	})
}
