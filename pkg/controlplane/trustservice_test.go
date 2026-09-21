package controlplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

var (
	coreIATest = addr.MustIAFrom(20, 0xff0000000001)
	nodeIATest = addr.MustIAFrom(20, 0xff0000000002)
	// iaExtendingTest renders 20-ff00:0:1f, extending the fixture core's
	// own 20-ff00:0:1 by its name alone.
	iaExtendingTest = addr.MustIAFrom(20, 0xff000000001f)
)

// trustFixture is a serving-side trust stack: DB with a genesis TRC and an
// issuer.
type trustFixture struct {
	db     trust.DB
	issuer *trust.Issuer
	trc    cppki.SignedTRC
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(context.Background(), db, coreIATest, keys)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(coreIATest, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	return &trustFixture{db: db, issuer: issuer, trc: trc}
}

// newCSR returns a CSR for a freshly generated AS key.
func newCSR(t *testing.T, ia addr.IA) (*x509.CertificateRequest, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr, key
}

func TestTrustServiceTRC(t *testing.T) {
	f := newTrustFixture(t)
	svc := &TrustService{DB: f.db, Issuer: f.issuer}

	for name, req := range map[string]*cppb.TRCRequest{
		"exact":  {Isd: uint32(coreIATest.ISD()), Base: 1, Serial: 1},
		"latest": {Isd: uint32(coreIATest.ISD())},
	} {
		resp, err := svc.TRC(context.Background(), connect.NewRequest(req))
		if err != nil {
			t.Fatal(err)
		}
		got, err := cppki.DecodeSignedTRC(resp.Msg.Trc)
		if err != nil {
			t.Fatal(err)
		}
		if got.TRC.ID != f.trc.TRC.ID {
			t.Errorf("%s: served TRC %v, want %v", name, got.TRC.ID, f.trc.TRC.ID)
		}
	}

	_, err := svc.TRC(context.Background(), connect.NewRequest(&cppb.TRCRequest{
		Isd: uint32(coreIATest.ISD()), Base: 4, Serial: 9,
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("unknown TRC error code = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestTrustServiceChains(t *testing.T) {
	f := newTrustFixture(t)
	svc := &TrustService{DB: f.db, Issuer: f.issuer}

	csr, _ := newCSR(t, nodeIATest)
	chain, err := f.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(context.Background(), chain); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Chains(context.Background(), connect.NewRequest(&cppb.ChainsRequest{
		IsdAs: uint64(nodeIATest),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Chains) != 1 {
		t.Fatalf("served chains = %d, want 1", len(resp.Msg.Chains))
	}
	asCert, err := x509.ParseCertificate(resp.Msg.Chains[0].AsCert)
	if err != nil {
		t.Fatal(err)
	}
	if !asCert.Equal(chain[0]) {
		t.Error("served chain differs from stored chain")
	}
}

func TestTrustServiceChainRenewal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}

		csr, key := newCSR(t, nodeIATest)
		req, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if err != nil {
			t.Fatal(err)
		}
		chain, err := trust.ParseRenewalResponse(resp.Msg.CmsSignedResponse)
		if err != nil {
			t.Fatal(err)
		}
		if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
			TRC: []*cppki.TRC{&f.trc.TRC},
		}); err != nil {
			t.Fatalf("renewed chain does not verify: %v", err)
		}
		// The issued chain is also in the core's DB.
		chains, err := f.db.Chains(context.Background(), trust.ChainQuery{IA: nodeIATest})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 1 {
			t.Fatalf("core DB chains = %d, want 1", len(chains))
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}

		// Wrapper signed by a different key than the CSR's subject.
		csr, _ := newCSR(t, nodeIATest)
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.BuildRenewalRequest(csr, other)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("wrong-key error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})

	t.Run("unsigned csr", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}

		csr, key := newCSR(t, nodeIATest)
		// Corrupt the CSR's signature in its DER form; parsing the request
		// already refuses it.
		bad := *csr
		bad.Raw = append([]byte(nil), csr.Raw...)
		bad.Raw[len(bad.Raw)-1] ^= 0xff
		req, err := trust.BuildRenewalRequest(&bad, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("unsigned-CSR error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})

	// The enrollment gate of self-picked ISD-ASes (proposal 0008): a name
	// that already holds an unexpired chain under a different subject key is
	// taken; the holder's own renewal passes untouched. The door's cap is
	// off — a microsecond admits every sequential ask — for these episodes
	// exercise the checks, not the rate.
	t.Run("taken name", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer, MinInterval: time.Microsecond}

		csr, key := newCSR(t, nodeIATest)
		req, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req})); err != nil {
			t.Fatal(err)
		}

		// Another key claiming the same ISD-AS is rejected.
		strangerCSR, strangerKey := newCSR(t, nodeIATest)
		strangerReq, err := trust.BuildRenewalRequest(strangerCSR, strangerKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: strangerReq}))
		if connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Errorf("taken-name error code = %v, want AlreadyExists", connect.CodeOf(err))
		}

		// The holder renews under its own key.
		renewal, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: renewal})); err != nil {
			t.Errorf("the holder's own renewal was rejected: %v", err)
		}
	})
}

// askAuthorizer records the facts the trust service asked with and answers
// the verdict it was told to.
type askAuthorizer struct {
	asked   []EnrollmentFacts
	verdict EnrollmentVerdict
}

func (a *askAuthorizer) Authorize(_ context.Context, f EnrollmentFacts) EnrollmentVerdict {
	a.asked = append(a.asked, f)
	return a.verdict
}

// askContext carries a SCION source address the way the QUIC transport puts
// one in the request context.
func askContext() context.Context {
	return context.WithValue(context.Background(), http3.RemoteAddrContextKey,
		&scion.Addr{IA: nodeIATest, Addr: netip.MustParseAddrPort("198.51.100.7:41234")})
}

// TestTrustServiceEnrollmentAuthorizer checks the seam of ADR-0010: the
// trust service asks the authorizer exactly at first issuance — never on a
// same-key renewal, never on a taken name — with the request's own facts,
// issuing on allow, refusing with PermissionDenied on deny, and answering
// Unavailable on pending, which the joiner's enrollment retry loop consumes
// without change.
func TestTrustServiceEnrollmentAuthorizer(t *testing.T) {
	ask := func(t *testing.T, svc *TrustService, ctx context.Context,
		csr *x509.CertificateRequest, key crypto.Signer) error {
		t.Helper()
		req, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(ctx, connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		return err
	}

	t.Run("nil is open", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}
		csr, key := newCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatalf("open enrollment refused a first issuance: %v", err)
		}
	})

	t.Run("allow issues with the request's facts", func(t *testing.T) {
		f := newTrustFixture(t)
		auth := &askAuthorizer{verdict: EnrollmentAllow}
		svc := &TrustService{DB: f.db, Issuer: f.issuer, Authorizer: auth}
		csr, key := newCSR(t, nodeIATest)

		if err := ask(t, svc, askContext(), csr, key); err != nil {
			t.Fatalf("allow was refused: %v", err)
		}
		if len(auth.asked) != 1 {
			t.Fatalf("the authorizer was asked %d times, want 1", len(auth.asked))
		}
		got := auth.asked[0]
		if got.IA != nodeIATest {
			t.Errorf("asked ISD-AS = %v, want the claimed %v", got.IA, nodeIATest)
		}
		if !got.Key.(interface{ Equal(crypto.PublicKey) bool }).Equal(csr.PublicKey) {
			t.Error("asked key differs from the CSR's subject key")
		}
		if want := netip.MustParseAddrPort("198.51.100.7:41234"); got.Addr != want {
			t.Errorf("asked source = %v, want the context's %v", got.Addr, want)
		}
	})

	t.Run("no address in the context is a zero fact", func(t *testing.T) {
		f := newTrustFixture(t)
		auth := &askAuthorizer{verdict: EnrollmentAllow}
		svc := &TrustService{DB: f.db, Issuer: f.issuer, Authorizer: auth}
		csr, key := newCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatal(err)
		}
		if got := auth.asked[0].Addr; got.IsValid() {
			t.Errorf("asked source = %v, want the zero address", got)
		}
	})

	t.Run("deny is PermissionDenied", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer,
			Authorizer: &askAuthorizer{verdict: EnrollmentDeny}}
		csr, key := newCSR(t, nodeIATest)
		err := ask(t, svc, context.Background(), csr, key)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("deny error code = %v, want PermissionDenied", connect.CodeOf(err))
		}
		// Nothing was issued or stored.
		chains, err := f.db.Chains(context.Background(), trust.ChainQuery{IA: nodeIATest})
		if err != nil || len(chains) != 0 {
			t.Errorf("chains after a denial = %d (%v), want none", len(chains), err)
		}
	})

	t.Run("pending is Unavailable", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer,
			Authorizer: &askAuthorizer{verdict: EnrollmentPending}}
		csr, key := newCSR(t, nodeIATest)
		err := ask(t, svc, context.Background(), csr, key)
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("pending error code = %v, want Unavailable", connect.CodeOf(err))
		}
	})

	t.Run("the holder's renewal is never asked", func(t *testing.T) {
		f := newTrustFixture(t)
		auth := &askAuthorizer{verdict: EnrollmentAllow}
		svc := &TrustService{DB: f.db, Issuer: f.issuer, Authorizer: auth,
			MinInterval: time.Microsecond}
		csr, key := newCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatal(err)
		}
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatalf("the holder's renewal was refused: %v", err)
		}
		if len(auth.asked) != 1 {
			t.Errorf("the authorizer was asked %d times, want the one of first issuance",
				len(auth.asked))
		}
	})

	t.Run("a taken name is never asked", func(t *testing.T) {
		f := newTrustFixture(t)
		auth := &askAuthorizer{verdict: EnrollmentAllow}
		svc := &TrustService{DB: f.db, Issuer: f.issuer, Authorizer: auth,
			MinInterval: time.Microsecond}
		csr, key := newCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatal(err)
		}
		strangerCSR, strangerKey := newCSR(t, nodeIATest)
		err := ask(t, svc, context.Background(), strangerCSR, strangerKey)
		if connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Errorf("taken-name error code = %v, want AlreadyExists", connect.CodeOf(err))
		}
		if len(auth.asked) != 1 {
			t.Errorf("the authorizer was asked %d times, want the one of first issuance",
				len(auth.asked))
		}
	})
}

// TestChainRenewalExtendingName checks the name's exactness (proposal
// 0015): a chain held under a name that extends the petitioner's —
// 20-ff00:0:1f beside 20-ff00:0:1 — neither takes the name nor renews it.
// The colliding fingerprint does not read as a renewal — the chains share
// the subject key — and the authorizer is asked on the first issuance the
// free name allows.
func TestChainRenewalExtendingName(t *testing.T) {
	f := newTrustFixture(t)
	auth := &askAuthorizer{verdict: EnrollmentAllow}
	svc := &TrustService{DB: f.db, Issuer: f.issuer, Authorizer: auth}
	ctx := context.Background()

	// The extending name holds a chain for the petitioner's own key; the
	// fixture's core — the victim, its name the shorter one — holds none.
	csr, key := newCSR(t, coreIATest)
	extendingCSR, err := trust.CreateCSR(iaExtendingTest, key)
	if err != nil {
		t.Fatal(err)
	}
	extending, err := f.issuer.IssueChain(extendingCSR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(ctx, extending); err != nil {
		t.Fatal(err)
	}

	req, err := trust.BuildRenewalRequest(csr, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChainRenewal(ctx, connect.NewRequest(
		&cppb.ChainRenewalRequest{CmsSignedRequest: req})); err != nil {
		t.Fatalf("the extending name took the petitioner's: %v", err)
	}
	if len(auth.asked) != 1 {
		t.Errorf("the authorizer was asked %d times, want the one of the free name",
			len(auth.asked))
	}
	chains, err := f.db.Chains(ctx, trust.ChainQuery{IA: coreIATest})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("the victim's chains = %d, want the one issued", len(chains))
	}
	if ia, err := cppki.ExtractIA(chains[0][0].Subject); err != nil || !ia.Equal(coreIATest) {
		t.Errorf("issued chain names %v, want the petitioner's own name", ia)
	}
}

// blockingAuthorizer holds every ask until released, then allows — the
// Telegram prompt's network send in miniature.
type blockingAuthorizer struct {
	asked   chan EnrollmentFacts
	release chan struct{}
}

func (a *blockingAuthorizer) Authorize(_ context.Context, f EnrollmentFacts) EnrollmentVerdict {
	a.asked <- f
	<-a.release
	return EnrollmentAllow
}

// sourceContext carries a SCION source address the way the QUIC transport
// puts one in the request context, the port naming the source.
func sourceContext(port string) context.Context {
	return context.WithValue(context.Background(), http3.RemoteAddrContextKey,
		&scion.Addr{IA: nodeIATest, Addr: netip.MustParseAddrPort("198.51.100.7:" + port)})
}

// TestChainRenewalSerialized checks the transaction of proposal 0015: two
// concurrent first issuances of one free name — different sources, both
// admitted by the door — yield one chain and one AlreadyExists, whatever
// the authorizer's latency; the name-taken check settles the loser on its
// retry, sequentially.
func TestChainRenewalSerialized(t *testing.T) {
	f := newTrustFixture(t)
	auth := &blockingAuthorizer{
		asked:   make(chan EnrollmentFacts),
		release: make(chan struct{}),
	}
	svc := &TrustService{DB: f.db, Issuer: f.issuer, Authorizer: auth}

	csrA, keyA := newCSR(t, nodeIATest)
	reqA, err := trust.BuildRenewalRequest(csrA, keyA)
	if err != nil {
		t.Fatal(err)
	}
	csrB, keyB := newCSR(t, nodeIATest)
	reqB, err := trust.BuildRenewalRequest(csrB, keyB)
	if err != nil {
		t.Fatal(err)
	}

	// One request holds the mutex inside the authorizer — the prompt's
	// network send is the latency it must survive — while the other waits
	// on the mutex; the holder's issuance completes, the waiter finds the
	// name taken.
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		req *cppb.ChainRenewalRequest
		ctx context.Context
	}{
		{&cppb.ChainRenewalRequest{CmsSignedRequest: reqA}, sourceContext("40001")},
		{&cppb.ChainRenewalRequest{CmsSignedRequest: reqB}, sourceContext("40002")},
	} {
		wg.Add(1)
		go func(req *cppb.ChainRenewalRequest, ctx context.Context) {
			defer wg.Done()
			_, err := svc.ChainRenewal(ctx, connect.NewRequest(req))
			results <- err
		}(tc.req, tc.ctx)
	}
	<-auth.asked
	close(auth.release)
	wg.Wait()
	close(results)

	var issued, refused int
	for err := range results {
		switch {
		case err == nil:
			issued++
		case connect.CodeOf(err) == connect.CodeAlreadyExists:
			refused++
		default:
			t.Fatalf("concurrent first issuance: %v", err)
		}
	}
	if issued != 1 || refused != 1 {
		t.Fatalf("issued = %d, refused = %d, want one of each", issued, refused)
	}
	chains, err := f.db.Chains(context.Background(), trust.ChainQuery{IA: nodeIATest})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Errorf("chains for the name = %d, want the one", len(chains))
	}
}

// TestChainRenewalRateCap checks the door of proposal 0015: one admission
// per interval per source — the request's SCION source address the key, the
// claimed ISD-AS when the context carries none — the second inside the
// interval answering ResourceExhausted and a different source passing.
func TestChainRenewalRateCap(t *testing.T) {
	f := newTrustFixture(t)
	svc := &TrustService{DB: f.db, Issuer: f.issuer, MinInterval: time.Hour}

	ask := func(ctx context.Context, ia addr.IA) error {
		csr, key := newCSR(t, ia)
		req, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(ctx, connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		return err
	}

	// The first source's admission issues; its second inside the interval
	// is refused at the door whatever name it claims.
	if err := ask(sourceContext("40001"), nodeIATest); err != nil {
		t.Fatalf("the first admission: %v", err)
	}
	if err := ask(sourceContext("40001"), iaExtendingTest); connect.CodeOf(err) !=
		connect.CodeResourceExhausted {

		t.Fatalf("the same source's second error code = %v, want ResourceExhausted",
			connect.CodeOf(err))
	}
	// A different source passes the door; the name it claims is taken by
	// now, and the answer is the name check's own.
	if err := ask(sourceContext("40002"), nodeIATest); connect.CodeOf(err) !=
		connect.CodeAlreadyExists {

		t.Fatalf("a different source's error code = %v, want AlreadyExists",
			connect.CodeOf(err))
	}
	// Without an address the claimed ISD-AS is the key: one admission per
	// name, a different name passing.
	if err := ask(context.Background(), iaExtendingTest); err != nil {
		t.Fatalf("the first name-keyed admission: %v", err)
	}
	if err := ask(context.Background(), iaExtendingTest); connect.CodeOf(err) !=
		connect.CodeResourceExhausted {

		t.Fatalf("the same name's second error code = %v, want ResourceExhausted",
			connect.CodeOf(err))
	}
	if err := ask(context.Background(), iaLineC); err != nil {
		t.Fatalf("a different name's admission: %v", err)
	}
}
