package controlplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
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
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/authtest"
	"github.com/fancl20/cion/pkg/modules/membership"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

var (
	coreIATest = addr.MustIAFrom(20, 0xff0000000001)
	nodeIATest = addr.MustIAFrom(20, 0xff0000000002)
	// iaExtendingTest renders 20-ff00:0:1f, extending the fixture core's
	// own 20-ff00:0:1 by its name alone.
	iaExtendingTest = addr.MustIAFrom(20, 0xff000000001f)
)

// newFounder returns the founder of coreIATest's ISD.
func newFounder(t *testing.T) *trusttest.Founder {
	t.Helper()
	return newFounderOf(t, coreIATest)
}

// newFounderOf returns the founder ia over a fresh trust database, its
// genesis TRC naming the fellow cores beside it.
func newFounderOf(t *testing.T, ia addr.IA, fellows ...addr.IA) *trusttest.Founder {
	t.Helper()
	return trusttest.NewFounder(t, openTrustDB(t, t.TempDir()), ia, fellows...)
}

// openTrustDB opens the trust database in dir, closed when the test ends.
func openTrustDB(t *testing.T, dir string) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestTrustServiceTRC(t *testing.T) {
	f := newFounder(t)
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
		Membership: trusttest.Unchecked{}}

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
		if got.TRC.ID != f.TRC.TRC.ID {
			t.Errorf("%s: served TRC %v, want %v", name, got.TRC.ID, f.TRC.TRC.ID)
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
	f := newFounder(t)
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
		Membership: trusttest.Unchecked{}}

	csr, _ := trusttest.NewCSR(t, nodeIATest)
	chain, err := f.Issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.DB.InsertChain(context.Background(), chain); err != nil {
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
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
			Membership: trusttest.Unchecked{}}

		csr, key := trusttest.NewCSR(t, nodeIATest)
		req, err := trust.BuildRenewalRequest(csr, key, nil)
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
			TRC: []*cppki.TRC{&f.TRC.TRC},
		}); err != nil {
			t.Fatalf("renewed chain does not verify: %v", err)
		}
		// The issued chain is also in the core's DB.
		chains, err := f.DB.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIATest})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 1 {
			t.Fatalf("core DB chains = %d, want 1", len(chains))
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
			Membership: trusttest.Unchecked{}}

		// Wrapper signed by a different key than the CSR's subject.
		csr, _ := trusttest.NewCSR(t, nodeIATest)
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.BuildRenewalRequest(csr, other, nil)
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
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
			Membership: trusttest.Unchecked{}}

		csr, key := trusttest.NewCSR(t, nodeIATest)
		// Corrupt the CSR's signature in its DER form; parsing the request
		// already refuses it.
		bad := *csr
		bad.Raw = append([]byte(nil), csr.Raw...)
		bad.Raw[len(bad.Raw)-1] ^= 0xff
		req, err := trust.BuildRenewalRequest(&bad, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("unsigned-CSR error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})

	// The enrollment gate of self-picked ISD-ASes: a name bound to a
	// different subject key is taken; the holder's own re-enrollment passes
	// untouched. The door's cap is off — a microsecond admits every
	// sequential ask — for these episodes exercise the checks, not the rate.
	t.Run("a name bound to another key", func(t *testing.T) {
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, MinInterval: time.Microsecond,
			Membership: trusttest.Unchecked{}}

		csr, key := trusttest.NewCSR(t, nodeIATest)
		req, err := trust.BuildRenewalRequest(csr, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req})); err != nil {
			t.Fatal(err)
		}

		// Another key claiming the same ISD-AS is rejected.
		strangerCSR, strangerKey := trusttest.NewCSR(t, nodeIATest)
		strangerReq, err := trust.BuildRenewalRequest(strangerCSR, strangerKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: strangerReq}))
		if connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Errorf("taken-name error code = %v, want AlreadyExists", connect.CodeOf(err))
		}

		// The holder re-enrolls under its own key.
		renewal, err := trust.BuildRenewalRequest(csr, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: renewal})); err != nil {
			t.Errorf("the holder's own re-enrollment was rejected: %v", err)
		}
	})
}

// rekeyingDB rekeys the issuer as it stores an issued chain: the window
// between the renewal's issuance and its response's signature.
type rekeyingDB struct {
	trustdb.DB
	rekey func() error
}

func (d rekeyingDB) InsertChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	if err := d.rekey(); err != nil {
		return false, err
	}
	return d.DB.InsertChain(ctx, chain)
}

// TestChainRenewalRekeyBetweenIssueAndSign checks the renewal's one CA
// snapshot: a rekey landing between the chain's issuance and the
// response's signature leaves the response signed by the CA certificate its
// chain carries, the check the client makes.
func TestChainRenewalRekeyBetweenIssueAndSign(t *testing.T) {
	f := newFounder(t)
	db := rekeyingDB{DB: f.DB, rekey: func() error {
		ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		keys := f.Keys.IssuerKeys
		keys.CA = ca
		return f.Issuer.Rekey(keys, f.TRC)
	}}
	svc := &TrustService{DB: db, Issuer: f.Issuer, Enrolls: true, Membership: trusttest.Unchecked{}}

	csr, key := trusttest.NewCSR(t, nodeIATest)
	req, err := trust.BuildRenewalRequest(csr, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
		&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ParseRenewalResponse(resp.Msg.CmsSignedResponse); err != nil {
		t.Errorf("the client refuses the response a rekey interleaved: %v", err)
	}
}

// askContext carries a SCION source address the way the QUIC transport puts
// one in the request context.
func askContext() context.Context {
	return context.WithValue(context.Background(), http3.RemoteAddrContextKey,
		&scion.Addr{IA: nodeIATest, Addr: netip.MustParseAddrPort("198.51.100.7:41234")})
}

// TestTrustServiceEnrollmentAuthorizer checks the enrollment seam: the
// trust service asks the authorizer exactly at first issuance — never on a
// same-key re-enrollment, never on a name bound to another key — with the
// request's own facts, issuing on allow, refusing with PermissionDenied on
// deny, and answering Unavailable on pending, which the joiner's enrollment
// retry loop consumes without change.
func TestTrustServiceEnrollmentAuthorizer(t *testing.T) {
	ask := func(t *testing.T, svc *TrustService, ctx context.Context,
		csr *x509.CertificateRequest, key crypto.Signer) error {
		t.Helper()
		req, err := trust.BuildRenewalRequest(csr, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(ctx, connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		return err
	}

	t.Run("nil is open", func(t *testing.T) {
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
			Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatalf("open enrollment refused a first issuance: %v", err)
		}
	})

	t.Run("allow issues with the request's facts", func(t *testing.T) {
		f := newFounder(t)
		auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
			Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)

		if err := ask(t, svc, askContext(), csr, key); err != nil {
			t.Fatalf("allow was refused: %v", err)
		}
		if len(auth.Asked) != 1 {
			t.Fatalf("the authorizer was asked %d times, want 1", len(auth.Asked))
		}
		got := auth.Asked[0]
		if got.Boundary != enrollauth.BoundaryEnrollment {
			t.Errorf("asked boundary = %v, want enrollment", got.Boundary)
		}
		if got.Claim != nodeIATest {
			t.Errorf("asked claim = %v, want the claimed %v", got.Claim, nodeIATest)
		}
		wantSKID, err := cppki.SubjectKeyID(csr.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Keys) != 1 || got.Keys[0] != hex.EncodeToString(wantSKID) {
			t.Errorf("asked keys = %v, want the CSR subject key's fingerprint %x",
				got.Keys, wantSKID)
		}
		if want := netip.MustParseAddrPort("198.51.100.7:41234"); got.Source != want {
			t.Errorf("asked source = %v, want the context's %v", got.Source, want)
		}
		if got.Credential != "" {
			t.Errorf("asked credential = %q, want none at enrollment", got.Credential)
		}
	})

	t.Run("no address in the context is a zero fact", func(t *testing.T) {
		f := newFounder(t)
		auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
			Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatal(err)
		}
		if got := auth.Asked[0].Source; got.IsValid() {
			t.Errorf("asked source = %v, want the zero address", got)
		}
	})

	t.Run("deny is PermissionDenied", func(t *testing.T) {
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
			Authorizer: &authtest.Recorder{Verdict: enrollauth.AdmissionDeny},
			Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)
		err := ask(t, svc, context.Background(), csr, key)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("deny error code = %v, want PermissionDenied", connect.CodeOf(err))
		}
		// Nothing was issued or stored.
		chains, err := f.DB.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIATest})
		if err != nil || len(chains) != 0 {
			t.Errorf("chains after a denial = %d (%v), want none", len(chains), err)
		}
	})

	t.Run("pending is Unavailable", func(t *testing.T) {
		f := newFounder(t)
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true,
			Authorizer: &authtest.Recorder{Verdict: enrollauth.AdmissionPending},
			Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)
		err := ask(t, svc, context.Background(), csr, key)
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("pending error code = %v, want Unavailable", connect.CodeOf(err))
		}
	})

	t.Run("the holder's re-enrollment is never asked", func(t *testing.T) {
		f := newFounder(t)
		auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
			MinInterval: time.Microsecond, Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatal(err)
		}
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatalf("the holder's re-enrollment was refused: %v", err)
		}
		if len(auth.Asked) != 1 {
			t.Errorf("the authorizer was asked %d times, want the one of first issuance",
				len(auth.Asked))
		}
	})

	t.Run("a name bound to another key is never asked", func(t *testing.T) {
		f := newFounder(t)
		auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
		svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
			MinInterval: time.Microsecond, Membership: trusttest.Unchecked{}}
		csr, key := trusttest.NewCSR(t, nodeIATest)
		if err := ask(t, svc, context.Background(), csr, key); err != nil {
			t.Fatal(err)
		}
		strangerCSR, strangerKey := trusttest.NewCSR(t, nodeIATest)
		err := ask(t, svc, context.Background(), strangerCSR, strangerKey)
		if connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Errorf("taken-name error code = %v, want AlreadyExists", connect.CodeOf(err))
		}
		if len(auth.Asked) != 1 {
			t.Errorf("the authorizer was asked %d times, want the one of first issuance",
				len(auth.Asked))
		}
	})
}

// TestChainRenewalExtendingName checks the name's exactness: a name that
// extends the petitioner's — 20-ff00:0:1f beside 20-ff00:0:1 — bound to the
// petitioner's own key and holding a chain under it neither binds the
// petitioner's name nor holds its chains: the shared key does not read as
// the name's own, and the authorizer is asked on the first issuance the free
// name allows.
func TestChainRenewalExtendingName(t *testing.T) {
	f := newFounder(t)
	auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
		Membership: trusttest.Unchecked{}}
	ctx := context.Background()

	// The extending name holds a chain for the petitioner's own key and is
	// bound to it; the fixture's core — the victim, its name the shorter
	// one — holds none and is bound to none.
	csr, key := trusttest.NewCSR(t, coreIATest)
	extendingCSR, err := trust.CreateCSR(iaExtendingTest, key)
	if err != nil {
		t.Fatal(err)
	}
	extending, err := f.Issuer.IssueChain(extendingCSR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.DB.InsertChain(ctx, extending); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.BindKey(ctx, iaExtendingTest, extending[0].SubjectKeyId); err != nil {
		t.Fatal(err)
	}

	req, err := trust.BuildRenewalRequest(csr, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChainRenewal(ctx, connect.NewRequest(
		&cppb.ChainRenewalRequest{CmsSignedRequest: req})); err != nil {
		t.Fatalf("the extending name took the petitioner's: %v", err)
	}
	if len(auth.Asked) != 1 {
		t.Errorf("the authorizer was asked %d times, want the one of the free name",
			len(auth.Asked))
	}
	chains, err := f.DB.Chains(ctx, trustdb.ChainQuery{IA: coreIATest})
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
	asked   chan enrollauth.AdmissionFacts
	release chan struct{}
}

func (a *blockingAuthorizer) Authorize(
	_ context.Context, f enrollauth.AdmissionFacts) enrollauth.AdmissionAnswer {

	a.asked <- f
	<-a.release
	return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}
}

// sourceContext carries a SCION source address the way the QUIC transport
// puts one in the request context, the port naming the source.
func sourceContext(port string) context.Context {
	return context.WithValue(context.Background(), http3.RemoteAddrContextKey,
		&scion.Addr{IA: nodeIATest, Addr: netip.MustParseAddrPort("198.51.100.7:" + port)})
}

// TestChainRenewalSerialized checks the name transaction: two
// concurrent first issuances of one free name — different sources, both
// admitted by the door — yield one chain and one AlreadyExists, whatever
// the authorizer's latency; the binding settles the loser on its retry,
// sequentially.
func TestChainRenewalSerialized(t *testing.T) {
	f := newFounder(t)
	auth := &blockingAuthorizer{
		asked:   make(chan enrollauth.AdmissionFacts),
		release: make(chan struct{}),
	}
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
		Membership: trusttest.Unchecked{}}

	csrA, keyA := trusttest.NewCSR(t, nodeIATest)
	reqA, err := trust.BuildRenewalRequest(csrA, keyA, nil)
	if err != nil {
		t.Fatal(err)
	}
	csrB, keyB := trusttest.NewCSR(t, nodeIATest)
	reqB, err := trust.BuildRenewalRequest(csrB, keyB, nil)
	if err != nil {
		t.Fatal(err)
	}

	// One request holds the mutex inside the authorizer — the prompt's
	// network send is the latency it must survive — while the other waits
	// on the mutex; the holder's issuance completes, the waiter finds the
	// name bound to another key.
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
	chains, err := f.DB.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIATest})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Errorf("chains for the name = %d, want the one", len(chains))
	}
}

// TestChainRenewalRateCap checks the admission door: one admission
// per interval per source — the request's SCION source address the key, the
// claimed ISD-AS when the context carries none — the second inside the
// interval answering ResourceExhausted and a different source passing.
func TestChainRenewalRateCap(t *testing.T) {
	f := newFounder(t)
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, MinInterval: time.Hour,
		Membership: trusttest.Unchecked{}}

	ask := func(ctx context.Context, ia addr.IA) error {
		csr, key := trusttest.NewCSR(t, ia)
		req, err := trust.BuildRenewalRequest(csr, key, nil)
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
	// A different source passes the door; the name it claims is bound to
	// another key by now, and the answer is the binding's own.
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

// iaIssuerTest is the authoritative core the renewal tests onboard as an
// issuer beside the founder.
var iaIssuerTest = addr.MustIAFrom(20, 0xff0000000f01)

// issuingCore is an authoritative core onboarded beside the founder: the
// TRC carrying its root, pinned in its own database and the founder's, and
// its issuer anchored in it.
type issuingCore struct {
	db     trustdb.DB
	trc    cppki.SignedTRC
	keys   trust.IssuerKeys
	issuer *trust.Issuer
}

func newIssuingCore(t *testing.T, f *trusttest.Founder) *issuingCore {
	t.Helper()
	state := t.TempDir()
	votingKey, err := trust.LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	votingCert, err := trust.LoadOrCreateVotingCert(state, iaIssuerTest, votingKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := trust.LoadOrCreateIssuerKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := trust.LoadOrCreateRootCert(state, iaIssuerTest, keys.Root)
	if err != nil {
		t.Fatal(err)
	}
	onboarding, err := trust.AssembleOnboarding(f.TRC, iaIssuerTest, votingCert, rootCert)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := trust.SignUpdate(onboarding, trust.KeyCert{Key: votingKey, Cert: votingCert},
		trust.KeyCert{Key: keys.Root, Cert: rootCert})
	if err != nil {
		t.Fatal(err)
	}
	sensitive, err := trust.SignerCert(f.TRC.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.CoSign(partial, f.Keys.Sensitive, sensitive)
	if err != nil {
		t.Fatal(err)
	}
	db := openTrustDB(t, t.TempDir())
	for _, pin := range []struct {
		db  trustdb.DB
		trc cppki.SignedTRC
	}{{db, f.TRC}, {db, trc}, {f.DB, trc}} {
		if _, err := pin.db.InsertTRC(context.Background(), pin.trc); err != nil {
			t.Fatal(err)
		}
	}
	issuer, err := trust.NewIssuer(iaIssuerTest, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	return &issuingCore{db: db, trc: trc, keys: keys, issuer: issuer}
}

// renewalAsk asks the service for a chain for the CSR, the request signed
// with key under chain, and returns the chain the response carries.
func renewalAsk(
	t *testing.T,
	svc *TrustService,
	csr *x509.CertificateRequest,
	key crypto.Signer,
	chain []*x509.Certificate,
) ([]*x509.Certificate, error) {

	t.Helper()
	req, err := trust.BuildRenewalRequest(csr, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
		&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
	if err != nil {
		return nil, err
	}
	return trust.ParseRenewalResponse(resp.Msg.CmsSignedResponse)
}

// TestChainRenewalOnTheChain checks renewal at every issuer: an
// authoritative core renews a node on the chain the founder issued it, for
// the same key, asking no policy — not even one that would deny — and the
// renewed chain, the authoritative core's, verifies against the TRC that
// carries its root and renews at the founder in turn.
func TestChainRenewalOnTheChain(t *testing.T) {
	f := newFounder(t)
	core := newIssuingCore(t, f)
	auth := &authtest.Recorder{Verdict: enrollauth.AdmissionDeny}
	svc := &TrustService{DB: core.db, Issuer: core.issuer, Authorizer: auth,
		Membership: trusttest.Unchecked{}}

	key, founders := f.Enroll(t, nodeIATest)
	csr, err := trust.CreateCSR(nodeIATest, key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := renewalAsk(t, svc, csr, key, founders)
	if err != nil {
		t.Fatalf("the authoritative core refused the renewal: %v", err)
	}
	if err := cppki.VerifyChain(renewed, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&core.trc.TRC},
	}); err != nil {
		t.Fatalf("the renewed chain does not verify against the TRC carrying its root: %v", err)
	}
	if err := cppki.VerifyChain(renewed, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&f.TRC.TRC},
	}); err == nil {
		t.Error("the renewed chain verifies under the founder's root alone, want the core's")
	}
	if string(renewed[0].SubjectKeyId) != string(founders[0].SubjectKeyId) {
		t.Error("the renewed chain certifies another key")
	}
	if len(auth.Asked) != 0 {
		t.Errorf("the authorizer was asked %d times, want none on a renewal", len(auth.Asked))
	}

	founder := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
		Membership: trusttest.Unchecked{}}
	if _, err := renewalAsk(t, founder, csr, key, renewed); err != nil {
		t.Errorf("the founder refused the renewal on the core's chain: %v", err)
	}
}

// TestChainRenewalRefusals checks what an authoritative core refuses: a
// request no chain authorizes — a first issuance, the founder's alone —
// asking no policy; a chain no root of its TRC anchors; a chain naming
// another ISD-AS than the CSR; a CSR certifying another key than the chain;
// a request the chain's AS key did not sign; and, while its issuer is
// unanchored, every renewal.
func TestChainRenewalRefusals(t *testing.T) {
	f := newFounder(t)
	core := newIssuingCore(t, f)
	auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
	svc := &TrustService{DB: core.db, Issuer: core.issuer, Authorizer: auth,
		MinInterval: time.Microsecond, Membership: trusttest.Unchecked{}}
	key, chain := f.Enroll(t, nodeIATest)
	csr, err := trust.CreateCSR(nodeIATest, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("first issuance", func(t *testing.T) {
		_, err := renewalAsk(t, svc, csr, key, nil)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("first issuance error code = %v, want FailedPrecondition", connect.CodeOf(err))
		}
		if len(auth.Asked) != 0 {
			t.Errorf("the authorizer was asked %d times, want none", len(auth.Asked))
		}
	})
	t.Run("another trust root", func(t *testing.T) {
		stranger := newFounder(t)
		strangerKey, strangerChain := stranger.Enroll(t, nodeIATest)
		strangerCSR, err := trust.CreateCSR(nodeIATest, strangerKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = renewalAsk(t, svc, strangerCSR, strangerKey, strangerChain)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("foreign chain error code = %v, want PermissionDenied", connect.CodeOf(err))
		}
	})
	t.Run("another ISD-AS", func(t *testing.T) {
		otherCSR, err := trust.CreateCSR(iaExtendingTest, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = renewalAsk(t, svc, otherCSR, key, chain)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("another ISD-AS error code = %v, want PermissionDenied", connect.CodeOf(err))
		}
	})
	t.Run("another key", func(t *testing.T) {
		otherCSR, _ := trusttest.NewCSR(t, nodeIATest)
		_, err := renewalAsk(t, svc, otherCSR, key, chain)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("another key error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})
	t.Run("signed by the CA", func(t *testing.T) {
		raw, err := proto.Marshal(&cppb.ChainRenewalRequestBody{Csr: csr.Raw})
		if err != nil {
			t.Fatal(err)
		}
		cms, err := trust.SignCMS(raw, chain, f.Keys.CA)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: cms}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("CA-signed error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})
	t.Run("unanchored", func(t *testing.T) {
		unanchored, err := trust.NewIssuer(iaIssuerTest, core.keys, f.TRC)
		if err != nil {
			t.Fatal(err)
		}
		svc := &TrustService{DB: core.db, Issuer: unanchored, Membership: trusttest.Unchecked{}}
		_, err = renewalAsk(t, svc, csr, key, chain)
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("unanchored error code = %v, want Unavailable", connect.CodeOf(err))
		}
	})
}

// TestChainRenewalBindsTheName checks the founder's binding of a name to its
// key: once the name's chains have expired and been swept, a first issuance
// of the name under another key is still refused, and the holder's own
// re-enrolls without the policy's question.
func TestChainRenewalBindsTheName(t *testing.T) {
	f := newFounder(t)
	auth := &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, Authorizer: auth,
		MinInterval: time.Microsecond, Membership: trusttest.Unchecked{}}

	csr, key := trusttest.NewCSR(t, nodeIATest)
	if _, err := renewalAsk(t, svc, csr, key, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.DB.DeleteExpiredChains(context.Background(),
		time.Now().Add(trust.ASValidity+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if chains, err := f.DB.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIATest}); err != nil ||
		len(chains) != 0 {

		t.Fatalf("chains after the sweep = %d (%v), want none", len(chains), err)
	}

	strangerCSR, strangerKey := trusttest.NewCSR(t, nodeIATest)
	_, err := renewalAsk(t, svc, strangerCSR, strangerKey, nil)
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Errorf("another key's error code = %v, want AlreadyExists", connect.CodeOf(err))
	}
	if _, err := renewalAsk(t, svc, csr, key, nil); err != nil {
		t.Errorf("the holder's re-enrollment was refused: %v", err)
	}
	if len(auth.Asked) != 1 {
		t.Errorf("the authorizer was asked %d times, want the one of first issuance",
			len(auth.Asked))
	}
}

// recordingMembership is a membership double: it records the facts of each
// decision and every chain issued, and refuses every chain with refuse when
// it is set.
type recordingMembership struct {
	refuse error

	mtx    sync.Mutex
	facts  []membership.Facts
	issued [][]*x509.Certificate
}

func (m *recordingMembership) Admit(_ context.Context, f membership.Facts) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.facts = append(m.facts, f)
	return m.refuse
}

func (m *recordingMembership) Issued(_ context.Context, chain []*x509.Certificate) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.issued = append(m.issued, chain)
	return nil
}

// TestChainRenewalAsksTheMembership checks the trust service's membership
// seam: a renewal is decided at the renewal boundary on the chain it rests
// on, a refused one is refused with PermissionDenied and issues nothing, and
// every chain the service issues, a first issuance's included, is handed to
// the membership.
func TestChainRenewalAsksTheMembership(t *testing.T) {
	f := newFounder(t)
	key, chain := f.Enroll(t, nodeIATest)
	csr, err := trust.CreateCSR(nodeIATest, key)
	if err != nil {
		t.Fatal(err)
	}

	refusing := &recordingMembership{refuse: errors.New("refused")}
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, MinInterval: time.Microsecond,
		Membership: refusing}
	if _, err := renewalAsk(t, svc, csr, key, chain); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a renewal the membership refuses = %v, want PermissionDenied", err)
	}
	if len(refusing.facts) != 1 || refusing.facts[0].Boundary != membership.BoundaryRenewal ||
		!refusing.facts[0].Chain[0].Equal(chain[0]) {

		t.Errorf("the membership decided %+v, want the renewal's chain", refusing.facts)
	}
	if len(refusing.issued) != 0 {
		t.Errorf("handed %d issued chains for a refused renewal, want none", len(refusing.issued))
	}

	admitting := &recordingMembership{}
	svc = &TrustService{DB: f.DB, Issuer: f.Issuer, Enrolls: true, MinInterval: time.Microsecond,
		Membership: admitting}
	renewed, err := renewalAsk(t, svc, csr, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	fresh, freshKey := trusttest.NewCSR(t, addr.MustIAFrom(nodeIATest.ISD(), 0xff00000000aa))
	enrolled, err := renewalAsk(t, svc, fresh, freshKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(admitting.issued) != 2 || !admitting.issued[0][0].Equal(renewed[0]) ||
		!admitting.issued[1][0].Equal(enrolled[0]) {

		t.Errorf("handed %d issued chains, want the renewal's and the first issuance's",
			len(admitting.issued))
	}
}
