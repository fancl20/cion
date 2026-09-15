package wireguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	gatewayv1 "github.com/fancl20/cion/proto/gateway/v1"
)

// fakeStore is an in-memory directory store.
type fakeStore struct {
	entries    []Entry
	publishErr error
}

func (s *fakeStore) Publish(_ context.Context, entry Entry) error {
	if s.publishErr != nil {
		return s.publishErr
	}
	for i := range s.entries {
		if s.entries[i].IA.Equal(entry.IA) {
			s.entries[i] = entry
			return nil
		}
	}
	s.entries = append(s.entries, entry)
	return nil
}

func (s *fakeStore) List(context.Context) ([]Entry, error) { return s.entries, nil }
func (s *fakeStore) Close() error                          { return nil }

// requestWithIA builds a request context carrying the authenticated
// publisher the middleware would have peered in.
func requestWithIA(t *testing.T, ia addr.IA) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), authenticatedIAKey{}, ia)
}

// TestDirectoryPublishRecordsAuthenticatedIA checks the handlers record the
// authenticated ISD-AS: a publish claiming another ISD-AS is recorded under
// the authenticated one, and one without an authenticated ISD-AS never
// records.
func TestDirectoryPublishRecordsAuthenticatedIA(t *testing.T) {
	store := &fakeStore{}
	svc := &DirectoryService{Store: store, Cnt: &counters{}}
	publisher := addr.MustIAFrom(20, 0xff0000000111)
	claimed := addr.MustIAFrom(20, 0xff0000000222)

	entry := Entry{
		IA:        claimed,
		PublicKey: PublicKey{},
		Overlay:   netip.MustParsePrefix("10.64.1.0/24"),
	}
	if _, err := svc.Publish(requestWithIA(t, publisher),
		connect.NewRequest(&gatewayv1.PublishRequest{Entry: entry.pb()})); err != nil {
		t.Fatalf("publishing: %v", err)
	}
	entries, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("store holds %d entries, want 1", len(entries))
	}
	if !entries[0].IA.Equal(publisher) {
		t.Errorf("entry recorded under %s, want the authenticated %s",
			entries[0].IA, publisher)
	}

	// A publish without an authenticated ISD-AS never records.
	_, err = svc.Publish(context.Background(),
		connect.NewRequest(&gatewayv1.PublishRequest{Entry: entry.pb()}))
	if err == nil {
		t.Error("publishing without an authenticated ISD-AS succeeded")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("error code = %s, want permission denied", code)
	}
}

// TestDirectoryListServesEntries checks List serves what Publish recorded.
func TestDirectoryListServesEntries(t *testing.T) {
	store := &fakeStore{}
	svc := &DirectoryService{Store: store, Cnt: &counters{}}
	ia := addr.MustIAFrom(20, 0xff0000000131)
	entry := Entry{
		IA:        ia,
		PublicKey: mustPubKey(0xab),
		Overlay:   netip.MustParsePrefix("10.64.7.0/24"),
	}
	if _, err := svc.Publish(requestWithIA(t, ia),
		connect.NewRequest(&gatewayv1.PublishRequest{Entry: entry.pb()})); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.List(context.Background(),
		connect.NewRequest(&gatewayv1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Entries) != 1 {
		t.Fatalf("list served %d entries, want 1", len(resp.Msg.Entries))
	}
	got, err := entryFromPB(resp.Msg.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if got != entry {
		t.Errorf("entry = %+v, want %+v", got, entry)
	}
}

func mustPubKey(b byte) PublicKey {
	var key PublicKey
	for i := range key {
		key[i] = b
	}
	return key
}

// TestAuthenticateMiddleware checks the middleware peers the verified
// chain's ISD-AS into the request context for the handlers to read.
func TestAuthenticateMiddleware(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000141)
	var seen addr.IA
	h := Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = AuthenticatedIA(r.Context())
	}))
	r := httptest.NewRequest("POST", "/", nil)
	// A certificate whose subject names the ISD-AS the way SCION chains do.
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		iaSubjectCert(t, ia),
	}}
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !seen.Equal(ia) {
		t.Errorf("authenticated ISD-AS = %s, want %s", seen, ia)
	}
}

// iaSubjectCert builds a certificate whose subject names the ISD-AS the way
// SCION chains do: the IA in the subject's dedicated RDN.
func iaSubjectCert(t *testing.T, ia addr.IA) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			// Marshaling writes ExtraNames; Names is only populated on
			// parsing.
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: cppki.OIDNameIA, Value: ia.String()}},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
