package wireguard

import (
	"context"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"testing"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/peeria"
	wireguardv1 "github.com/fancl20/cion/proto/wireguard/v1"
)

// fakeStore is the in-package directory-store double: the shared one lives
// in the contract suite's package, which imports this one — an internal
// test cannot import it back. It assigns slices the store's way.
type fakeStore struct {
	entries []Entry
	hosts   []HostEntry
}

func (s *fakeStore) Publish(_ context.Context, entry Entry) (Entry, error) {
	overlay, err := AssignSlice(entry.IA, s.entries)
	if err != nil {
		return Entry{}, err
	}
	entry.Overlay = overlay
	for i := range s.entries {
		if s.entries[i].IA.Equal(entry.IA) {
			s.entries[i] = entry
			return entry, nil
		}
	}
	s.entries = append(s.entries, entry)
	return entry, nil
}

func (s *fakeStore) PublishHost(_ context.Context, entry HostEntry) error {
	for i := range s.hosts {
		if s.hosts[i].PublicKey == entry.PublicKey {
			s.hosts[i] = entry
			return nil
		}
	}
	s.hosts = append(s.hosts, entry)
	return nil
}

func (s *fakeStore) List(context.Context) (Directory, error) {
	return Directory{Nodes: s.entries, Hosts: s.hosts}, nil
}
func (s *fakeStore) Close() error { return nil }

// mustPubKey is the local key-minting helper, the shared one out of reach
// behind the same import cycle.
func mustPubKey(b byte) PublicKey {
	var key PublicKey
	for i := range key {
		key[i] = b
	}
	return key
}

// requestWithIA builds a request context carrying the authenticated
// publisher the middleware would have peered in.
func requestWithIA(t *testing.T, ia addr.IA) context.Context {
	t.Helper()
	return context.WithValue(context.Background(),
		peeria.AuthenticatedIAContextKey(), ia)
}

// TestDirectoryPublishRecordsAuthenticatedIA checks the handlers record the
// authenticated ISD-AS: a publish claiming another ISD-AS is recorded under
// the authenticated one, the store's assigned slice answering the
// publication, and one without an authenticated ISD-AS never records.
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
	resp, err := svc.Publish(requestWithIA(t, publisher),
		connect.NewRequest(&wireguardv1.PublishRequest{Entry: entry.pb()}))
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	if want := "100.64.0.0/24"; resp.Msg.OverlaySubnet != want {
		t.Errorf("the publish answer = %q, want the assigned %q",
			resp.Msg.OverlaySubnet, want)
	}
	entries, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.Nodes) != 1 {
		t.Fatalf("store holds %d entries, want 1", len(entries.Nodes))
	}
	if !entries.Nodes[0].IA.Equal(publisher) {
		t.Errorf("entry recorded under %s, want the authenticated %s",
			entries.Nodes[0].IA, publisher)
	}

	// A publish without an authenticated ISD-AS never records.
	_, err = svc.Publish(context.Background(),
		connect.NewRequest(&wireguardv1.PublishRequest{Entry: entry.pb()}))
	if err == nil {
		t.Error("publishing without an authenticated ISD-AS succeeded")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Errorf("error code = %s, want permission denied", code)
	}
}

// TestDirectoryListServesEntries checks List serves what Publish recorded —
// nodes beside hosts, one authenticated snapshot, the claimed overlay
// nowhere in it.
func TestDirectoryListServesEntries(t *testing.T) {
	store := &fakeStore{}
	svc := &DirectoryService{Store: store, Cnt: &counters{}}
	ia := addr.MustIAFrom(20, 0xff0000000131)
	entry := Entry{
		IA:           ia,
		PublicKey:    mustPubKey(0xab),
		Overlay:      netip.MustParsePrefix("100.64.7.0/24"),
		HostEndpoint: netip.MustParseAddrPort("198.51.100.20:51820"),
	}
	if _, err := svc.Publish(requestWithIA(t, ia),
		connect.NewRequest(&wireguardv1.PublishRequest{Entry: entry.pb()})); err != nil {
		t.Fatalf("publishing: %v", err)
	}
	entry.Overlay = netip.MustParsePrefix("100.64.0.0/24")
	host := HostEntry{
		PublicKey: mustPubKey(0xcd),
		Addr:      netip.MustParseAddr("100.64.7.9"),
		IA:        ia,
		Note:      "telegram operator",
	}
	if err := store.PublishHost(context.Background(), host); err != nil {
		t.Fatalf("publishing the host: %v", err)
	}
	resp, err := svc.List(context.Background(),
		connect.NewRequest(&wireguardv1.ListRequest{}))
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
	if len(resp.Msg.Hosts) != 1 {
		t.Fatalf("list served %d hosts, want 1", len(resp.Msg.Hosts))
	}
	gotHost, err := hostEntryFromPB(resp.Msg.Hosts[0])
	if err != nil {
		t.Fatal(err)
	}
	if gotHost != host {
		t.Errorf("host entry = %+v, want %+v", gotHost, host)
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
