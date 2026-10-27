package measured

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

var directoryIA = addr.MustIAFrom(20, 0xfd0000000041)

// directoryPublish calls the handler as the authenticated publisher.
func directoryPublish(
	ctx context.Context, svc *DirectoryService, publisher addr.IA, entry *nodev1.Entry,
) error {

	sctx := context.WithValue(ctx, peeria.AuthenticatedIAContextKey(), publisher)
	_, err := svc.Publish(sctx, &nodev1.PublishRequest{Entry: entry})
	return err
}

func directoryList(ctx context.Context, svc *DirectoryService) ([]DirectoryEntry, error) {
	resp, err := svc.List(ctx, &nodev1.ListRequest{})
	if err != nil {
		return nil, err
	}
	var out []DirectoryEntry
	for _, pb := range resp.Entries {
		entry, err := entryFromPB(pb)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func directoryEntryPB(control, rendezvous string) *nodev1.Entry {
	return &nodev1.Entry{ControlAddr: control, RendezvousAddr: rendezvous}
}

// TestDirectoryPublishRecordsAuthenticatedIA checks the handlers record the
// authenticated ISD-AS: a publish claiming another ISD-AS is recorded under
// the authenticated one, and one without an authenticated ISD-AS never
// records.
func TestDirectoryPublishRecordsAuthenticatedIA(t *testing.T) {
	svc := &DirectoryService{Store: NewDirectoryStore()}
	entry := directoryEntryPB("192.0.2.7:30042", "192.0.2.7:30043")
	entry.IsdAs = uint64(addr.MustIAFrom(20, 0xfd0000000099)) // a false claim
	if err := directoryPublish(context.Background(), svc, directoryIA, entry); err != nil {
		t.Fatal(err)
	}
	entries, err := directoryList(context.Background(), svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IA.Equal(directoryIA) {
		t.Fatalf("entries = %v, want the authenticated %v only", entries, directoryIA)
	}
	if entries[0].ControlAddr != netip.MustParseAddrPort("192.0.2.7:30042") {
		t.Errorf("control address = %v", entries[0].ControlAddr)
	}
	if entries[0].RendezvousAddr != netip.MustParseAddrPort("192.0.2.7:30043") {
		t.Errorf("rendezvous address = %v", entries[0].RendezvousAddr)
	}

	if err := directoryPublish(context.Background(), svc, addr.IA(0),
		directoryEntryPB("192.0.2.7:30042", "192.0.2.7:30043")); err == nil {
		t.Error("a publish without an authenticated ISD-AS was recorded")
	}
	if err := directoryPublish(context.Background(), svc, directoryIA, nil); err == nil {
		t.Error("a publish without an entry was recorded")
	}
	if err := directoryPublish(context.Background(), svc, directoryIA,
		directoryEntryPB("nope", "192.0.2.7:30043")); err == nil {
		t.Error("a publish with a malformed address was recorded")
	}
}

// clientOf returns an HTTP client whose every request the handler serves —
// the connect machinery's round trip with no network beneath it.
func clientOf(h http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result(), nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// idleTransport serves every request through the handler, recording the
// authority each names, and counts the idle-connection closes asked of it.
type idleTransport struct {
	handler http.Handler
	hosts   []string
	closes  int
}

func (tr *idleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.hosts = append(tr.hosts, r.URL.Host)
	w := httptest.NewRecorder()
	tr.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func (tr *idleTransport) CloseIdleConnections() { tr.closes++ }

// TestDirectoryClientReleasesTheReplacedEndpoint checks the client's moved
// route: one HTTP client carries every endpoint the core's route names, an
// unmoved route keeps its endpoint, and a moved one closes the connections
// no request rides — the replaced endpoint's — the request naming the new
// endpoint.
func TestDirectoryClientReleasesTheReplacedEndpoint(t *testing.T) {
	server := connect.NewServer()
	nodev1connect.RegisterDirectoryServiceHandler(server,
		&DirectoryService{Store: NewDirectoryStore()})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	transport := &idleTransport{handler: mux}
	core := addr.MustIAFrom(20, 0xfd0000000001)
	oneHop := &scion.Addr{IA: core, Service: addr.SvcCS, IfID: 1}
	atDistance := &scion.Addr{IA: core, Service: addr.SvcCS}
	route := oneHop
	rpc := &rpcDirectoryClient{
		coreRoute: func() *scion.Addr { return route },
		hclt:      &http.Client{Transport: transport},
	}

	ctx := t.Context()
	for range 2 {
		if _, err := rpc.List(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if transport.closes != 0 {
		t.Errorf("idle closes while the route stood = %d, want 0", transport.closes)
	}
	route = atDistance
	if _, err := rpc.List(ctx); err != nil {
		t.Fatal(err)
	}
	if transport.closes != 1 {
		t.Errorf("idle closes once the route moved = %d, want 1", transport.closes)
	}
	want := []string{
		scionrpc.PeerAuthority(oneHop), scionrpc.PeerAuthority(oneHop),
		scionrpc.PeerAuthority(atDistance),
	}
	if !slices.Equal(transport.hosts, want) {
		t.Errorf("request authorities = %q, want %q", transport.hosts, want)
	}
}

// TestDirectoryReadBound checks the channel's adopted default read bound: a
// publish past the 4 MiB the connect server reads is refused where it
// enters, the entry never reaching the store.
func TestDirectoryReadBound(t *testing.T) {
	svc := &DirectoryService{Store: NewDirectoryStore()}
	server := connect.NewServer()
	nodev1connect.RegisterDirectoryServiceHandler(server, svc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	clt := nodev1connect.NewDirectoryServiceClient(connect.NewClient(
		connecthttp.NewTransport(clientOf(mux), "https://core")))

	oversized := directoryEntryPB(strings.Repeat("a", 5<<20), "192.0.2.7:30043")
	ctx := context.WithValue(context.Background(),
		peeria.AuthenticatedIAContextKey(), directoryIA)
	_, err := clt.Publish(ctx, &nodev1.PublishRequest{Entry: oversized})
	if code := connect.CodeOf(err); code != connect.CodeResourceExhausted {
		t.Errorf("the oversized publish = %v, want resource exhaustion", err)
	}
	if entries := svc.Store.List(time.Now()); len(entries) != 0 {
		t.Errorf("the refused publish recorded %d entries, want none", len(entries))
	}
}

// TestDirectoryExpiry checks the TTL: entries expire without refresh, the
// list serving only the fresh ones. The TTL's passage is a fake-time sleep
// in the bubble.
func TestDirectoryExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := &DirectoryService{Store: NewDirectoryStore()}
		if err := directoryPublish(context.Background(), svc, directoryIA,
			directoryEntryPB("192.0.2.7:30042", "192.0.2.7:30043")); err != nil {
			t.Fatal(err)
		}
		other := addr.MustIAFrom(20, 0xfd0000000042)
		if err := directoryPublish(context.Background(), svc, other,
			directoryEntryPB("192.0.2.8:30042", "192.0.2.8:30043")); err != nil {
			t.Fatal(err)
		}

		// A refresh of the first publisher only.
		time.Sleep(NodeDirectoryTTL / 2)
		if err := directoryPublish(context.Background(), svc, directoryIA,
			directoryEntryPB("192.0.2.7:30042", "192.0.2.7:30043")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(NodeDirectoryTTL)
		entries, err := directoryList(context.Background(), svc)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || !entries[0].IA.Equal(directoryIA) {
			t.Fatalf("entries after the TTL = %v, want the refreshed one only", entries)
		}

		// Beyond every refresh, the directory empties.
		time.Sleep(2 * NodeDirectoryTTL)
		entries, err = directoryList(context.Background(), svc)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("entries beyond every TTL = %v, want none", entries)
		}
	})
}

// TestDirectoryPublishResolvesHost checks the publication's host: the entry
// is built at each cadence from the host the configuration resolves — the
// learned external host when one is recorded, else the control host — the
// endpoint and rendezvous ports fixed beside it.
func TestDirectoryPublishResolvesHost(t *testing.T) {
	store := NewDirectoryStore()
	host := netip.MustParseAddr("127.0.0.1")
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA:    directoryIA,
		Host:  func(context.Context) netip.Addr { return host },
		Store: store,
	})
	ctx := context.Background()
	if err := d.publish(ctx); err != nil {
		t.Fatal(err)
	}
	entries := store.List(time.Now())
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want the one", entries)
	}
	published := func(host netip.Addr) (control, rendezvous netip.AddrPort) {
		return netip.AddrPortFrom(host, scionrpc.EndpointPort),
			netip.AddrPortFrom(host, RendezvousPort)
	}
	wantControl, wantRendezvous := published(host)
	if entries[0].ControlAddr != wantControl || entries[0].RendezvousAddr != wantRendezvous {
		t.Errorf("published addresses = %v, %v, want %v, %v",
			entries[0].ControlAddr, entries[0].RendezvousAddr, wantControl, wantRendezvous)
	}

	// The next cadence publishes the host it resolves then: a host learned
	// mid-run follows without a restart.
	host = netip.MustParseAddr("203.0.113.7")
	if err := d.publish(ctx); err != nil {
		t.Fatal(err)
	}
	_, wantRendezvous = published(host)
	if got := store.List(time.Now())[0].RendezvousAddr; got != wantRendezvous {
		t.Errorf("published rendezvous after learning = %v, want %v", got, wantRendezvous)
	}
}

// TestDirectoryCarriesTheReach checks the report rides the directory: a
// publisher's report lists as published, and an entry without one — an
// earlier publisher's — lists the zero report.
func TestDirectoryCarriesTheReach(t *testing.T) {
	svc := &DirectoryService{Store: NewDirectoryStore()}
	reported := directoryEntryPB("192.0.2.7:30042", "192.0.2.7:30043")
	reported.BehindNat = true
	reported.RendezvousUnanswered = true
	if err := directoryPublish(context.Background(), svc, directoryIA, reported); err != nil {
		t.Fatal(err)
	}
	earlier := addr.MustIAFrom(20, 0xfd0000000042)
	if err := directoryPublish(context.Background(), svc, earlier,
		directoryEntryPB("192.0.2.8:30042", "192.0.2.8:30043")); err != nil {
		t.Fatal(err)
	}
	entries, err := directoryList(context.Background(), svc)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[addr.IA]Reach, len(entries))
	for _, e := range entries {
		got[e.IA] = e.Reach
	}
	want := map[addr.IA]Reach{
		directoryIA: {BehindNAT: true, RendezvousUnanswered: true},
		earlier:     {},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the listed reports mismatch (-want +got):\n%s", diff)
	}
}

// TestDirectoryPublishReportsReach checks the publication's report: each
// cadence asks it at the host it resolved and the entry carries it, while a
// report that fails fails the publication, which records nothing.
func TestDirectoryPublishReportsReach(t *testing.T) {
	store := NewDirectoryStore()
	host := netip.MustParseAddr("203.0.113.7")
	report := Reach{BehindNAT: true, RendezvousUnanswered: true}
	var asked []netip.Addr
	var failure error
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA:   directoryIA,
		Host: func(context.Context) netip.Addr { return host },
		Reach: func(h netip.Addr) (Reach, error) {
			asked = append(asked, h)
			return report, failure
		},
		Store: store,
	})
	ctx := context.Background()

	failure = errors.New("binding the published host failed")
	if err := d.publish(ctx); err == nil {
		t.Fatal("a publication whose report failed succeeded")
	}
	if entries := store.List(time.Now()); len(entries) != 0 {
		t.Fatalf("a failed report recorded %v, want nothing", entries)
	}

	failure = nil
	if err := d.publish(ctx); err != nil {
		t.Fatal(err)
	}
	if entries := store.List(time.Now()); len(entries) != 1 || entries[0].Reach != report {
		t.Fatalf("entries = %v, want the one carrying %+v", entries, report)
	}
	if want := []netip.Addr{host, host}; !slices.Equal(asked, want) {
		t.Errorf("reports asked at %v, want %v", asked, want)
	}
}
