package measured

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
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

func directoryList(ctx context.Context, svc *DirectoryService) ([]bus.DirectoryEntry, error) {
	resp, err := svc.List(ctx, &nodev1.ListRequest{})
	if err != nil {
		return nil, err
	}
	var out []bus.DirectoryEntry
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
		founderRoute: func() *scion.Addr { return route },
		hclt:         &http.Client{Transport: transport},
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
// is built at each publication from the host of the node's own state — the
// learned external host when one is recorded, else the control host — the
// endpoint and rendezvous ports fixed beside it.
func TestDirectoryPublishResolvesHost(t *testing.T) {
	store := NewDirectoryStore()
	host := netip.MustParseAddr("127.0.0.1")
	self := new(bus.Topic[bus.SelfState])
	self.Publish(bus.SelfState{Host: host})
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA:    directoryIA,
		Self:  self,
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

	// The next publication publishes the host the state holds then: a host
	// learned mid-run follows without a restart.
	host = netip.MustParseAddr("203.0.113.7")
	self.Publish(bus.SelfState{Host: host})
	if err := d.publish(ctx); err != nil {
		t.Fatal(err)
	}
	_, wantRendezvous = published(host)
	if got := store.List(time.Now())[0].RendezvousAddr; got != wantRendezvous {
		t.Errorf("published rendezvous after learning = %v, want %v", got, wantRendezvous)
	}
}

// TestDirectoryPublishesOnSelfEvents checks the publication's wake: the
// entry publishes at once, again at once when the node's own state changes,
// and again on the cadence with no change.
func TestDirectoryPublishesOnSelfEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := NewDirectoryStore()
		first, learned := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.7")
		self := new(bus.Topic[bus.SelfState])
		self.Publish(bus.SelfState{Host: first})
		d := NewNodeDirectory(NodeDirectoryConfig{
			IA:              directoryIA,
			Self:            self,
			Store:           store,
			PublishInterval: time.Minute,
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go d.runPublish(ctx)
		published := func() (netip.Addr, time.Time) {
			entries := store.List(time.Now())
			if len(entries) != 1 {
				t.Fatalf("entries = %v, want the one", entries)
			}
			return entries[0].RendezvousAddr.Addr(), entries[0].Published
		}
		synctest.Wait()
		if host, _ := published(); host != first {
			t.Errorf("the first publication's host = %v, want %v", host, first)
		}

		time.Sleep(time.Second)
		self.Publish(bus.SelfState{Host: learned})
		synctest.Wait()
		host, at := published()
		if host != learned || !at.Equal(time.Now()) {
			t.Errorf("after the state changed: host %v published at %v, want %v at once", host, at, learned)
		}

		time.Sleep(time.Minute)
		synctest.Wait()
		if _, again := published(); !again.Equal(time.Now()) {
			t.Errorf("the cadence's publication landed at %v, want %v", again, time.Now())
		}
	})
}

// listingClient lists the entries it holds, or fails with its error.
type listingClient struct {
	mtx     sync.Mutex
	entries []bus.DirectoryEntry
	err     error
}

func (c *listingClient) set(entries []bus.DirectoryEntry, err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.entries, c.err = entries, err
}

func (c *listingClient) Publish(context.Context, bus.DirectoryEntry) error { return nil }

func (c *listingClient) List(context.Context) ([]bus.DirectoryEntry, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.entries, c.err
}

// TestDirectoryFetchPublishes checks the fetch's publication: each fetch
// publishes the entries it listed on the directory topic, and a failed one
// publishes nothing, the last fetched entries standing.
func TestDirectoryFetchPublishes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := bus.DirectoryEntry{IA: directoryIA,
			RendezvousAddr: netip.MustParseAddrPort("192.0.2.7:30043")}
		second := bus.DirectoryEntry{IA: addr.MustIAFrom(20, 0xfd0000000042),
			RendezvousAddr: netip.MustParseAddrPort("192.0.2.8:30043")}
		client := &listingClient{}
		client.set([]bus.DirectoryEntry{first}, nil)
		topic := new(bus.Topic[bus.Directory])
		d := &NodeDirectory{
			cfg:    NodeDirectoryConfig{Directory: topic, FetchInterval: time.Minute},
			client: client,
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		events := topic.Subscribe(ctx)
		go d.runFetch(ctx)
		// fetched returns the entries of the event published since the last
		// call, and whether one was.
		fetched := func() ([]bus.DirectoryEntry, bool) {
			synctest.Wait()
			select {
			case e := <-events:
				return e.Entries(), true
			default:
				return nil, false
			}
		}
		if got, ok := fetched(); !ok || !slices.Equal(got, []bus.DirectoryEntry{first}) {
			t.Errorf("the first fetch published %v (%t), want the one entry", got, ok)
		}

		client.set(nil, errors.New("the core is unreachable"))
		time.Sleep(time.Minute)
		if got, ok := fetched(); ok {
			t.Errorf("a failed fetch published %v, want nothing", got)
		}
		if got := topic.Latest().Entries(); !slices.Equal(got, []bus.DirectoryEntry{first}) {
			t.Errorf("after a failed fetch the topic holds %v, want the last fetched", got)
		}

		client.set([]bus.DirectoryEntry{first, second}, nil)
		time.Sleep(time.Minute)
		if got, ok := fetched(); !ok || !slices.Equal(got, []bus.DirectoryEntry{first, second}) {
			t.Errorf("the next fetch published %v (%t), want both entries", got, ok)
		}
	})
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
	got := make(map[addr.IA]bus.Reach, len(entries))
	for _, e := range entries {
		got[e.IA] = e.Reach
	}
	want := map[addr.IA]bus.Reach{
		directoryIA: {BehindNAT: true, RendezvousUnanswered: true},
		earlier:     {},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the listed reports mismatch (-want +got):\n%s", diff)
	}
}

// TestDirectoryPublishReportsReach checks the publication's report: each
// publication asks whether a NAT stands at the state's host, and the entry
// carries that beside the state's rendezvous answer, while an ask that fails
// fails the publication, which records nothing.
func TestDirectoryPublishReportsReach(t *testing.T) {
	store := NewDirectoryStore()
	host := netip.MustParseAddr("203.0.113.7")
	report := bus.Reach{BehindNAT: true, RendezvousUnanswered: true}
	self := new(bus.Topic[bus.SelfState])
	self.Publish(bus.SelfState{Host: host, RendezvousUnanswered: true})
	var asked []netip.Addr
	var failure error
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA:   directoryIA,
		Self: self,
		BehindNAT: func(h netip.Addr) (bool, error) {
			asked = append(asked, h)
			return true, failure
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
