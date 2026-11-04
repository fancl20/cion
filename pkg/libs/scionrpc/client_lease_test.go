package scionrpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// segmentDB is a path database serving the up segments it holds, which a
// test replaces.
type segmentDB struct {
	pathdb.DB

	mtx  sync.Mutex
	segs []*pathdb.Segment
}

func (d *segmentDB) Get(context.Context, pathdb.Query) ([]*pathdb.Segment, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return d.segs, nil
}

// hold replaces the segments the database serves.
func (d *segmentDB) hold(segs ...*pathdb.Segment) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	d.segs = segs
}

// upToCore returns the client node's up segment from the endpoint's node over
// their link, the endpoint's node originating it at origin, each hop MACed
// with the forwarding key the test nodes share.
func upToCore(key []byte, origin time.Time) (*pathdb.Segment, error) {
	pcb, err := segment.PCBWithID(origin, 0x444)
	if err != nil {
		return nil, err
	}
	mac := func() hash.Hash {
		h, _ := scrypto.InitMac(key)
		return h
	}
	if _, err := pcb.AppendRouteHop(nodeIATest,
		segment.EntryOptions{EgressIfID: dataplanetest.IfID}, mac); err != nil {
		return nil, err
	}
	if _, err := pcb.AppendRouteHop(iaLineC,
		segment.EntryOptions{IngressIfID: dataplanetest.IfID}, mac); err != nil {
		return nil, err
	}
	return &pathdb.Segment{Type: pathdb.SegmentTypeUp, PCB: pcb}, nil
}

// pathToCore returns the client node's path to the endpoint's node: the
// reversal of its up segment originated at origin.
func pathToCore(key []byte, origin time.Time) (*spath.Decoded, error) {
	up, err := upToCore(key, origin)
	if err != nil {
		return nil, err
	}
	return up.PCB.ReversePathTo(0)
}

// providerToCore returns the client node's path provider, its database
// holding the up segment to the endpoint's node originated now.
func providerToCore(t *testing.T, key []byte) (*scion.PathProvider, *segmentDB) {
	t.Helper()
	up, err := upToCore(key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	db := &segmentDB{segs: []*pathdb.Segment{up}}
	return &scion.PathProvider{IA: iaLineC, DB: db}, db
}

// countingTLS has the endpoint's TLS configuration count the handshakes it
// begins: a client's dials that reach it.
func countingTLS(cfg *tls.Config, handshakes *atomic.Int32) *tls.Config {
	pick := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		return pick(chi)
	}
	return cfg
}

// waitFor waits until the condition holds, checking it every few
// milliseconds, and fails the test once the deadline passes first: past
// three idle timeouts.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(15 * time.Second)
	for !cond() {
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// leaseFixture is an endpoint served on one node and a client of it on the
// other, every dial riding the endpoint's lease and counted at the endpoint.
// The endpoint answers /hold only once the request ends.
type leaseFixture struct {
	ctx      context.Context
	hclt     *http.Client
	url      string
	key      []byte
	endpoint *scion.Conn
	provider *scion.PathProvider
	db       *segmentDB
	dials    atomic.Int32
}

func newLeaseFixture(t *testing.T) *leaseFixture {
	t.Helper()
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	provider, db := providerToCore(t, peer.MACKey)
	endpoint := core.newConn(t, 0)
	fx := &leaseFixture{ctx: ctx, key: peer.MACKey, endpoint: endpoint, provider: provider, db: db}

	served := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-served:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("ServeHTTP3 returned (%v), want the closed socket's error", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the endpoint did not stop with the test's context")
		}
	})
	go func() {
		served <- ServeHTTP3(t.Context(), endpoint,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/hold" {
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte("ok"))
			}),
			countingTLS(EndpointTLS(EndpointTLSConfig{Credentials: f.engine, Key: f.engine.Key}), &fx.dials))
	}()

	conn := peer.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	fx.hclt = NewSCIONClient(PeerClientConfig{
		Credentials: f.peer,
		Key:         f.peer.Key,
		Conn:        conn,
		Lease:       provider.Lease,
	}, qclt, true)
	server := &scion.Addr{IA: nodeIATest, Addr: netip.AddrPortFrom(core.ControlIP, endpoint.LocalPort())}
	fx.url = "https://" + PeerAuthority(server)
	return fx
}

// fetch requests the endpoint's root and returns an error unless it answers.
func (fx *leaseFixture) fetch() error {
	return fx.get(fx.ctx, "/")
}

// get requests the endpoint's target within ctx and returns an error unless
// it answers.
func (fx *leaseFixture) get(ctx context.Context, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fx.url+target, nil)
	if err != nil {
		return err
	}
	resp, err := fx.hclt.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if string(body) != "ok" {
		return fmt.Errorf("the response = %q, want %q", body, "ok")
	}
	return nil
}

// health returns the health of the one path the provider composes to the
// endpoint's node.
func (fx *leaseFixture) health(t *testing.T) scion.Health {
	t.Helper()
	candidates, err := fx.provider.Enumerate(fx.ctx, nodeIATest)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("%d candidates to the endpoint's node, want 1", len(candidates))
	}
	return candidates[0].Health
}

// TestSCIONClientRidesTheLease checks a client over a lease: requests share
// the connection dialed over the leased path, whose handshake confirms the
// path though no response came, and whose responses confirm it again after
// a loss doubted it.
func TestSCIONClientRidesTheLease(t *testing.T) {
	fx := newLeaseFixture(t)
	if got := fx.health(t); got != scion.HealthUnknown {
		t.Fatalf("the path's health before any request = %v, want unknown", got)
	}
	ctx, cancel := context.WithTimeout(fx.ctx, 500*time.Millisecond)
	defer cancel()
	if err := fx.get(ctx, "/hold"); err == nil {
		t.Fatal("the held request answered")
	}
	if got := fx.health(t); got != scion.HealthHealthy {
		t.Errorf("the path's health after the handshake = %v, want healthy", got)
	}
	lease := fx.provider.Lease(nodeIATest)
	leased, err := lease.Peek()
	if err != nil {
		t.Fatal(err)
	}
	lease.Lost(leased.ID)
	if got := fx.health(t); got != scion.HealthSuspect {
		t.Fatalf("the path's health after a loss = %v, want suspect", got)
	}
	for i := range 2 {
		if err := fx.fetch(); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := fx.dials.Load(); got != 1 {
		t.Errorf("dials = %d, want 1: every request rode the first's connection", got)
	}
	if got := fx.health(t); got != scion.HealthHealthy {
		t.Errorf("the path's health after the responses = %v, want healthy", got)
	}
}

// TestSCIONClientReportsAnIdleTimeout checks a connection gone dark: once
// the endpoint's socket closes, the connection's idle timeout doubts its
// path.
func TestSCIONClientReportsAnIdleTimeout(t *testing.T) {
	fx := newLeaseFixture(t)
	if err := fx.fetch(); err != nil {
		t.Fatal(err)
	}
	_ = fx.endpoint.Close()
	waitFor(t, "the idle timeout to doubt the path", func() bool {
		return fx.health(t) == scion.HealthSuspect
	})
}

// TestSCIONClientRetiresALeftPath checks a lease that left its connection's
// path, for the bootstrap route or for nothing: the next request closes the
// connection and dials anew.
func TestSCIONClientRetiresALeftPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bootstrap bool
	}{
		{"nothing composes", false},
		{"the bootstrap route", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newLeaseFixture(t)
			if tc.bootstrap {
				fx.provider.Bootstrap = func(addr.IA) *spath.Decoded {
					p, err := pathToCore(fx.key, time.Now())
					if err != nil {
						t.Error(err)
					}
					return p
				}
			}
			if err := fx.fetch(); err != nil {
				t.Fatal(err)
			}
			lease := fx.provider.Lease(nodeIATest)
			dialed, err := lease.Peek()
			if err != nil {
				t.Fatal(err)
			}
			fx.db.hold()
			waitFor(t, "the lease to leave the path", func() bool {
				leased, err := lease.Peek()
				return err != nil || leased.ID != dialed.ID
			})
			if err := fx.fetch(); err != nil {
				t.Fatalf("the request after the lease left the path: %v", err)
			}
			if got := fx.dials.Load(); got != 2 {
				t.Errorf("dials = %d, want 2: the lease's move retired the connection", got)
			}
		})
	}
}

// TestSCIONClientRetiresAnExpiringPath checks a connection whose hop fields
// near their expiry while its lease keeps the route over a fresher
// instance: the first request once they lapse within LeaseExpiryMargin dials
// anew, and the lease's path rides on.
func TestSCIONClientRetiresAnExpiringPath(t *testing.T) {
	fx := newLeaseFixture(t)
	lifetime := path.ExpTimeToDuration(segment.HopExpTime)
	aging, err := upToCore(fx.key, time.Now().Add(scion.LeaseExpiryMargin+2*time.Second-lifetime))
	if err != nil {
		t.Fatal(err)
	}
	fx.db.hold(aging)
	if err := fx.fetch(); err != nil {
		t.Fatal(err)
	}
	lease := fx.provider.Lease(nodeIATest)
	dialed, err := lease.Peek()
	if err != nil {
		t.Fatal(err)
	}
	expiry := scion.PathExpiry(dialed.Path)
	if time.Until(expiry) < scion.LeaseExpiryMargin {
		t.Fatalf("the dialed path lapses at %v, within the margin already", expiry)
	}

	fresh, err := upToCore(fx.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fx.db.hold(fresh)
	waitFor(t, "the dialed path to lapse within the margin", func() bool {
		return time.Until(expiry) < scion.LeaseExpiryMargin
	})
	if err := fx.fetch(); err != nil {
		t.Fatalf("the request once the dialed path neared its expiry: %v", err)
	}
	if got := fx.dials.Load(); got != 2 {
		t.Errorf("dials = %d, want 2: the expiring path retired the connection", got)
	}
	leased, err := lease.Peek()
	if err != nil {
		t.Fatal(err)
	}
	if leased.ID != dialed.ID || !scion.PathExpiry(leased.Path).After(expiry) {
		t.Errorf("the lease holds %q lapsing at %v, want %q's fresher instance",
			leased.ID, scion.PathExpiry(leased.Path), dialed.ID)
	}
}

// TestLeasedConnsReportDials checks what a failed dial reports on its leased
// path: a handshake or an idle timeout a loss; a refused handshake, either
// end's, a delivery; and a local transport error or a dial its caller
// abandoned nothing.
func TestLeasedConnsReportDials(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want scion.Health
	}{
		{"handshake timeout", &quic.HandshakeTimeoutError{}, scion.HealthSuspect},
		{"idle timeout", &quic.IdleTimeoutError{}, scion.HealthSuspect},
		{"refused certificate", &quic.TransportError{Remote: true, ErrorCode: 0x100 + 42}, scion.HealthHealthy},
		{"refused connection", &quic.TransportError{Remote: true, ErrorCode: quic.ConnectionRefused}, scion.HealthHealthy},
		{"peer's certificate refused", &quic.TransportError{ErrorCode: 0x100 + 42}, scion.HealthHealthy},
		{"local transport error", &quic.TransportError{ErrorCode: quic.InternalError}, scion.HealthUnknown},
		{"abandoned dial", context.Canceled, scion.HealthUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := providerToCore(t, []byte("0123456789abcdef"))
			lease := provider.Lease(nodeIATest)
			leased, err := lease.Path()
			if err != nil {
				t.Fatal(err)
			}
			conns := &leasedConns{lease: provider.Lease, conns: make(map[string]leasedConn)}
			conns.dialed("peer", nodeIATest, leased, nil, tc.err)
			if len(conns.conns) != 0 {
				t.Errorf("a failed dial held %d connections", len(conns.conns))
			}
			candidates, err := provider.Enumerate(t.Context(), nodeIATest)
			if err != nil {
				t.Fatal(err)
			}
			if len(candidates) != 1 {
				t.Fatalf("%d candidates to the endpoint's node, want 1", len(candidates))
			}
			if got := candidates[0].Health; got != tc.want {
				t.Errorf("the path's health = %v, want %v", got, tc.want)
			}
		})
	}
}
