package controlplane

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
	"github.com/fancl20/cion/pkg/scion"
)

const (
	testIfID   = 1
	testMACKey = "0123456789abcdef"
)

var testMACKeyBytes = []byte(testMACKey)

// testNode is one CION node: data plane with an internal and an external
// link, plus a registered discovery service.
type testNode struct {
	ia        addr.IA
	neighbor  addr.IA
	ifID      uint16
	internal  string
	controlIP netip.Addr
	provider  *dataplane.UDPProvider
	store     *memory.DB
	discovery *Discovery
	cancel    context.CancelFunc
}

// startTestNode brings up the node; extRemote must be the neighbor node's
// extLocal, so that traffic crosses the data plane over the direct link
// exactly as between two deployed nodes.
func startTestNode(t *testing.T, ia, neighbor addr.IA, extLocal, extRemote string) *testNode {
	t.Helper()

	internal, control := freeUDPAddr(t), freeUDPAddr(t)
	controlAddr, err := netip.ParseAddrPort(control)
	if err != nil {
		t.Fatal(err)
	}

	store := memory.New()
	entry := &links.Link{
		NeighborIA: neighbor,
		Local:      netip.MustParseAddrPort(extLocal),
		Remote:     netip.MustParseAddrPort(extRemote),
		State:      links.StateEstablished,
	}
	if err := store.Insert(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0)
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	el, err := provider.NewExternalLink(64, nil, extLocal, extRemote, entry.IfID,
		metrics.NewInterfaceMetrics(entry.IfID, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	local := addr.HostIP(controlAddr.Addr())
	d, err := dataplane.NewDataPlane(ia, local, testMACKeyBytes, provider,
		[]dataplane.Link{il, el})
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{
		NumProcessors:         2,
		NumSlowPathProcessors: 1,
		BatchSize:             64,
	}
	discovery, err := NewDiscovery(DiscoveryConfig{
		IA:           ia,
		ControlAddr:  control,
		MACKey:       testMACKeyBytes,
		InternalAddr: internal,
		Store:        store,
		Interval:     discoveryGap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := discovery.Register(provider); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		provider.Stop()
		discovery.Close() //nolint:errcheck
	})
	go func() { _ = d.Serve(ctx) }()
	go discovery.Run(ctx)

	return &testNode{
		ia:        ia,
		neighbor:  neighbor,
		ifID:      entry.IfID,
		internal:  internal,
		controlIP: controlAddr.Addr(),
		provider:  provider,
		store:     store,
		discovery: discovery,
		cancel:    cancel,
	}
}

// newConn returns a SCION connection of the node, bound to the control
// address's host with the given port.
func (n *testNode) newConn(t *testing.T, port uint16) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           n.ia,
		Bind:         netip.AddrPortFrom(n.controlIP, port).String(),
		InternalAddr: n.internal,
		MACKey:       testMACKeyBytes,
		Links:        n.linkTable,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return conn
}

// linkTable snapshots the node's link table for its connections.
func (n *testNode) linkTable() map[uint16]addr.IA {
	entries, err := n.store.All(context.Background())
	if err != nil {
		return nil
	}
	return links.Links(entries)
}

// TestPeerAuthorityRoundTrip checks the authority encoding both destination
// forms keep: an underlay peer and a service peer decode back to themselves.
func TestPeerAuthorityRoundTrip(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000021)
	for _, peer := range []*scion.Addr{
		{IA: ia, Addr: netip.MustParseAddrPort("192.0.2.7:30044")},
		{IA: ia, Service: addr.SVC(0x7ff2)},
	} {
		got, err := peerFromAuthority(PeerAuthority(peer))
		if err != nil {
			t.Fatalf("decoding the authority of %s: %v", peer, err)
		}
		if !got.IA.Equal(peer.IA) || got.Addr != peer.Addr || got.Service != peer.Service {
			t.Errorf("authority round trip = %v, want %v", got, peer)
		}
	}
}

// TestSCIONClientServiceWithoutBackend checks the publish-side negative: a
// dial toward a service with no registered backend fails — the receiving
// router answers SCMP destination unreachable, the sender sees the dial time
// out — rather than hanging or succeeding.
func TestSCIONClientServiceWithoutBackend(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000031)
	iaB := addr.MustIAFrom(20, 0xff0000000032)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	startTestNode(t, iaB, iaA, extB, extA)

	conn := a.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { qclt.Close() }) //nolint:errcheck
	// The dial's TLS is never exercised: no backend answers the handshake.
	hclt := NewSCIONClient(PeerClientConfig{Conn: conn}, qclt, false)
	unregistered := &scion.Addr{IA: iaB, Service: addr.SVC(0x7ff2)}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://"+PeerAuthority(unregistered)+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hclt.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a dial to a service with no backend succeeded")
	}
}
