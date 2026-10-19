package testnetwork

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// fastPacing paces the assembly's loops for the integration tests. BFD keeps
// the production interval: its detection time rides out the stalls of a
// loaded runner, which at a lab interval take every link down, lose the
// echoes in flight, and leave the selection to retire live links. The
// selection windows are long enough that the three a retirement counts
// outlast a BFD detection and the re-handshake after it, so a stall that
// drops a session on one side does not retire the link on that side alone.
var fastPacing = services.NodePacing{
	Propagation:     Propagation,
	Registration:    Registration,
	Enrollment:      EnrollRetry,
	Selection:       2 * time.Second,
	CandidateWindow: 5 * time.Second,
	Directory:       100 * time.Millisecond,
	RendezvousRate:  10 * time.Millisecond,
	LinkSetPoll:     100 * time.Millisecond,
	BFD:             liveness.BFDTransmissionInterval,
}

// assemblyNode is a node booted through the run command's own assembly.
type assemblyNode struct {
	app      *services.App
	stateDir string
	host     netip.Addr
}

// rendezvousOf returns the node's advertised rendezvous address: the
// control address's host on the fixed rendezvous port.
func (n *assemblyNode) rendezvousOf() string {
	return netip.AddrPortFrom(n.host, measured.RendezvousPort).String()
}

// stop stops the node, its loops returned and its resources released when
// stop returns, and fails the test on the node's stop result.
func (n *assemblyNode) stop(t *testing.T) {
	t.Helper()
	if err := n.app.Close(); err != nil {
		t.Fatalf("stopping %v: %v", n.app.IA(), err)
	}
}

// conn binds a SCION conn on the node's control host at an ephemeral port,
// sending through the node's internal link, and closes it with the test.
func (n *assemblyNode) conn(t *testing.T) *scion.Conn {
	t.Helper()
	conn, err := n.app.Conn(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// forwardingKey reads the forwarding key the node's boot wrote to its
// state: the key its data plane verifies its own hop fields with.
func (n *assemblyNode) forwardingKey(t *testing.T) []byte {
	t.Helper()
	key, err := trust.LoadOrCreateForwardingKey(n.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// bootAssembly boots a full node assembly — the run command's own wiring —
// and serves it underneath the test, stopping it at cleanup.
func bootAssembly(t *testing.T, mutate func(*services.NodeConfig)) *assemblyNode {
	t.Helper()
	cfg := services.NodeConfig{
		Domain: webpkitest.Domain,
		Pacing: fastPacing,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if cfg.State == "" {
		cfg.State = t.TempDir()
	}
	app, err := services.BootApp(t.Context(), cfg, underlay.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	n := &assemblyNode{app: app, stateDir: cfg.State}
	t.Cleanup(func() {
		if err := app.Close(); err != nil {
			t.Errorf("stopping %v: %v", app.IA(), err)
		}
	})
	// The control address's host is the address the lab's helpers name a
	// peer by, the bare-host form included — its port derived the same way
	// the resolution derives it.
	ap, err := underlay.ResolveAddrPortDefault(cfg.Control, scionrpc.EndpointPort)
	if err != nil {
		t.Fatal(err)
	}
	n.host = ap.Addr()
	return n
}

// pingFrom pings the destination once through the node's own assembly,
// reporting success. The responder runs beside every node's control
// endpoint, as the daemon serves it.
func pingFrom(ctx context.Context, n *assemblyNode, dst addr.IA, host netip.Addr) bool {
	return pingOver(ctx, n, n.app.Provider(), dst, host)
}

// pingOver is pingFrom resolving the path through the given provider.
func pingOver(ctx context.Context, n *assemblyNode, provider *scion.PathProvider,
	dst addr.IA, host netip.Addr) bool {

	conn, err := n.app.Conn(0)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	report, err := ping.Run(ctx, ping.Config{
		Conn:     conn,
		Paths:    provider,
		Dst:      dst,
		DstHost:  host,
		Count:    1,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
	return err == nil && report.Received == 1
}

// entryOf returns the node's link entry of a neighbor: its live one, the
// store holding at most one, else a retired one.
func entryOf(ctx context.Context, n *assemblyNode, ia addr.IA) *links.Link {
	entries, err := n.app.Links().All(ctx)
	if err != nil {
		return nil
	}
	var retired *links.Link
	for _, l := range entries {
		if !l.NeighborIA.Equal(ia) {
			continue
		}
		if l.Live() {
			return l
		}
		retired = l
	}
	return retired
}

// markedDown reports whether the node treats the interface's link as down:
// its BFD verdict is down, or the link left the serving set. The monitor
// drops a departed link's session and reports an interface it holds no
// session for as up, so a link that retires before a poll reads its verdict
// reads as up from then on.
func markedDown(ctx context.Context, n *assemblyNode, ifID uint16) bool {
	if !n.app.Monitor().Up(ifID) {
		return true
	}
	entries, err := n.app.Links().All(ctx)
	if err != nil {
		return false
	}
	for _, l := range entries {
		if l.IfID == ifID && l.Serving() {
			return false
		}
	}
	return true
}

// linkPortsInBand checks that every entry of the node holds its local
// address in the link band, where no bind of port 0 lands.
func linkPortsInBand(t *testing.T, n *assemblyNode) {
	t.Helper()
	entries, err := n.app.Links().All(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if p := l.Local.Port(); p < measured.LinkPortBase ||
			p >= measured.LinkPortBase+measured.LinkPortSpan {
			t.Errorf("%v's entry for %v lies on %v, outside the link band",
				n.app.IA(), l.NeighborIA, l.Local)
		}
	}
}

// establishedTo reports whether the node holds an established entry of the
// neighbor: re-establishment past a retirement mints a second entry beside
// the retired first, so the live one is what the polls want.
func establishedTo(ctx context.Context, n *assemblyNode, ia addr.IA) bool {
	entries, err := n.app.Links().All(ctx)
	if err != nil {
		return false
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) && l.State == links.StateEstablished {
			return true
		}
	}
	return false
}

// bootRendezvousLine brings up the assembly's three-node line — the
// founding core A, the middle B joined to it by rendezvous, and C below
// joined to B — on the given loopback hosts, each node's run arguments
// taking the mutation last when one is set.
func bootRendezvousLine(t *testing.T, wpki *webpkitest.CA, ipA, ipB, ipC netip.Addr,
	mutate func(*services.NodeConfig)) (a, b, c *assemblyNode) {

	t.Helper()
	last := func(cfg *services.NodeConfig) {
		if mutate != nil {
			mutate(cfg)
		}
	}
	// The founding core; its certificate files are the offline fallback the
	// tests always take.
	a = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		last(cfg)
	})
	// B joins the core by rendezvous, its neighbor a bare host — the port
	// the argument's grammar defaults.
	b = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.host.String()}
		cfg.RootCAs = wpki.Pool
		last(cfg)
	})
	// C joins B — a non-core neighbor — with the core's domain.
	c = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
		last(cfg)
	})
	return a, b, c
}

// TestJoinByRendezvous is the rendezvous join's integration proof: a
// three-node line — the core A, the middle B, and C below — where B and C join by
// rendezvous with one bootstrap neighbor and the core's domain, enroll,
// publish, and fetch the node directory; C probes A by rendezvous echo
// against the two-hop path and promotes the direct link below the
// redundancy floor; killing B leaves C connected through A; and a bare
// restart serves from the persisted link store without rendezvous.
func TestJoinByRendezvous(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB, ipC := hostSlot(t), hostSlot(t), hostSlot(t)
	a, b, c := bootRendezvousLine(t, wpki, ipA, ipB, ipC, nil)
	ctx := t.Context()

	// The joins land: both sides of each link hold an entry, each naming
	// its neighbor from the rendezvous exchange alone.
	Poll(t, "B's link to A", func() bool {
		e := entryOf(ctx, b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "A's link to B", func() bool {
		e := entryOf(ctx, a, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C's link to B", func() bool {
		e := entryOf(ctx, c, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})

	// B and C enroll through the joined links.
	Poll(t, "B enrolled", func() bool { return pingFrom(ctx, b, a.app.IA(), a.host) })
	Poll(t, "C enrolled", func() bool { return pingFrom(ctx, c, a.app.IA(), a.host) })

	// C publishes and fetches the directory, probes A by rendezvous echo
	// against the two-hop path, and promotes the direct link — below the
	// floor of two, outright on reachability.
	Poll(t, "C's direct link to A", func() bool {
		e := entryOf(ctx, c, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "A's link to C", func() bool {
		e := entryOf(ctx, a, c.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	// Every link the joins and the promotion allocated lies in the band.
	for _, n := range []*assemblyNode{a, b, c} {
		linkPortsInBand(t, n)
	}

	// The traffic of the swap survives: echo runs before and after the
	// promotion answer across the swap's bounded loss burst — a request
	// landing inside it is retried, as QUIC retransmits through any
	// internet loss.
	PollFor(t, 10*time.Second, "C's echo to A after the generation swap", func() bool {
		return pingFrom(ctx, c, a.app.IA(), a.host)
	})

	// The precondition of the episode below: A's beacons over the direct
	// link have reached C and terminated into a direct up segment — the
	// route that takes over when B dies. Without it, the takeover races
	// the beaconing convergence.
	Poll(t, "C's direct up segment from A", func() bool {
		segs, err := c.app.PathDB().Get(ctx, pathdb.Query{
			Type:  pathdb.SegmentTypeUp,
			SrcIA: a.app.IA(),
		})
		if err != nil {
			return false
		}
		for _, s := range segs {
			if len(s.PCB.Entries) == 2 {
				return true
			}
		}
		return false
	})

	// Killing B leaves C connected through A.
	cbIfID := entryOf(ctx, c, b.app.IA()).IfID
	b.stop(t)
	// C marks its link to B down — the condition the wait wants, not a
	// fixed multiple of the transmission interval — so the composed route
	// crosses no link the monitor distrusts or the node no longer serves.
	Poll(t, "C to mark the C–B link down", func() bool {
		return markedDown(ctx, c, cbIfID)
	})
	// The freshest up segment — A's beacon over the direct link — takes
	// over from the one through the dead B.
	PollFor(t, 10*time.Second, "C's path to A after B died", func() bool {
		return pingFrom(ctx, c, a.app.IA(), a.host)
	})

	// A bare restart — the same state directory, no rendezvous — serves from
	// the persisted link store.
	b2 := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = b.stateDir
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.RootCAs = wpki.Pool
	})
	Poll(t, "the restarted B serves its persisted link", func() bool {
		e := entryOf(ctx, b2, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	linkPortsInBand(t, b2)
	Poll(t, "the restarted B reaches A", func() bool {
		return pingFrom(ctx, b2, a.app.IA(), a.host)
	})
}

// TestJoinByAddressIdentity is the address identity's join proof: the
// founding core's --trust.domain a public address — the control host's own,
// as the resolution pins it — its certificate the address-shaped one the
// test CA mints, and the joiner's --trust.domain the same literal. The
// joiner's bootstrap client arrives nameless — Go's client omitting the SNI
// extension for an address-shaped server name — and the endpoint's demux
// hands it the WebPKI channel; over it the joiner fetches the TRC and
// enrolls, and the core's published host is the literal its sockets bind.
func TestJoinByAddressIdentity(t *testing.T) {
	t.Parallel()
	ipA, ipB := hostSlot(t), hostSlot(t)
	wpki := webpkitest.NewFor(t, ipA)
	identity := ipA.String()
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Domain = identity
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.AddrCertFile
		cfg.KeyFile = wpki.AddrKeyFile
	})
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Domain = identity
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	ctx := t.Context()

	Poll(t, "B's link to the core", func() bool {
		e := entryOf(ctx, b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	// The TRC the enrollment verifies against came through the address
	// identity's channel, the first fetch the WebPKI anchors.
	Poll(t, "B fetched the TRC over the address identity", func() bool {
		trc, err := b.app.TrustDB().SignedTRC(ctx, trust.NewestTRCID(a.app.IA().ISD()))
		return err == nil && !trc.IsZero()
	})
	Poll(t, "B enrolled over the address identity", func() bool {
		return pingFrom(ctx, b, a.app.IA(), a.host)
	})
}

// TestLineCutHeals is the cut's integration proof: the three-node line —
// the core A, the middle B, and C below — where killing B leaves C with
// every route to A crossing the dead link. C, below the floor of up links,
// promotes A outright, the establishment riding the rendezvous exchange —
// for no composed path resolves — and the dead link retires once the new
// segments serve the tier.
func TestLineCutHeals(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB, ipC := hostSlot(t), hostSlot(t), hostSlot(t)
	a, b, c := bootRendezvousLine(t, wpki, ipA, ipB, ipC, nil)
	ctx := t.Context()

	// The joins land and C enrolls through the line.
	Poll(t, "B's link to A", func() bool {
		e := entryOf(ctx, b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C's link to B", func() bool {
		e := entryOf(ctx, c, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C enrolled through B", func() bool { return pingFrom(ctx, c, a.app.IA(), a.host) })
	// The cut's precondition: C's directory holds A — proven by C's probe of
	// A landing on A's acceptor — for the snapshot is the last one C fetches
	// through B, and without it the cut leaves C nothing to promote.
	Poll(t, "C's directory to hold A", func() bool {
		entries, err := a.app.Links().All(ctx)
		if err != nil {
			return false
		}
		for _, l := range entries {
			if l.Live() && l.Remote.Addr() == c.host {
				return true
			}
		}
		return false
	})

	// Killing B strands C: every route from C to A crossed the dead link.
	cbIfID := entryOf(ctx, c, b.app.IA()).IfID
	b.stop(t)
	Poll(t, "C to mark the C–B link down", func() bool {
		return markedDown(ctx, c, cbIfID)
	})

	// C promotes A below the floor of up links — reachability outranking
	// latency — and the establishment rides the rendezvous exchange, for no
	// composed path resolves into the stranded tier.
	Poll(t, "C's direct link to A", func() bool { return establishedTo(ctx, c, a.app.IA()) })
	Poll(t, "A's link to C", func() bool { return establishedTo(ctx, a, c.app.IA()) })

	// The traffic of the generation swaps survives.
	PollFor(t, 10*time.Second, "C's echo to A after the cut healed", func() bool {
		return pingFrom(ctx, c, a.app.IA(), a.host)
	})

	// The dead link retires once the new segments serve the tier: the
	// verdict stayed down across the sustained window.
	Poll(t, "the dead link to retire", func() bool {
		e := entryOf(ctx, c, b.app.IA())
		return e != nil && e.State == links.StateRetired
	})
}

// TestBootstrapWithoutAnswer checks the negative: a first start whose
// bootstrap neighbor never answers its rendezvous fails cleanly — no
// identity persists, nothing was allocated on any acceptor — and a retry
// once a neighbor exists draws a fresh identity and joins.
func TestBootstrapWithoutAnswer(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipD := hostSlot(t), hostSlot(t)
	dead := FreeUDPAddrOn(t, ipA) // reserved, then released: nothing answers
	state := t.TempDir()

	func() {
		ctx, cancel := context.WithCancel(t.Context())
		_, err := services.BootApp(ctx, services.NodeConfig{
			Domain:    webpkitest.Domain,
			State:     state,
			Internal:  PinnedUDPAddrOn(t, ipD),
			Control:   FreeUDPAddrOn(t, ipD),
			Neighbors: []string{dead},
			RootCAs:   wpki.Pool,
			Pacing:    fastPacing,
		}, underlay.Kernel)
		defer cancel()
		if err == nil {
			t.Fatal("a first start whose bootstrap neighbor never answered succeeded")
		}
	}()

	// Nothing persisted: the identity stays unset for a fresh draw.
	if ia, err := trust.LoadIA(state); err != nil || !ia.IsZero() {
		t.Fatalf("identity after the failed bootstrap = %v (%v), want unset", ia, err)
	}

	// A core comes up; the retry joins it and completes its identity.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = state
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	Poll(t, "the retried join to land", func() bool {
		e := entryOf(t.Context(), d, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	if got := d.app.IA().ISD(); got != a.app.IA().ISD() {
		t.Errorf("the joiner's ISD = %d, want the network's %d", got, a.app.IA().ISD())
	}
}

// TestHeldHostPortRefusesBoot checks the default's failure mode: a boot
// against a shared port another socket already holds — the machine's
// existing WireGuard interface — fails loudly at the bind, the argument's
// override the remedy. The refusal releases what the boot acquired: once the
// held socket closes, a second boot on the same host and state succeeds,
// the endpoint, responder, and rendezvous ports free again.
func TestHeldHostPortRefusesBoot(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ip := hostSlot(t)
	held, err := net.ListenUDP("udp",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, apps.DefaultHostPort)))
	if err != nil {
		t.Fatal(err)
	}

	cfg := services.NodeConfig{
		Core:     true,
		Domain:   webpkitest.Domain,
		State:    t.TempDir(),
		Internal: PinnedUDPAddrOn(t, ip),
		Control:  FreeUDPAddrOn(t, ip),
		CertFile: wpki.CertFile,
		KeyFile:  wpki.KeyFile,
		AppArguments: apps.Arguments{
			Wireguard: apps.WireguardArguments{HostPort: apps.DefaultHostPort},
		},
	}
	_, err = services.BootApp(t.Context(), cfg, underlay.Kernel)
	_ = held.Close()
	if err == nil {
		t.Fatal("a boot against a held shared port succeeded")
	}
	if want := "binding the host port"; !strings.Contains(err.Error(), want) {
		t.Errorf("the boot's refusal = %v, want it to name %q", err, want)
	}

	app, err := services.BootApp(t.Context(), cfg, underlay.Kernel)
	if err != nil {
		t.Fatalf("a boot on the refused boot's host and state: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Errorf("stopping the second boot: %v", err)
	}
}

// TestHeldStateRefusesBoot checks a second boot on the state directory a
// running node holds — `cion ping` beside the daemon — fails at the store
// lock's bound with the directory named, instead of waiting on the lock.
func TestHeldStateRefusesBoot(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ip := hostSlot(t)
	running := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Applications = []string{}
		cfg.Internal = PinnedUDPAddrOn(t, ip)
		cfg.Control = FreeUDPAddrOn(t, ip)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})

	app, err := services.BootApp(t.Context(), services.NodeConfig{
		Core:         true,
		Applications: []string{},
		Domain:       webpkitest.Domain,
		State:        running.stateDir,
		Internal:     PinnedUDPAddrOn(t, ip),
		Control:      FreeUDPAddrOn(t, ip),
		CertFile:     wpki.CertFile,
		KeyFile:      wpki.KeyFile,
	}, underlay.Kernel)
	if err == nil {
		_ = app.Close()
		t.Fatal("a second boot on the held state directory succeeded")
	}
	if want := "the state directory " + running.stateDir + " is in use"; !strings.Contains(err.Error(), want) {
		t.Errorf("the boot's refusal = %v, want it to name %q", err, want)
	}
}

// TestCoreRestartsInPlace checks the restart a process supervisor performs:
// a core stopped and booted again three times on the same state and
// addresses boots at once each time — the stopped node's every socket
// released when its Close returns, the WireGuard application's fixed host
// port among them — and a joiner enrolls against the last.
func TestCoreRestartsInPlace(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB := hostSlot(t), hostSlot(t)
	state := t.TempDir()
	internal, control := PinnedUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipA)
	// The shared host port is drawn from the pinned band, for a WireGuard
	// interface on the test host may hold the default.
	hostPort := netip.MustParseAddrPort(PinnedUDPAddrOn(t, ipA)).Port()
	boot := func() *assemblyNode {
		return bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.Applications = []string{"wireguard", "voting"}
			cfg.AppArguments.Wireguard.HostPort = hostPort
			cfg.State = state
			cfg.Internal = internal
			cfg.Control = control
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
	}
	a := boot()
	for range 3 {
		a.stop(t)
		a = boot()
	}

	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	Poll(t, "the joiner to enroll against the last boot", func() bool {
		return holdsChain(t.Context(), b)
	})
}

// TestDeliberateCore is the empty list's proof: a core and a joiner that
// name --applications empty — the deliberate core, no application loaded
// — join and enroll over the control endpoint's own services, and neither
// node binds any application surface: the pure forwarder a stated shape
// rather than an accident of unset arguments.
func TestDeliberateCore(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB := hostSlot(t), hostSlot(t)

	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Applications = []string{}
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Applications = []string{}
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})

	Poll(t, "the joiner's link to the core", func() bool {
		e := entryOf(t.Context(), b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "the joiner enrolled", func() bool {
		return pingFrom(t.Context(), b, a.app.IA(), a.host)
	})
	for _, node := range []struct {
		name string
		app  *services.App
	}{{"the core", a.app}, {"the joiner", b.app}} {
		for _, resident := range []string{"wireguard", "coordination", "socks"} {
			if got := node.app.Application(resident); got != nil {
				t.Errorf("%s loaded the %s application beside an empty list",
					node.name, resident)
			}
		}
	}
}
