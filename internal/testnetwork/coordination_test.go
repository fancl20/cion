package testnetwork

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/tsnet"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// TailnetRange is the overlay's host space, mirrored from the application.
var TailnetRange = wireguard.Tailnet

// The coordination suites' topology: the core A and the leaf B of the
// wireguard topology, assembled through the run command's own wiring, the core
// serving the coordination endpoint beside its WireGuard application. The
// hosts are real tailnet clients in-process — the vendored client engine
// (tsnet). Each suite holds its own loopback pair — the fixed endpoint,
// rendezvous, and shared host ports bind on them — so the suites run
// parallel, the hosts dialing the default port unasked.

// coordinationPlacement is the harness's placement of the core's
// coordination endpoint: a loopback address the tailnet clients dial by,
// standing in for the core's domain at the HTTPS port.
type coordinationPlacement struct {
	// addr is the endpoint's "host:port".
	addr string
	// controlURL is the endpoint as the tailnet clients log in against.
	controlURL string
	// derpURL is the relay as the nodes' presences and the clients' relay
	// legs dial it, the protocol's own path included.
	derpURL string
}

// placeCoordination reserves the placement for the core's coordination
// endpoint: a pinned port on 127.0.0.1, the address the lab certificate
// names.
func placeCoordination(t *testing.T) coordinationPlacement {
	t.Helper()
	addr := PinnedTCPAddrOn(t, netip.MustParseAddr("127.0.0.1"))
	return coordinationPlacement{
		addr:       addr,
		controlURL: "https://" + addr,
		derpURL:    "https://" + addr + "/derp",
	}
}

// labKeyPrefix opens the credential a lab host presents to the labs'
// admission policy.
const labKeyPrefix = "lab:"

// labKey is the credential that lands a lab host on the node: the labs'
// stand-in for an auth key an operator minted naming the node.
func labKey(node addr.IA) string { return labKeyPrefix + node.String() }

// labPolicy is the labs' admission policy, loaded through the harness's
// field: nodes enroll openly, the founder's vote is denied, and a
// registration presenting lab:<isd-as> is admitted onto that node while
// any other is denied.
type labPolicy struct{}

func (labPolicy) Authorize(_ context.Context, f enrollauth.AdmissionFacts) enrollauth.AdmissionAnswer {
	switch f.Boundary {
	case enrollauth.BoundaryEnrollment:
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}
	case enrollauth.BoundaryRegistration:
		name, keyed := strings.CutPrefix(f.Credential, labKeyPrefix)
		node, err := addr.ParseIA(name)
		if !keyed || err != nil {
			return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
		}
		return enrollauth.AdmissionAnswer{
			Admission: enrollauth.AdmissionAllow,
			Note:      "lab key",
			Node:      node,
		}
	default:
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	}
}

// coordCore boots the core of the coordination topology on its suite's
// loopback host: the WebPKI certificate files, the wireguard application —
// its tailnet slice the directory's assignment, its hosts dialed on the
// default shared port — and the coordination endpoint beside it, the labs'
// policy admitting where the suite names no method.
func coordCore(t *testing.T, wpki *webpkitest.CA, host netip.Addr,
	place coordinationPlacement, mutate func(*services.NodeConfig)) *assemblyNode {

	t.Helper()
	return bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, host)
		cfg.Control = FreeUDPAddrOn(t, host)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.AppArguments.Wireguard.HostPort = apps.DefaultHostPort
		cfg.Coordination = &services.CoordinationOptions{
			Addr: place.addr,
			DERP: services.DERPOptions{URL: place.derpURL, IPv4: "127.0.0.1"},
			// RelayOnly: true,
		}
		if mutate != nil {
			mutate(cfg)
		}
		if cfg.EnrollAuth == "" {
			cfg.Admission = labPolicy{}
		}
	})
}

// coordLeaf boots the leaf of the coordination topology on its suite's
// loopback host: it joins by rendezvous and runs the wireguard application
// with its relay presence, its tailnet slice the directory's assignment and
// its hosts dialed on the default shared port.
func coordLeaf(t *testing.T, wpki *webpkitest.CA, host netip.Addr, core *assemblyNode,
	place coordinationPlacement, mutate func(*services.NodeConfig)) *assemblyNode {

	t.Helper()
	return bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, host)
		cfg.Control = FreeUDPAddrOn(t, host)
		cfg.Neighbors = []string{core.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
		cfg.AppArguments.Wireguard.HostPort = apps.DefaultHostPort
		cfg.Coordination = &services.CoordinationOptions{
			DERP: services.DERPOptions{URL: place.derpURL, IPv4: "127.0.0.1"},
		}
		if mutate != nil {
			mutate(cfg)
		}
	})
}

// wireguardOf returns the node's booted WireGuard application, where the
// labs watch host peers — the same assertion the borrowing entries make.
func wireguardOf(n *assemblyNode) *wireguard.App {
	return n.app.Application("wireguard").(*wireguard.App)
}

// tailnetHost is a real tailnet client in-process — the vendored client
// engine as the host double: registration, the netmap, and the data plane
// all run through it, NAT traversal and roaming its own.
func tailnetHost(t *testing.T, name, controlURL, authKey string) *tsnet.Server {
	t.Helper()
	logf := func(format string, args ...any) {
		// The client engine's own log beside the test's, for the failures
		// only -v shows.
		t.Logf("tsnet[%s]: "+format, append([]any{name}, args...)...)
	}
	srv := &tsnet.Server{
		Hostname:   name,
		Dir:        filepath.Join(t.TempDir(), name),
		ControlURL: controlURL,
		AuthKey:    authKey,
		Ephemeral:  false,
		Logf:       logf,
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// hostUp logs the host in and waits for its netmap, returning its tailnet
// addresses.
func hostUp(t *testing.T, srv *tsnet.Server) []netip.Addr {
	t.Helper()
	ips, failed := hostUpErr(t, srv, TestTimeout)
	if failed {
		t.Fatal("the host's login never completed")
	}
	return ips
}

// hostUpErr is hostUp's patient form: it reports whether the login
// completed within the budget instead of failing the test, for the suites
// that prove a login never does.
func hostUpErr(t *testing.T, srv *tsnet.Server, budget time.Duration) ([]netip.Addr, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	status, err := srv.Up(ctx)
	if err != nil {
		return nil, true
	}
	return status.TailscaleIPs, false
}

// warmSession dials a far tailnet address from the host, ignoring the
// outcome: the session a host's node needs to reach it begins with the
// host's own outbound exchange — the client protocol's model, the session
// outbound-initiated — and a wireguard-only peer of one endpoint is never
// pinged by the client engine on its own, so the listening host must have
// spoken once before its node can deliver to it.
func warmSession(t *testing.T, srv *tsnet.Server, far netip.Addr) {
	t.Helper()
	// The far end refuses the connection — nothing listens on the port —
	// and that refusal is the exchange the warm-up waits for: the host's
	// own handshake with its node, which the dial's first packets begin,
	// has carried a packet of the far end's back. While the node still
	// drops the host's packets the dial instead times out, so the retries
	// cover the wireguard handshake's own cadence.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		conn, err := srv.Dial(ctx, "tcp",
			netip.AddrPortFrom(far, 1).String())
		cancel()
		if err == nil {
			_ = conn.Close()
			return
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ownerOf returns the node whose slice holds the address.
func ownerOf(t *testing.T, a *assemblyNode, ip netip.Addr) addr.IA {
	t.Helper()
	ctx := t.Context()
	directory, err := wireguardOf(a).Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range directory.Nodes {
		if entry.Overlay.Contains(ip) {
			return entry.IA
		}
	}
	t.Fatalf("no node's slice holds %s", ip)
	return 0
}

// holdsHostEndpoint reports whether the core's registry holds the node's
// entry with its host endpoint: until it does, a registration naming the
// node is refused.
func holdsHostEndpoint(t *testing.T, core *assemblyNode, node addr.IA) bool {
	directory, err := wireguardOf(core).Directory(t.Context())
	if err != nil {
		return false
	}
	return slices.ContainsFunc(directory.Nodes, func(entry wireguard.Entry) bool {
		return entry.IA.Equal(node) && entry.HostEndpoint.IsValid()
	})
}

// echoOverTailnet exchanges one message between two hosts through the
// tunnel: the destination host listens, the source dials, and the echo
// returns — the whole path a host's traffic rides.
func echoOverTailnet(t *testing.T, dst *tsnet.Server, dstAddr netip.Addr,
	src *tsnet.Server, payload string) {

	t.Helper()
	listener, err := dst.Listen("tcp", fmt.Sprintf("%s:0", dstAddr))
	if err != nil {
		t.Fatalf("the destination host's listener: %v", err)
	}
	defer func() { _ = listener.Close() }()
	echoAddr, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("the destination host's listener address %q: %v",
			listener.Addr(), err)
	}

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		// The echo answers one payload and closes: the exchange the proof
		// wants, not a stream the source would have to end first.
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != payload {
			done <- fmt.Errorf("the destination read %q, want %q", buf, payload)
			return
		}
		_, err = conn.Write(buf)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(t.Context(), TestTimeout)
	defer cancel()
	var conn net.Conn
	PollErr(t, "the source host's dial through the tunnel", func() error {
		// The dial rides the source host's own stack — the vendored
		// client engine's tunnel, the whole path under proof.
		conn, err = src.Dial(ctx, "tcp", echoAddr.String())
		return err
	})
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(TestTimeout))
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("the echo never returned through the tunnel: %v", err)
	}
	if string(reply) != payload {
		t.Fatalf("the echo returned %q, want %q", reply, payload)
	}
	// The destination's side of the exchange blocks on its own timeout, the
	// same budget the reply read carried.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the destination's side of the echo: %v", err)
		}
	case <-time.After(TestTimeout):
		t.Fatal("the destination's side of the echo never finished")
	}
}

// TestCoordinationJoin is the coordination join proof on the two-node
// topology: each host registers with a key naming one node, its login
// completing on the spot and its address from that node's slice; each
// node programs itself from the fetched registry within one cadence; and
// the two hosts exchange traffic through the mesh — the tunnel carrying
// the tailnet and nothing else — the exchange counted on the endpoint's
// metrics. The core then stops before its hosts leave, and its Close
// returns.
func TestCoordinationJoin(t *testing.T) {
	t.Parallel()
	// The package CA: its certificate file is the one the vendored
	// clients' root store trusts.
	wpki := packageWebPKI
	place := placeCoordination(t)
	a := coordCore(t, wpki, hostSlot(t), place, nil)
	b := coordLeaf(t, wpki, hostSlot(t), a, place, nil)
	// The nodes' counters, printed at the test's end: the overlay's own
	// tooling, where the operating system's cannot see.
	t.Cleanup(func() {
		t.Logf("node A counters: %v", wireguardOf(a).Counters())
		t.Logf("node B counters: %v", wireguardOf(b).Counters())
	})

	// The mesh stands before any host joins — in both directions, for
	// the echo's traffic rides each node's own composition: the core's
	// path to the leaf warms only once the leaf's down segments reach its
	// database, and the mesh device's first send reads the cache alone.
	Poll(t, "the leaf reaches the core", func() bool {
		return pingFrom(t.Context(), b, a.app.IA(), a.host)
	})
	Poll(t, "the core reaches the leaf", func() bool {
		return pingFrom(t.Context(), a, b.app.IA(), b.host)
	})

	// The far node's entry reaches the core's registry before its hosts
	// can place in its slice: the directory's own convergence, the same
	// one the mesh rides.
	Poll(t, "the core's registry holding B's entry", func() bool {
		return holdsHostEndpoint(t, a, b.app.IA())
	})

	// The two hosts land on the nodes their keys name, one on each, and own
	// distinct addresses of the tailnet range.
	hostA := tailnetHost(t, "host-a", place.controlURL, labKey(a.app.IA()))
	ipsA := hostUp(t, hostA)
	if len(ipsA) != 1 || !ipsA[0].Is4() || !TailnetRange.Contains(ipsA[0]) {
		t.Fatalf("the host's addresses = %v, want one of the tailnet range", ipsA)
	}
	hostB := tailnetHost(t, "host-b", place.controlURL, labKey(b.app.IA()))
	ipsB := hostUp(t, hostB)
	if len(ipsB) != 1 || !ipsB[0].Is4() || !TailnetRange.Contains(ipsB[0]) {
		t.Fatalf("the far host's addresses = %v, want one of the tailnet range",
			ipsB)
	}
	if got := ownerOf(t, a, ipsA[0]); got != a.app.IA() {
		t.Fatalf("the core's host landed on %s, want the core its key names", got)
	}
	if got := ownerOf(t, a, ipsB[0]); got != b.app.IA() {
		t.Fatalf("the leaf's host landed on %s, want the leaf its key names", got)
	}

	// The join completes at the directory's cadence: both owning nodes
	// program their host devices from the fetched registry before any
	// host speaks, for a node that has not fetched its host's entry drops
	// the host's first handshake.
	Poll(t, "A's host device programmed", func() bool {
		return len(wireguardOf(a).HostPeers()) == 1
	})
	Poll(t, "B's host device programmed", func() bool {
		return len(wireguardOf(b).HostPeers()) == 1
	})

	// Each host's session with its node begins with the host's own
	// outbound exchange — the session is outbound-initiated in the
	// client's model, and a listening host that never spoke leaves its
	// node no endpoint to deliver to.
	warmSession(t, hostA, ipsB[0])
	warmSession(t, hostB, ipsA[0])

	// The echo crosses the mesh: the core's host dials the leaf's.
	echoOverTailnet(t, hostB, ipsB[0], hostA, "through the tailnet")

	// The exchange reaches the endpoint's metrics: a scrape of the leaf's
	// mount carries each node's host datagrams and mesh sends under its own
	// local_as.
	Poll(t, "the WireGuard counters served at the leaf's mount", func() bool {
		body := scrapeMetrics(t, a, b.app.IA())
		for _, ia := range []addr.IA{a.app.IA(), b.app.IA()} {
			if servedSum(body, "wireguard_host_datagrams_total", ia) == 0 ||
				servedSum(body, "wireguard_sent_datagrams_total", ia) == 0 {
				return false
			}
		}
		return true
	})

	// The core stops before its hosts leave: its Close returns with their
	// conversations and relay connections still open.
	stopped := make(chan error, 1)
	go func() { stopped <- a.app.Close() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("stopping the core: %v", err)
		}
	case <-time.After(TestTimeout):
		t.Fatal("the core's Close never returned with its hosts connected")
	}
}

// TestCoordinationByAddressIdentity is the address identity's coordination
// proof: the core's --trust.domain a public address — the loopback host its
// control sockets and placed endpoint both sit on, as the resolution pins
// it — and its certificate the address-shaped one the package CA mints.
// The vendored client engine logs in against the placed address — the
// tailnet named by the identity, the certificate verified against its IP
// addresses — and two hosts exchange traffic through the mesh, the relay
// the netmap advertises dialed by the same literal.
func TestCoordinationByAddressIdentity(t *testing.T) {
	t.Parallel()
	// The package CA: its address certificate is the one the vendored
	// clients' root store trusts.
	wpki := packageWebPKI
	place := placeCoordination(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	a := coordCore(t, wpki, loopback, place, func(cfg *services.NodeConfig) {
		cfg.Domain = webpkitest.Address
		cfg.CertFile = wpki.AddrCertFile
		cfg.KeyFile = wpki.AddrKeyFile
	})
	b := coordLeaf(t, wpki, hostSlot(t), a, place, func(cfg *services.NodeConfig) {
		cfg.Domain = webpkitest.Address
	})

	Poll(t, "the leaf reaches the core", func() bool {
		return pingFrom(t.Context(), b, a.app.IA(), a.host)
	})
	Poll(t, "the core reaches the leaf", func() bool {
		return pingFrom(t.Context(), a, b.app.IA(), b.host)
	})

	// The far node's entry reaches the core's registry before its hosts
	// can place in its slice: the directory's own convergence, the same
	// one the mesh rides.
	Poll(t, "the core's registry holding B's entry", func() bool {
		return holdsHostEndpoint(t, a, b.app.IA())
	})

	hostA := tailnetHost(t, "host-a", place.controlURL, labKey(a.app.IA()))
	ipsA := hostUp(t, hostA)
	if len(ipsA) != 1 || !ipsA[0].Is4() || !TailnetRange.Contains(ipsA[0]) {
		t.Fatalf("the host's addresses = %v, want one of the tailnet range", ipsA)
	}
	hostB := tailnetHost(t, "host-b", place.controlURL, labKey(b.app.IA()))
	ipsB := hostUp(t, hostB)
	if len(ipsB) != 1 || !ipsB[0].Is4() || !TailnetRange.Contains(ipsB[0]) {
		t.Fatalf("the far host's addresses = %v, want one of the tailnet range", ipsB)
	}

	Poll(t, "A's host device programmed", func() bool {
		return len(wireguardOf(a).HostPeers()) == 1
	})
	Poll(t, "B's host device programmed", func() bool {
		return len(wireguardOf(b).HostPeers()) == 1
	})

	warmSession(t, hostA, ipsB[0])
	warmSession(t, hostB, ipsA[0])

	echoOverTailnet(t, hostB, ipsB[0], hostA, "through the address identity")
}
