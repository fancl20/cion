package testnetwork

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
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

// Node is a node booted through the run command's own assembly.
type Node struct {
	app      *services.App
	stateDir string
	host     netip.Addr
	// internal is the internal link's UDP address as the run arguments
	// carried it, where a lab submits raw packets as a local host.
	internal string
}

// App returns the node's assembly.
func (n *Node) App() *services.App { return n.app }

// Host returns the control address's host: the address the labs name the
// node by.
func (n *Node) Host() netip.Addr { return n.host }

// bootOn boots a full node assembly binding every underlay socket through
// the source, the kernel's or a fabric's, and serves it underneath the
// test.
func bootOn(
	t *testing.T, sockets underlay.Sockets, mutate func(*services.NodeConfig),
) *Node {

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
	app, err := services.BootApp(t.Context(), cfg, sockets)
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{app: app, stateDir: cfg.State, internal: cfg.Internal}
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

// bootOnFabric boots a full node assembly on the fabric's node for the
// host — the same wiring as bootAssembly, every underlay socket bound on
// the node's stack and every port drawn there, no kernel port held or
// probed. A founding core's domain names its host on the fabric, so the
// founder publishes the host its peers reach and stands in the directory,
// as a production founder does.
func bootOnFabric(
	t *testing.T, f *fabric.Fabric, host netip.Addr,
	mutate func(*services.NodeConfig),
) *Node {

	t.Helper()
	stack := f.Node(host)
	return bootOn(t, stack.Sockets(), func(cfg *services.NodeConfig) {
		if cfg.Internal == "" {
			cfg.Internal = netip.AddrPortFrom(host, stack.DrawPort()).String()
		}
		if cfg.Control == "" {
			cfg.Control = netip.AddrPortFrom(host, stack.DrawPort()).String()
		}
		if mutate != nil {
			mutate(cfg)
		}
		if cfg.Core && len(cfg.Neighbors) == 0 {
			f.Name(cfg.Domain, host)
		}
	})
}

// InBubble runs a lab's body inside a synctest bubble, on virtual time: the
// fabric, its stacks UDP-only, and the test CA are made inside the bubble,
// for the fabric's clock and the CA's validity window both read the time at
// their creation — the CA's twenty-four hours then bound the lab's virtual
// run. Every cleanup the body registers runs inside the bubble before the
// bubble drains, so a goroutine the lab leaks fails the lab at its exit. A
// lab that needs a process of its own re-executes before it enters: the
// re-execution cannot run inside a bubble.
func InBubble(t *testing.T, body func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		body(t, fabric.New(t, fabric.UDPOnly()), webpkitest.New(t))
	})
}

// BootInBubble boots a node on a bubble's fabric at the daemon's own
// pacing: under virtual time a lab's cost is the work each virtual second
// carries, so the production intervals are the cheap ones, and they are
// the ratios the node runs at.
func BootInBubble(
	t *testing.T, f *fabric.Fabric, host netip.Addr,
	mutate func(*services.NodeConfig),
) *Node {

	t.Helper()
	return bootOnFabric(t, f, host, func(cfg *services.NodeConfig) {
		cfg.Pacing = services.NodePacing{}
		if mutate != nil {
			mutate(cfg)
		}
	})
}
