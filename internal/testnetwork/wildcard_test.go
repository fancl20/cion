package testnetwork

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// TestWildcardControlBoots is the wildcard default's integration proof: a
// founding core booted with no --control of its own — the bare wildcard the
// default spells, its port derived — binds every socket on every interface
// of the family. The rendezvous acceptor answers a wildcard-bound dial
// through the loopback and records the wildcard claim's port on the observed
// host, and the founder's HTTPS serves the coordination surfaces at the
// port. The lab owns a network namespace of its own, for a wildcard bind
// holds the fixed ports against every node of the process — the same host
// cannot serve two of them, which is why the observed-address link between
// two wildcard assemblies stays proven at the measured package's exchange.
func TestWildcardControlBoots(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	wpki := webpkitest.New(t)
	n := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Domain = webpkitest.Domain
		cfg.State = t.TempDir()
		cfg.Internal = services.DefaultInternal
		cfg.Control = services.DefaultControl
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.AppArguments.Wireguard.HostPort = apps.DefaultHostPort
	})
	ctx := t.Context()

	// The founder's HTTPS holds the port where the refusal once fired,
	// answering before anything serves it, the coordination surfaces the
	// mounted application contributes.
	https, err := net.DialTimeout("tcp", "127.0.0.1:443", time.Second)
	if err != nil {
		t.Fatalf("the wildcard's HTTPS port does not answer: %v", err)
	}
	_ = https.Close()

	// A wildcard-bound dial claiming the wildcard reaches the acceptor
	// through the loopback: the reply carries the acceptor's wildcard bind
	// value and the source the dial proved routable, and the acceptor
	// records the observed source whole — the loopback host under the bound
	// port.
	wildcard := netip.MustParseAddr("0.0.0.0")
	claim := netip.AddrPortFrom(wildcard, 31001)
	peer := addr.MustIAFrom(20, 0xfd00000000f1)
	reply, observed, _, err := measured.RendezvousEcho(ctx, claim,
		netip.MustParseAddrPort("127.0.0.1:30043"), peer, claim)
	if err != nil {
		t.Fatalf("the wildcard's rendezvous did not answer: %v", err)
	}
	if !reply.LinkAddr.Addr().IsUnspecified() {
		t.Errorf("the reply's link address = %v, want the wildcard bind value",
			reply.LinkAddr)
	}
	if observed.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("the reply's source = %v, want the loopback host", observed)
	}
	recorded := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), claim.Port())
	Poll(t, "the acceptor to record the observed claim", func() bool {
		entries, err := n.app.Links().All(ctx)
		if err != nil {
			return false
		}
		for _, l := range entries {
			if l.NeighborIA.Equal(peer) && l.Remote == recorded {
				return true
			}
		}
		return false
	})
}
