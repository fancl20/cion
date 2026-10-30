package testnetwork

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// renewSoon paces a node to renew its chain within seconds of each
// issuance: an issued chain starts a minute back, the issuers' backdate, so
// its remaining validity drops below the threshold three seconds after its
// issuance at the latest. The passes between renewals, at the inspection
// pace, do the role's owed work, which a pass that renews skips.
func renewSoon(cfg *services.NodeConfig) {
	cfg.Pacing.RenewalThreshold = trust.ASValidity - time.Minute - 3*time.Second
	cfg.Pacing.EnrollmentInspect = EnrollRetry
}

// TestChainsRenewWithTheFounderDown checks renewal without the founder: a
// founder, an authoritative core onboarded through it, and a normal node
// linked to both, the latter two renewing within seconds of each issuance.
// Once the authoritative core issues under its own root and the normal node
// pins the TRC carrying that root, the founder stops, and both keep
// renewing: each one's newest chain is issued after the stop, by the
// authoritative core.
func TestChainsRenewWithTheFounderDown(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipF, ipA, ipN := HostSlot(t), HostSlot(t), HostSlot(t)

	// The founding core.
	f := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipF)
		cfg.Control = FreeUDPAddrOn(t, ipF)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.EnrollAuth = votingAuth
	})
	// The authoritative core, onboarded through the founder.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.Neighbors = []string{f.Rendezvous()}
		cfg.RootCAs = wpki.Pool
		renewSoon(cfg)
	})
	Poll(t, "the authoritative core to issue its own chain", func() bool {
		chain := newestChain(t, a)
		return chain != nil && issuedBy(t, chain) == a.app.IA()
	})

	// The normal node, linked to both cores: it enrolls at the founder and
	// pins the TRC carrying the authoritative core's root.
	n := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipN)
		cfg.Control = FreeUDPAddrOn(t, ipN)
		cfg.Neighbors = []string{f.Rendezvous(), a.Rendezvous()}
		cfg.RootCAs = wpki.Pool
		renewSoon(cfg)
	})
	Poll(t, "the normal node enrolled", func() bool {
		return holdsAssemblyChain(t, n, n.app.IA())
	})
	Poll(t, "the normal node pinned the authoritative core's root", func() bool {
		trc, err := n.app.TrustDB().SignedTRC(t.Context(), trust.NewestTRCID(n.app.IA().ISD()))
		if err != nil {
			t.Fatal(err)
		}
		return trust.Onboarded(trc.TRC, a.app.IA())
	})

	// The founder stops. A chain newer than the newest each node holds once
	// the stop returns was issued after it; the authoritative core issues
	// both.
	f.Stop(t)
	for _, node := range []struct {
		name string
		node *Node
	}{{"normal node", n}, {"authoritative core", a}} {
		stopped := newestChain(t, node.node)
		PollFor(t, RestartTimeout, "the "+node.name+" to renew without the founder", func() bool {
			chain := newestChain(t, node.node)
			return chain != nil && chain[0].NotAfter.After(stopped[0].NotAfter) &&
				issuedBy(t, chain) == a.app.IA()
		})
	}
}

// newestChain returns the node's newest chain valid now, nil when it holds
// none.
func newestChain(t *testing.T, n *Node) []*x509.Certificate {
	t.Helper()
	chain, err := trust.NewestChain(t.Context(), n.app.TrustDB(), n.app.IA(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// issuedBy returns the ISD-AS the chain's CA certificate names: the core
// that issued the chain.
func issuedBy(t *testing.T, chain []*x509.Certificate) addr.IA {
	t.Helper()
	ia, err := cppki.ExtractIA(chain[1].Subject)
	if err != nil {
		t.Fatal(err)
	}
	return ia
}
