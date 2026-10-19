package testnetwork

import (
	"testing"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/links"
)

// TestFabricJoin is the fabric's proof at the node's scale: a founding core
// and a joiner booted through the same assembly on the userspace fabric —
// each node one netstack, no kernel port held — join by rendezvous, the
// joiner enrolls through the founder's endpoint, and the echo crosses the
// stacks both ways. The labs that follow draw their impairments on this
// network; this one proves the network itself carries the whole node.
func TestFabricJoin(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	f := fabric.New(t)
	ipA, ipB := hostSlot(t), hostSlot(t)
	a := bootOnFabric(t, f, ipA, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	b := bootOnFabric(t, f, ipB, func(cfg *services.NodeConfig) {
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	ctx := t.Context()

	Poll(t, "B's link to A on the fabric", func() bool {
		e := entryOf(ctx, b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "A's link to B on the fabric", func() bool {
		e := entryOf(ctx, a, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "B enrolled over the fabric", func() bool {
		return pingFrom(ctx, b, a.app.IA(), a.host)
	})
	linkPortsInBand(t, a)
	linkPortsInBand(t, b)
}
