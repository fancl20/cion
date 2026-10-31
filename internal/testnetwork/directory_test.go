package testnetwork

import (
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// directoryBudget bounds each step of the directory lab in virtual time:
// the joins and the enrollments of a three-node line, or a restart.
const directoryBudget = 3 * time.Minute

// holdsEntries reports whether the node's views of its directories hold an
// entry of each ISD-AS.
func holdsEntries(n *Node, ias ...addr.IA) bool {
	view := n.app.Bus().Directory().Latest()
	for _, ia := range ias {
		if _, ok := view.Latest(ia); !ok {
			return false
		}
	}
	return true
}

// TestNodeDirectoryOnEveryNode checks the node directory every node holds,
// on a fabric line at the daemon's own pacing: the founder A, B joined to
// it, and C joined to B. Every node's view holds every node's entry. The
// founder stops, withdrawing its entry, and the other two keep each other's.
// C stops too, and B drops it; restarted on its state with an empty
// directory, C holds B's entry once its link comes up, and B holds the entry
// C signed anew, which outranks its withdrawal.
func TestNodeDirectoryOnEveryNode(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		ipA, ipB, ipC := HostSlot(t), HostSlot(t), HostSlot(t)
		a := BootInBubble(t, f, ipA, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
		b := BootInBubble(t, f, ipB, func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{a.Rendezvous()}
			cfg.RootCAs = wpki.Pool
		})
		c := BootInBubble(t, f, ipC, func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{b.Rendezvous()}
			cfg.RootCAs = wpki.Pool
		})
		ias := []addr.IA{a.app.IA(), b.app.IA(), c.app.IA()}
		for _, n := range []*Node{a, b, c} {
			PollVirtual(t, directoryBudget, n.app.IA().String()+" to hold every node's entry",
				func() bool { return holdsEntries(n, ias...) })
		}

		a.Stop(t)
		for _, n := range []*Node{b, c} {
			PollVirtual(t, directoryBudget, n.app.IA().String()+" to drop the stopped founder alone",
				func() bool {
					_, founder := n.app.Bus().Directory().Latest().Latest(a.app.IA())
					return !founder && holdsEntries(n, b.app.IA(), c.app.IA())
				})
		}

		state := c.StateDir()
		c.Stop(t)
		PollVirtual(t, directoryBudget, "B to drop the stopped C", func() bool {
			return !holdsEntries(b, c.app.IA())
		})
		start := time.Now()
		restarted := BootInBubble(t, f, ipC, func(cfg *services.NodeConfig) {
			cfg.State = state
			cfg.RootCAs = wpki.Pool
		})
		PollVirtual(t, directoryBudget, "the restarted C to hold B's entry", func() bool {
			return holdsEntries(restarted, b.app.IA(), c.app.IA())
		})
		PollVirtual(t, directoryBudget, "B to hold the entry C signed anew", func() bool {
			return holdsEntries(b, c.app.IA())
		})
		t.Logf("B held the entry C signed anew %v after C's restart", time.Since(start))
	})
}

// TestDirectoryScopesOnASite checks the directory's scopes on a fabric
// site: the founder outside, and A and B behind one port-restricted NAT, A
// joined through the founder and B through the founder and A's inside
// address. A and B come to share a directory the founder does not hold,
// where each names its inside address, and the founder's views name each
// at the NAT's gateway alone, never at its inside address.
func TestDirectoryScopesOnASite(t *testing.T) {
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		ipF, ipA, ipB := HostSlot(t), HostSlot(t), HostSlot(t)
		nat := f.NAT(fabric.PortRestricted, HostSlot(t), ipA, ipB)
		founder := BootInBubble(t, f, ipF, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
		a := BootInBubble(t, f, ipA, func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{founder.Rendezvous()}
			cfg.RootCAs = wpki.Pool
		})
		b := BootInBubble(t, f, ipB, func(cfg *services.NodeConfig) {
			cfg.Neighbors = []string{founder.Rendezvous(), a.Rendezvous()}
			cfg.RootCAs = wpki.Pool
		})
		inside := map[addr.IA]netip.Addr{a.app.IA(): ipA, b.app.IA(): ipB}
		PollVirtual(t, directoryBudget, "A and B to share a directory of their inside addresses",
			func() bool {
				return sharesSite(founder, inside, a, b)
			})
		PollVirtual(t, directoryBudget, "the founder to name A and B at the gateway",
			func() bool {
				view := founder.app.Bus().Directory().Latest()
				for ia := range inside {
					e, ok := view.Latest(ia)
					if !ok || len(e.Addresses) == 0 ||
						e.Addresses[0].RendezvousAddr.Addr() != nat.Gateway() {
						return false
					}
				}
				return true
			})
		for _, s := range founder.app.Bus().Directory().Latest().Scopes() {
			for _, e := range s.Entries() {
				for _, a := range e.Addresses {
					if host, ok := inside[e.IA]; ok && a.RendezvousAddr.Addr() == host {
						t.Errorf("the founder's view names %v at its inside address %v", e.IA, host)
					}
				}
			}
		}
	})
}

// sharesSite reports whether the site nodes all hold a directory the
// founder does not, whose view shows each site node's entry naming its
// inside address first.
func sharesSite(founder *Node, inside map[addr.IA]netip.Addr, site ...*Node) bool {
	held := founder.app.Bus().Directory().Latest()
	for _, candidate := range site[0].app.Bus().Directory().Latest().Scopes() {
		if _, ok := held.Scope(candidate.ID()); ok {
			continue
		}
		shared := true
		for _, n := range site {
			s, ok := n.app.Bus().Directory().Latest().Scope(candidate.ID())
			if !ok {
				shared = false
				break
			}
			for ia, host := range inside {
				e, ok := s.Entry(ia)
				if !ok || len(e.Addresses) == 0 || e.Addresses[0].RendezvousAddr.Addr() != host {
					shared = false
				}
			}
		}
		if shared {
			return true
		}
	}
	return false
}
