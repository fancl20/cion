package services

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/modules/links"
)

// TestWildcardHostRoutesTowardThePublishedHost checks the host the wildcard
// conns name: the routing table's answer toward the node's own host — the
// inside address a NAT hides, not the host itself — memoized while the host
// stands and the answer is young, routed anew when the host moves or the
// answer ages past its bound. A failed route resolves nothing, and with no
// host and no link the resolution asks the table nothing.
func TestWildcardHostRoutesTowardThePublishedHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := netip.MustParseAddr("203.0.113.7")
		moved := netip.MustParseAddr("198.51.100.9")
		inside := netip.MustParseAddr("192.168.50.2")
		self := new(bus.Topic[bus.SelfState])
		self.Publish(bus.SelfState{Host: first})
		var routed []netip.Addr
		var refusal error
		w := &wildcardHost{
			self: self,
			route: func(dst netip.Addr) (netip.Addr, error) {
				routed = append(routed, dst)
				if refusal != nil {
					return netip.Addr{}, refusal
				}
				return inside, nil
			},
		}
		check := func(step string, want netip.Addr, wantRouted ...netip.Addr) {
			t.Helper()
			if got := w.resolve(t.Context()); got != want {
				t.Errorf("%s: the wildcard host = %v, want %v", step, got, want)
			}
			if diff := cmp.Diff(wantRouted, routed, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
				t.Errorf("%s: the routes asked (-want +got):\n%s", step, diff)
			}
		}

		check("the first resolution", inside, first)
		check("a resolution inside the bound", inside, first)

		self.Publish(bus.SelfState{Host: moved})
		check("a moved published host", inside, first, moved)

		time.Sleep(wildcardHostTTL)
		check("an answer past the bound", inside, first, moved, moved)

		refusal = errors.New("network is unreachable")
		time.Sleep(wildcardHostTTL)
		check("a failed route", netip.Addr{}, first, moved, moved, moved)
		check("a failed route inside the bound", netip.Addr{}, first, moved, moved, moved)

		self.Publish(bus.SelfState{})
		check("an unpublished host", netip.Addr{}, first, moved, moved, moved)
	})
}

// TestWildcardHostRoutesTowardALink checks the destination while the node
// names no host of its own: the peer the live entry of the least interface
// ID records, an entry recording none passed over; once the node names a
// host, the resolution routes toward it.
func TestWildcardHostRoutesTowardALink(t *testing.T) {
	self := new(bus.Topic[bus.SelfState])
	state := new(bus.Topic[bus.LinkState])
	peer := netip.MustParseAddrPort("198.51.100.20:30100")
	state.Publish(bus.NewLinkState(
		bus.Link{Entry: links.Link{IfID: 1}},
		bus.Link{Entry: links.Link{IfID: 3, Remote: netip.MustParseAddrPort("198.51.100.30:30100")}},
		bus.Link{Entry: links.Link{IfID: 2, Remote: peer}},
	))
	var routed []netip.Addr
	w := &wildcardHost{
		self:  self,
		links: state,
		route: func(dst netip.Addr) (netip.Addr, error) {
			routed = append(routed, dst)
			return netip.MustParseAddr("10.0.0.2"), nil
		},
	}
	if got := w.resolve(t.Context()); got != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("the wildcard host = %v, want the route's answer", got)
	}
	host := netip.MustParseAddr("203.0.113.7")
	self.Publish(bus.SelfState{Host: host})
	w.resolve(t.Context())
	if want := []netip.Addr{peer.Addr(), host}; !slices.Equal(routed, want) {
		t.Errorf("routed toward %v, want the least interface's recorded peer, then the host: %v",
			routed, want)
	}
}
