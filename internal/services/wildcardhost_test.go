package services

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestWildcardHostRoutesTowardThePublishedHost checks the host the wildcard
// conns name: the routing table's answer toward the published host — the
// inside address a translation hides, not the published host itself —
// memoized while the published host stands and the answer is young, routed
// anew when the published host moves or the answer ages past its bound. A
// failed route resolves nothing, and an unpublished host resolves nothing
// without asking the table.
func TestWildcardHostRoutesTowardThePublishedHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := netip.MustParseAddr("203.0.113.7")
		moved := netip.MustParseAddr("198.51.100.9")
		inside := netip.MustParseAddr("192.168.50.2")
		published := first
		var routed []netip.Addr
		var refusal error
		w := &wildcardHost{
			published: func(context.Context) netip.Addr { return published },
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

		published = moved
		check("a moved published host", inside, first, moved)

		time.Sleep(wildcardHostTTL)
		check("an answer past the bound", inside, first, moved, moved)

		refusal = errors.New("network is unreachable")
		time.Sleep(wildcardHostTTL)
		check("a failed route", netip.Addr{}, first, moved, moved, moved)
		check("a failed route inside the bound", netip.Addr{}, first, moved, moved, moved)

		published = netip.Addr{}
		check("an unpublished host", netip.Addr{}, first, moved, moved, moved)
	})
}
