package behavior

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// regionsOneWay is the regions lab's one-way delay matrix in microseconds.
// Region 0 is nodes 0, 3, and 6; regions 1 and 2 are nodes 1, 4, and 7 and
// nodes 2, 5, and 8. A region is 3 to 9ms across; regions 1 and 2 sit 8 to
// 17ms apart, and region 0 sits 82 to 106ms from both.
var regionsOneWay = [9][9]int{
	{0, 92966, 84579, 5965, 98702, 89398, 2960, 100638, 84978},
	{92966, 0, 8894, 98287, 7284, 8367, 90547, 8185, 9210},
	{84579, 8894, 0, 89905, 15129, 9023, 82162, 16579, 4171},
	{5965, 98287, 89905, 0, 103973, 94611, 8276, 105952, 90249},
	{98702, 7284, 15129, 103973, 0, 10504, 96268, 4325, 14224},
	{89398, 8367, 9023, 94611, 10504, 0, 86952, 13663, 6013},
	{2960, 90547, 82162, 8276, 96268, 86952, 0, 98217, 82544},
	{100638, 8185, 16579, 105952, 4325, 13663, 98217, 0, 16479},
	{84978, 9210, 4171, 90249, 14224, 6013, 82544, 16479, 0},
}

// The regions lab's spanning tree, joined from the founder outward: each
// node of regionsOrder joins through its parent alone.
var (
	regionsParent = map[int]int{3: 0, 6: 0, 2: 6, 8: 2, 5: 8, 1: 5, 4: 1, 7: 4}
	regionsOrder  = []int{3, 6, 2, 8, 5, 1, 4, 7}
)

const (
	// regionsBudget bounds the regions lab's run in virtual time.
	regionsBudget = time.Hour
	// regionsQuiet is how long the link set must hold unchanged to count
	// as settled: twenty selection windows at the daemon's pacing.
	regionsQuiet = 10 * time.Minute
	// regionsSample spaces the lab's reads of the link set.
	regionsSample = 10 * time.Second
)

// TestRegionsSettle is the selection loop's convergence proof at the
// daemon's own pacing: nine nodes over three regions, joined outward from
// the founder along a spanning tree, settle — the link set holds unchanged
// for regionsQuiet with every node at or above its floor and the links
// connecting them all — within regionsBudget of virtual time. Under the
// labs' two-second windows the same network settles even with both ends of
// a link judging it, so only the daemon's own pacing holds the settling.
func TestRegionsSettle(t *testing.T) {
	t.Skip("a partition can freeze: across one, each side's baseline echo " +
		"into the other answers, so neither reads the other's tier stranded")
	testnetwork.InBubble(t, func(t *testing.T, fab *fabric.Fabric, wpki *webpkitest.CA) {
		var hosts [9]netip.Addr
		for i := range hosts {
			hosts[i] = testnetwork.HostSlot(t)
		}
		for i := range hosts {
			for j := i + 1; j < len(hosts); j++ {
				fab.Delay(hosts[i], hosts[j], time.Duration(regionsOneWay[i][j])*time.Microsecond)
			}
		}
		var nodes [9]*testnetwork.Node
		nodes[0] = testnetwork.BootInBubble(t, fab, hosts[0], func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
		for _, i := range regionsOrder {
			parent := nodes[regionsParent[i]]
			nodes[i] = testnetwork.BootInBubble(t, fab, hosts[i], func(cfg *services.NodeConfig) {
				cfg.Neighbors = []string{rendezvous(parent)}
				cfg.RootCAs = wpki.Pool
			})
		}
		ctx := t.Context()

		start := time.Now()
		var last string
		changed, changes := start, 0
		for {
			synctest.Wait()
			if now := linkSet(ctx, nodes[:]); now != last {
				last, changed = now, time.Now()
				changes++
			}
			if time.Since(changed) >= regionsQuiet && settled(ctx, nodes[:]) {
				return
			}
			if time.Since(start) >= regionsBudget {
				t.Fatalf("the link set changed %d times in %v and never held for %v; last: %s",
					changes, regionsBudget, regionsQuiet, last)
			}
			time.Sleep(regionsSample)
		}
	})
}
