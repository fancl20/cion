package testnetwork

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
)

// awaitRemovalPinned waits for the node to pin a TRC that names the core no
// more.
func awaitRemovalPinned(t *testing.T, n *Node, core addr.IA) {
	t.Helper()
	PollFor(t, RestartTimeout, fmt.Sprintf("%v to pin the removal of %v", n.app.IA(), core),
		func() bool {
			trc, err := n.app.TrustDB().SignedTRC(t.Context(), trust.NewestTRCID(core.ISD()))
			if err != nil {
				t.Fatal(err)
			}
			return !trc.IsZero() && !trust.CoreNamed(trc.TRC, core)
		})
}

// awaitAcceptance waits for dst to complete the handshake creds present from
// the node's stack.
func awaitAcceptance(t *testing.T, from *Node, dst addr.IA, creds scionrpc.Credentials,
	key *ecdsa.PrivateKey, what string) {

	t.Helper()
	PollFor(t, RestartTimeout, fmt.Sprintf("%v to accept %s", dst, what), func() bool {
		return handshake(t, from, dst, creds, key) == nil
	})
}

// TestRemovedCoreAnchorsNothing is the core removal's proof on coreTrio's
// network, its normal node holding a chain the authoritative core issued as
// its newest. The founder removes that core, stopped first, for the labs'
// admission policy would admit it back: every node pins the removal; the
// normal node keeps completing handshakes with the founder, on its
// membership, and renews at the founder; a chain the removed core issues
// passes no handshake; and the removed core's name is bound to no key at
// the founder.
func TestRemovedCoreAnchorsNothing(t *testing.T) {
	t.Parallel()
	_, f, a, n := coreTrio(t, func(*services.NodeConfig) {})
	ctx := t.Context()
	key := n.app.Engine().Key
	// A chain issued in the same second as the node's own expires no later
	// than it: the authoritative core issues until its chain is the newest.
	Poll(t, "the normal node's newest chain to be one the authoritative core issued", func() bool {
		if _, err := n.app.TrustDB().InsertChain(ctx, issueAt(t, a, n.app.IA(), key)); err != nil {
			t.Fatal(err)
		}
		return issuedBy(t, newestChain(t, n)) == a.app.IA()
	})
	awaitHandshake(t, n, f.app.IA())
	a.Stop(t)

	removed := time.Now()
	if err := f.app.RemoveNode(ctx, a.app.IA()); err != nil {
		t.Fatal(err)
	}
	for _, node := range []*Node{f, n} {
		awaitRemovalPinned(t, node, a.app.IA())
	}
	awaitHandshake(t, n, f.app.IA())
	PollFor(t, RestartTimeout, "the normal node to renew at the founder", func() bool {
		chain := newestChain(t, n)
		return issuedBy(t, chain) == f.app.IA() && chain[0].NotBefore.Add(time.Minute).After(removed)
	})

	forgery, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	creds := forgedCredentials{
		chain:  issueAt(t, a, n.app.IA(), forgery),
		beside: n.app.MembershipStore().Get(n.app.IA()),
		pool:   n.app.Engine().AnchorPool,
	}
	awaitRefusal(t, n, f.app.IA(), creds, forgery, "a chain the removed core issued")

	if bound, err := f.app.TrustDB().BoundKey(ctx, a.app.IA()); err != nil || bound != nil {
		t.Errorf("the founder binds the removed core's name to %x (%v), want no key", bound, err)
	}
}

// TestRemovedCoreKeepsGraceWithoutMemberships is the core removal on
// coreTrio's network with none on every node: once the founder removes the
// authoritative core, stopped first, for the labs' admission policy would
// admit it back, a chain the core issued still passes the founder's
// handshake inside the roll's grace period, and its node is not removed:
// its name stays bound.
func TestRemovedCoreKeepsGraceWithoutMemberships(t *testing.T) {
	t.Parallel()
	_, f, a, n := coreTrio(t, func(cfg *services.NodeConfig) { cfg.Membership = "none" })
	ctx := t.Context()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	creds := forgedCredentials{
		chain: issueAt(t, a, n.app.IA(), key),
		pool:  n.app.Engine().AnchorPool,
	}
	a.Stop(t)

	if err := f.app.RemoveNode(ctx, a.app.IA()); err != nil {
		t.Fatal(err)
	}
	awaitRemovalPinned(t, f, a.app.IA())
	newest, err := f.app.TrustDB().SignedTRC(ctx, trust.NewestTRCID(a.app.IA().ISD()))
	if err != nil {
		t.Fatal(err)
	}
	if !newest.TRC.InGracePeriod(time.Now()) {
		t.Fatalf("the removal %v keeps no grace period", newest.TRC.ID)
	}
	awaitAcceptance(t, n, f.app.IA(), creds, key, "a chain the removed core issued, in the grace period")

	if bound, err := f.app.TrustDB().BoundKey(ctx, a.app.IA()); err != nil || bound == nil {
		t.Errorf("the founder freed the core's name (%v), want no node removed", err)
	}
}
