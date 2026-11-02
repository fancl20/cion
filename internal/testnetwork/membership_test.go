package testnetwork

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/modules/membership/impl/founder"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// memberValidity is the chain validity the membership labs pace their cores
// to, and so the membership window: a chain starts a minute back, the
// issuers' backdate, so it lives a minute and a half from its issuance.
const memberValidity = 150 * time.Second

// paceMemberships paces a node's chains and memberships to memberValidity,
// each renewed 45 seconds after its issuance.
func paceMemberships(cfg *services.NodeConfig) {
	cfg.Pacing.ChainValidity = memberValidity
	cfg.Pacing.RenewalThreshold = 45 * time.Second
	cfg.Pacing.EnrollmentInspect = EnrollRetry
}

// coreTrio boots the membership labs' network: a founder, booted again by
// the returned function on the same state, an authoritative core onboarded
// through it, its issuer anchored, and a normal node linked to both
// that pinned the TRC carrying the authoritative core's root, each holding
// the membership the founder issued it. mutate paces every node.
func coreTrio(t *testing.T, mutate func(*services.NodeConfig)) (bootFounder func() *Node, f, a, n *Node) {
	t.Helper()
	wpki := webpkitest.New(t)
	ipF, ipA, ipN := HostSlot(t), HostSlot(t), HostSlot(t)
	stateF := t.TempDir()
	internalF, controlF := PinnedUDPAddrOn(t, ipF), FreeUDPAddrOn(t, ipF)
	bootFounder = func() *Node {
		return bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.State = stateF
			cfg.Internal = internalF
			cfg.Control = controlF
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
			cfg.EnrollAuth = votingAuth
			mutate(cfg)
		})
	}
	f = bootFounder()
	a = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.Neighbors = []string{f.Rendezvous()}
		cfg.RootCAs = wpki.Pool
		mutate(cfg)
	})
	PollFor(t, OnboardTimeout, "the authoritative core's issuer to anchor", func() bool {
		return a.app.Issuer().Anchored()
	})
	n = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Internal = PinnedUDPAddrOn(t, ipN)
		cfg.Control = FreeUDPAddrOn(t, ipN)
		cfg.Neighbors = []string{f.Rendezvous(), a.Rendezvous()}
		cfg.RootCAs = wpki.Pool
		mutate(cfg)
	})
	Poll(t, "the normal node to pin the authoritative core's root", func() bool {
		trc, err := n.app.TrustDB().SignedTRC(t.Context(), trust.NewestTRCID(n.app.IA().ISD()))
		if err != nil {
			t.Fatal(err)
		}
		return trust.Onboarded(trc.TRC, a.app.IA())
	})
	for _, node := range []*Node{f, a, n} {
		Poll(t, "each node to hold the membership the founder issued it", func() bool {
			m := node.app.MembershipStore().Get(node.app.IA())
			return m != nil && issuedBy(t, m) == f.app.IA()
		})
	}
	return bootFounder, f, a, n
}

// handshake opens a channel of its own from the node's stack to dst's
// control endpoint, presenting creds with key behind them, and returns nil
// once dst's metrics answered over it: the mutual SCION-native handshake
// completed on a connection no earlier handshake opened.
func handshake(t *testing.T, from *Node, dst addr.IA, creds scionrpc.Credentials, key crypto.Signer) error {
	t.Helper()
	conn, err := from.app.Conn(0)
	if err != nil {
		t.Fatal(err)
	}
	clt := controlplane.NewPeerClient(scionrpc.PeerClientConfig{
		Credentials: creds,
		Key:         key,
		Conn:        conn,
		PathTo: func(ia addr.IA) *spath.Decoded {
			path, err := from.app.Provider().LocalPath(ia)
			if err != nil {
				return nil
			}
			return path
		},
	})
	defer func() {
		_ = clt.Close()
		_ = conn.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	peer := &scion.Addr{IA: dst, Service: addr.SvcCS}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+scionrpc.PeerAuthority(peer)+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := clt.VerifiedClient().Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the metrics answered %d", resp.StatusCode)
	}
	return nil
}

// awaitHandshake waits for the node, presenting its own credentials, to
// complete a fresh handshake with dst.
func awaitHandshake(t *testing.T, from *Node, dst addr.IA) {
	t.Helper()
	PollFor(t, RestartTimeout, fmt.Sprintf("%v to handshake with %v", from.app.IA(), dst),
		func() bool {
			return handshake(t, from, dst, from.app.Engine(), from.app.Engine().Key) == nil
		})
}

// awaitRefusal waits for dst to refuse the handshake creds present from the
// node's stack: one that completes fails the test, and one its deadline cut
// short, a loaded runner's, is tried again.
func awaitRefusal(t *testing.T, from *Node, dst addr.IA, creds scionrpc.Credentials,
	key crypto.Signer, what string) {

	t.Helper()
	PollFor(t, RestartTimeout, fmt.Sprintf("%v to refuse %s", dst, what), func() bool {
		err := handshake(t, from, dst, creds, key)
		if err == nil {
			t.Fatalf("%v completed a handshake presenting %s", dst, what)
		}
		return !errors.Is(err, context.DeadlineExceeded)
	})
}

// forgedCredentials are an impostor's side of the handshake: the chain a
// leaked core key issued, what the impostor presents beside it, and every
// peer accepted.
type forgedCredentials struct {
	chain, beside []*x509.Certificate
	pool          func() ([]*cppki.TRC, error)
}

func (c forgedCredentials) Chain(context.Context) ([]*x509.Certificate, error) {
	return c.chain, nil
}

func (c forgedCredentials) Beside(context.Context, []*x509.Certificate) ([]*x509.Certificate, error) {
	return c.beside, nil
}

func (c forgedCredentials) AnchorPool() ([]*cppki.TRC, error) { return c.pool() }

func (c forgedCredentials) AcceptChain(_, _ []*x509.Certificate) error { return nil }

// issueAt issues ia a chain for key at the core's issuer.
func issueAt(t *testing.T, core *Node, ia addr.IA, key crypto.Signer) []*x509.Certificate {
	t.Helper()
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := core.app.Issuer().IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// TestMembershipsOutliveTheFounder is the founder outage's proof, on chains
// paced to a validity of minutes. The founder of coreTrio's network stops:
// the chains renew at the authoritative core, every membership expires, and
// past the expiry the authoritative core and the normal node still complete
// fresh handshakes each way, the expired memberships presented beside the
// authoritative core's chains, and answer each other's pings. The founder
// returns, and both renew their memberships at it within the retry
// schedule's cap of its return, beside the time its links take back.
func TestMembershipsOutliveTheFounder(t *testing.T) {
	t.Parallel()
	bootFounder, f, a, n := coreTrio(t, paceMemberships)
	members := []*Node{a, n}

	f.Stop(t)
	PollFor(t, memberValidity, "every membership to expire", func() bool {
		for _, node := range members {
			m := node.app.MembershipStore().Get(node.app.IA())
			if time.Now().Before(m[0].NotAfter) {
				return false
			}
		}
		return true
	})
	expired := time.Now()
	for _, node := range members {
		PollFor(t, RestartTimeout, "a chain the authoritative core issued past the expiry",
			func() bool {
				chain := newestChain(t, node)
				return chain != nil && issuedBy(t, chain) == a.app.IA() &&
					issuedSince(chain, expired)
			})
	}
	awaitHandshake(t, n, a.app.IA())
	awaitHandshake(t, a, n.app.IA())
	Poll(t, "the pair to answer each other's pings", func() bool {
		return pingFrom(t.Context(), n, a.app.IA(), a.host) &&
			pingFrom(t.Context(), a, n.app.IA(), n.host)
	})

	bootFounder()
	returned := time.Now()
	for _, node := range members {
		PollFor(t, founder.RetryCap+TestTimeout, "a membership renewed at the returned founder",
			func() bool {
				m := node.app.MembershipStore().Get(node.app.IA())
				return issuedSince(m, returned)
			})
		t.Logf("%v renewed its membership %v after the founder's return",
			node.app.IA(), time.Since(returned).Round(time.Second))
	}
}

// TestForgedChainRefused is the leaked core key's proof. On coreTrio's
// network, the authoritative core's CA key issues a chain for a name the
// founder never admitted and one for the normal node's name under another
// key, each presented beside the normal node's own membership: every node
// completes a member's handshake but refuses each forgery's, and records
// neither.
func TestForgedChainRefused(t *testing.T) {
	t.Parallel()
	_, f, a, n := coreTrio(t, func(*services.NodeConfig) {})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unadmitted := addr.MustIAFrom(n.app.IA().ISD(), 0xff00000000ee)
	forgeries := map[string][]*x509.Certificate{
		"an unadmitted name": issueAt(t, a, unadmitted, key),
		"another key":        issueAt(t, a, n.app.IA(), key),
	}
	member := n.app.MembershipStore().Get(n.app.IA())

	for _, r := range []struct{ from, to *Node }{{a, f}, {a, n}, {n, a}} {
		awaitHandshake(t, r.from, r.to.app.IA())
		for name, chain := range forgeries {
			creds := forgedCredentials{chain: chain, beside: member, pool: r.from.app.Engine().AnchorPool}
			awaitRefusal(t, r.from, r.to.app.IA(), creds, key, name)
		}
	}
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []*Node{f, a, n} {
		for _, ia := range []addr.IA{unadmitted, n.app.IA()} {
			recorded, err := node.app.TrustDB().Chains(t.Context(),
				trustdb.ChainQuery{IA: ia, SubjectKeyID: skid})
			if err != nil {
				t.Fatal(err)
			}
			if len(recorded) != 0 {
				t.Errorf("%v recorded a forged chain of %v", node.app.IA(), ia)
			}
		}
	}
}

// TestHeldChainBindsNothing is the founder's boot: a chain for a name the
// founder never bound, held valid in its trust database — a chain a
// handshake recorded or a fetch cached — binds nothing across a restart;
// first issuance alone binds a name.
func TestHeldChainBindsNothing(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ip := HostSlot(t)
	state := t.TempDir()
	internal, control := PinnedUDPAddrOn(t, ip), FreeUDPAddrOn(t, ip)
	boot := func() *Node {
		return bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.State = state
			cfg.Internal = internal
			cfg.Control = control
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
	}
	f := boot()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unbound := addr.MustIAFrom(f.app.IA().ISD(), 0xff00000000ee)
	if _, err := f.app.TrustDB().InsertChain(t.Context(), issueAt(t, f, unbound, key)); err != nil {
		t.Fatal(err)
	}
	f.Stop(t)
	f = boot()
	bound, err := f.app.TrustDB().BoundKey(t.Context(), unbound)
	if err != nil {
		t.Fatal(err)
	}
	if bound != nil {
		t.Error("the restarted founder bound a name it holds a chain of")
	}
}
