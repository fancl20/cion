package wireguard

import (
	"context"
	"errors"
	"fmt"
	"go4.org/mem"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// DERPConfig configures the node's relay presence: the address of the core's
// relay and the stands-ins the integration harness needs.
type DERPConfig struct {
	// URL is the relay's HTTPS address, "https://host[:port]" — the core's
	// coordination endpoint on its own identity.
	URL string
	// IPv4 optionally dials the relay by address instead of DNS — the
	// harness's stand-in for resolution.
	IPv4 string
	// CertName optionally pins the certificate the relay presents, in the
	// DERP map's grammar — the harness's stand-in for the WebPKI.
	CertName string
}

// The bridge's own times: a short reconnect pace, so a relay connection
// lost returns inside a fetch cadence, and the connect timeout the relay
// dial answers within.
const (
	// derpReconnect paces a lost relay connection's return.
	derpReconnect = 5 * time.Second
	// derpConnect bounds one relay dial.
	derpConnect = 10 * time.Second
)

// derpBridge is the node's DERP presence: one relay client keyed by the
// node's own WireGuard public key — the key the netmap's peer already names
// — whose received datagrams feed the shared host socket and whose sends
// carry the replies. A DERP-sourced datagram reaches the host device with a
// synthetic endpoint naming the sender's key, and WireGuard's own roaming
// carries the leg switch: the peer's endpoint is whichever leg's
// authenticated packet arrived last, UDP or relay, no discovery protocol
// beside the transport. The bridge is the application's only new
// data-carrying code, and it is bounded: one connection, one feed, one
// send path.
// derpConn is the relay connection the bridge holds: the receive the feed
// loop blocks on and the send the replies ride. The vendored client
// satisfies it; the tests' double does.
type derpConn interface {
	Recv() (derp.ReceivedMessage, error)
	Send(key.NodePublic, []byte) error
}

type derpBridge struct {
	cfg derpBridgeConfig

	// mtx guards conn, shared by the receive loop and the send path.
	mtx  sync.Mutex
	conn derpConn
}

// derpBridgeConfig carries what the bridge builds on.
type derpBridgeConfig struct {
	// Key is the node's WireGuard private key — the presence's identity.
	Key PrivateKey
	// Socket is the shared host-facing port the relay's datagrams feed.
	Socket *hostSocket
	// Cnt counts the bridge's drops.
	Cnt *counters
	// URL is the relay's HTTPS address.
	URL string
	// IPv4 optionally dials the relay by address.
	IPv4 string
}

// newDERPBridge builds the presence; run serves it.
func newDERPBridge(cfg derpBridgeConfig) *derpBridge {
	return &derpBridge{cfg: cfg}
}

// run holds the relay connection until the context is canceled: one dial of
// the core's relay, the receive loop feeding the shared host socket, and
// the reconnect that returns a lost connection.
func (b *derpBridge) run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := b.connectAndServe(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("WireGuard DERP presence", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(derpReconnect):
		}
	}
}

// connectAndServe dials the relay and feeds the host socket until the
// connection or the context ends.
func (b *derpBridge) connectAndServe(ctx context.Context) error {
	// The presence's own monitor, discarded to silence: its logs would say
	// nothing the connection's own lines do not.
	netMon, err := netmon.New(eventbus.New(), logger.Discard)
	if err != nil {
		return fmt.Errorf("building the relay monitor: %w", err)
	}
	client, err := derphttp.NewClient(nodePrivateOf(b.cfg.Key), b.cfg.URL,
		logger.Logf(func(format string, args ...any) {
			slog.Debug("WireGuard DERP client: "+format, args...)
		}), netMon)
	if err != nil {
		return fmt.Errorf("building the relay client: %w", err)
	}
	if b.cfg.IPv4 != "" {
		ipv4 := b.cfg.IPv4
		client.SetURLDialer(func(ctx context.Context, network, _ string) (
			net.Conn, error) {

			var d net.Dialer
			return d.DialContext(ctx, network,
				net.JoinHostPort(ipv4, relayPortOf(b.cfg.URL)))
		})
	}
	connectCtx, cancel := context.WithTimeout(ctx, derpConnect)
	defer cancel()
	if err := client.Connect(connectCtx); err != nil {
		return fmt.Errorf("dialing the relay: %w", err)
	}
	b.mtx.Lock()
	b.conn = client
	b.mtx.Unlock()
	defer func() {
		b.mtx.Lock()
		b.conn = nil
		b.mtx.Unlock()
	}()
	slog.Info("WireGuard DERP presence up", "url", b.cfg.URL)

	for ctx.Err() == nil {
		msg, err := client.Recv()
		if err != nil {
			return fmt.Errorf("the relay connection: %w", err)
		}
		b.deliver(msg)
	}
	return nil
}

// deliver feeds one relay message to the shared host socket: a datagram
// reaches the device as if it had arrived on the socket, the synthetic
// endpoint naming the sender's key — the leg the send path returns over.
func (b *derpBridge) deliver(msg derp.ReceivedMessage) {
	pkt, ok := msg.(derp.ReceivedPacket)
	if !ok {
		return
	}
	var sender PublicKey
	copy(sender[:], pkt.Source.AppendTo(nil))
	b.cfg.Socket.deliver(pkt.Data, &hostEndpoint{derp: sender})
}

// send carries one datagram to a relay-sourced peer. The bridge holds no
// queue of its own: a presence without a connection drops, the client's own
// retries covering the reconnect.
func (b *derpBridge) send(dst PublicKey, pkt []byte) error {
	b.mtx.Lock()
	conn := b.conn
	b.mtx.Unlock()
	if conn == nil {
		b.cfg.Cnt.droppedPackets.Add(1)
		return errors.New("no relay connection")
	}
	return conn.Send(nodePublicOf(dst), pkt)
}

// nodePrivateOf converts the node's key to the relay client's — the cast
// from wireguard-go's key type the function exists for.
func nodePrivateOf(k PrivateKey) key.NodePrivate {
	return key.NodePrivateFromRaw32(mem.B(k[:])) // nolint - wireguard-go's key type
}

// nodePublicOf converts a peer's key to the relay's addressing.
func nodePublicOf(k PublicKey) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(k[:]))
}

// relayPortOf extracts the relay URL's port, defaulting to HTTPS's own.
func relayPortOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "443"
	}
	if port := parsed.Port(); port != "" {
		return port
	}
	return "443"
}
