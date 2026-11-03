package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"

	"github.com/fancl20/cion/pkg/libs/loops"
)

// DERPConfig configures the node's relay presence: the address of the core's
// relay, the resolvers its name resolves through, and the stands-ins the
// integration harness needs.
type DERPConfig struct {
	// URL is the relay's HTTPS address, "https://host[:port]" — the core's
	// coordination endpoint on its own identity.
	URL string
	// Resolvers are the DNS resolvers the URL's host name resolves through,
	// each asked at the DNS port; none leaves the system's resolver.
	Resolvers []netip.Addr
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

// dnsPort is the port a resolver answers DNS on.
const dnsPort = 53

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
	// Resolvers resolve the URL's host name; none leaves the system's
	// resolver.
	Resolvers []netip.Addr
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
		if !loops.Sleep(ctx, derpReconnect) {
			return
		}
	}
}

// connectAndServe dials the relay and feeds the host socket until the
// connection or the context ends: the context's end closes the client,
// ending a blocked Recv. The dial goes to the pinned address when one is
// configured, and otherwise resolves the URL's host name through the
// resolvers, the system's resolver when none are named. The attempt closes
// its client, network monitor, and event bus as it returns.
func (b *derpBridge) connectAndServe(ctx context.Context) error {
	bus := eventbus.New()
	defer bus.Close()
	// The presence's own monitor, discarded to silence: its logs would say
	// nothing the connection's own lines do not.
	netMon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		return fmt.Errorf("building the relay monitor: %w", err)
	}
	defer func() { _ = netMon.Close() }()
	client, err := derphttp.NewClient(nodePrivateOf(b.cfg.Key), b.cfg.URL,
		logger.Logf(func(format string, args ...any) {
			slog.Debug("WireGuard DERP client: "+format, args...)
		}), netMon)
	if err != nil {
		return fmt.Errorf("building the relay client: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer func() {
		stop()
		_ = client.Close()
	}()
	switch {
	case b.cfg.IPv4 != "":
		ipv4 := b.cfg.IPv4
		client.SetURLDialer(func(ctx context.Context, network, _ string) (
			net.Conn, error) {

			var d net.Dialer
			return d.DialContext(ctx, network,
				net.JoinHostPort(ipv4, relayPortOf(b.cfg.URL)))
		})
	case len(b.cfg.Resolvers) > 0:
		client.SetURLDialer(resolvingDialer(b.cfg.Resolvers).DialContext)
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

// resolvingDialer returns a dialer that resolves host names through the
// resolvers alone, each asked at the DNS port in place of the nameservers
// the system names. Go's own resolver sends each of its exchanges over UDP
// to every resolver at once and takes the first answer, so a resolver that
// never answers delays nothing; an exchange over TCP dials the resolvers in
// order and rides the first connection that opens.
func resolvingDialer(resolvers []netip.Addr) *net.Dialer {
	servers := make([]netip.AddrPort, len(resolvers))
	for i, r := range resolvers {
		servers[i] = netip.AddrPortFrom(r.Unmap(), dnsPort)
	}
	return &net.Dialer{Resolver: &net.Resolver{
		// The system's resolver library would never call Dial.
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "udp" {
				conn, err := net.ListenUDP(network, nil)
				if err != nil {
					return nil, err
				}
				return &fanOutConn{UDPConn: conn, servers: servers}, nil
			}
			var d net.Dialer
			var errs []error
			for _, s := range servers {
				conn, err := d.DialContext(ctx, network, s.String())
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}}
}

// fanOutConn is one DNS exchange over UDP with several resolvers: a write
// goes to each of them, and a read returns the first datagram any of them
// sends.
type fanOutConn struct {
	*net.UDPConn
	servers []netip.AddrPort
}

// Write sends the datagram to every resolver, failing when no send
// succeeds.
func (c *fanOutConn) Write(b []byte) (int, error) {
	var errs []error
	for _, s := range c.servers {
		if _, err := c.WriteToUDPAddrPort(b, s); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == len(c.servers) {
		return 0, errors.Join(errs...)
	}
	return len(b), nil
}

// Read returns the next datagram a resolver sends, skipping any other
// source's. A dual-stack socket reports an IPv4 source mapped into IPv6.
func (c *fanOutConn) Read(b []byte) (int, error) {
	for {
		n, src, err := c.ReadFromUDPAddrPort(b)
		if err != nil {
			return 0, err
		}
		if slices.Contains(c.servers, netip.AddrPortFrom(src.Addr().Unmap(), src.Port())) {
			return n, nil
		}
	}
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
