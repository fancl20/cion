package dataplane

import (
	"context"

	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
)

// LinkScope describes the kind (or scope) of a link: internal, sibling, or external.
type LinkScope int

const (
	Internal LinkScope = iota // to/from end-hosts in the local AS
	Sibling                   // to/from (external interfaces owned by) a sibling router
	External                  // to/from routers in another AS
)

// RawWriter sends a prebuilt packet on a link's own underlay socket —
// beneath the forwarding queues and the egress validation above them — so a
// BFD session's stream survives its own down verdict by construction: a
// probe gated by the verdict could never overturn it.
type RawWriter interface {
	WriteRaw(b []byte) error
}

// Session is the BFD session of a link: every control packet the link
// receives is handed to it, its verdict is the flag the egress check reads,
// and the link attaches its raw writer at construction — the one send path
// that stays open while the link is down, which is how recovery is seen.
type Session interface {
	// ReceiveMessage hands one received BFD control message to the session.
	ReceiveMessage(msg *layers.BFD)
	// IsUp returns the session's verdict: up until the detect multiplier
	// expires without an arrival, up again on the next answered one.
	IsUp() bool
	// SetRawWriter attaches the link's writer for prebuilt packets.
	SetRawWriter(w RawWriter)
}

// Link embodies the router's idea of a point to point connection. A link associates the underlay
// connection with a BFDSession, a destination address, etc. It also allows the concrete send
// operation to be delegated to different underlay implementations. The association between
// link and underlay connection is a channel, on the sending side, and a demultiplexer on
// the receiving side. The demultiplexer must have a src-addr:link map in all cases where links
// share connections.
//
// Regardless of underlay, links come in three scopes: internal, sibling, and external. The
// difference in behaviour is hidden from the rest of the router. The router only needs to
// associate an interface ID with a link. If the interface ID belongs to a sibling router, then
// the link is a sibling link. If the interface ID is zero, then the link is the internal link.
//
// Note about Resolve. It resolves the given SCION host/svc address to an address on this underlay.
// This functionality is really only needed on the internal link,
type Link interface {
	// IsUp returns whether this link is functional according to the associated BFD session.
	IsUp() bool
	// IfID returns the interface ID associated with this link. 0 for sibling and internal links.
	IfID() uint16
	// Metrics returns the metrics specific to this link.
	Metrics() *InterfaceMetrics
	// Scope returns the scope of this link: internal, external, or sibling.
	Scope() LinkScope
	// BFDSession returns the BFD session associated with this link.
	BFDSession() Session
	// Resolve finds and sets the packet's internal underlay destination for the given dst and port.
	Resolve(p *Packet, dst addr.Host, port uint16) error
	// Send queues the packet for sending over this link; discarding if the queue is full.
	Send(p *Packet) bool
	// SendBlocking queues the packet for sending over this link; blocking while the queue is full.
	SendBlocking(p *Packet)
}

// UnderlayProvider is a provider of connectivity over some underlay implementation. It owns the
// connections that carry the traffic of the links it creates.
type UnderlayProvider interface {
	// NumConnections returns the current number of configured connections.
	NumConnections() int

	// Headroom returns the length of the largest header possibly added by this underlay.
	// The dataplane ensures that all received packets are stored at an offset in the packet
	// buffer such that the largest underlay header declared across all underlay providers can
	// be prepended to the SCION header without having to copy the packet or to allocate a
	// separate buffer.
	Headroom() int

	// NewExternalLink returns a link that addresses a single remote AS at a unique underlay
	// address. Outgoing packets do not need an underlay destination as metadata. Incoming
	// packets have a defined ingress ifID.
	NewExternalLink(
		qSize int,
		bfd Session,
		local string,
		remote string,
		ifID uint16,
		metrics *InterfaceMetrics,
	) (Link, error)

	// NewInternalLink returns a link that addresses any host internal to the enclosing AS.
	// Outgoing packets need to have a destination address as metadata. Incoming packets have
	// no defined ingress ifID.
	NewInternalLink(localAddr string, qSize int, metrics *InterfaceMetrics) (Link, error)

	// Start puts the provider in the running state. In that state, the provider delivers
	// incoming packets to the given processor queues and sends the packets queued on its
	// links. Only connections in existence at the time of calling Start are started.
	Start(ctx context.Context, pool PacketPool, procQs []chan *Packet)

	// Stop puts the provider in the stopped state. In that state, the provider no longer
	// delivers incoming packets and ignores packets present on its input channels.
	Stop()
}
