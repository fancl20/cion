package dataplane

import (
	"unsafe"

	"github.com/scionproto/scion/pkg/slayers"
)

const (
	// TODO(karampok). Investigate whether that value should be higher.  In
	// theory, PayloadLen in SCION header is 16 bits long, supporting a maximum
	// payload size of 64KB. At the moment we are limited by Ethernet size
	// usually ~1500B, but 9000B to support jumbo frames.
	// TODO(multi_underlay): The buffer size should be a function of the collection of
	// underlays (the largest frame size of all the enabled ones).
	BufferSize = 9000

	// bufSize is an alias of BufferSize for internal use.
	bufSize = BufferSize

	// For SCMP packet quoting. A strict minimum of 28 is required. Much more is recommended.
	minHeadroom      = 512
	_           uint = minHeadroom - slayers.MaxSCMPHeaderSize // assert >= 28

	// Needed to compute required padding
	ptrSize = unsafe.Sizeof(&struct{ int }{})
	is32bit = 1 - (ptrSize-4)/4
)

type disposition int

const (
	pDiscard disposition = iota // Zero value, default.
	pForward
	pSlowPath
	pDone
)

// Packet aggregates buffers and ancillary metadata related to one packet.
// That is everything we need to pass-around while processing a packet. The motivation is to save on
// copy (pass everything via one reference) AND garbage collection (reuse everything).
// The buffer is allocated in a separate location (but still reused) to keep the packet structures
// tightly packed (might not matter, though).
// Golang gives precious little guarantees about alignment and padding. We do it ourselves in such
// a way that Go has no sane reason to add any padding. Everything is 8 byte aligned (on 64 bit
// arch) until SlowpathRequest which is 4 bytes long. The rest is in decreasing order of size and
// size-aligned. We want to fit neatly into cache lines, so we need to fit in 64 bytes. The padding
// required to occupy exactly 64 bytes depends on the architecture.
type Packet struct {
	// The useful part of the raw packet at a point in time (i.e. a slice of the full buffer).  It
	// can be any portion of the full buffer; not necessarily the start. This code maintains the
	// invariant that RawPacket always represents the portion of a packet that immediately follows
	// any underlay provider header. See also dataplane.underlayHeadroom.
	RawPacket []byte
	// The entire packet buffer. We don't need it as a slice; we know its size.
	buffer *[bufSize]byte
	// The source address during ingest and the destination during forwarding. We never need both
	// src and dst at the same time. The real type is only known to underlay provider that sets it.
	RemoteAddr unsafe.Pointer
	// The ingest link; which can give us the ifID, scope, bfdSession...
	Link Link
	// Additional metadata in case the packet is put on the slow path. Updated in-place.
	slowPathRequest slowPathRequest
	// The egress on which this packet must leave. This is set by the processing routine.
	egress uint16
	// The type of traffic. This is used for metrics at the forwarding stage, but is most
	// economically determined at the processing stage. So store it here. It's 2 bytes long.
	trafficType trafficType
	// Pad to 64 bytes. For 64bit arch, add 1 byte. For 32bit arch, add 29 bytes.
	_ [1 + is32bit*28]byte
}

// Make sure that the packet structure has the size we expect.
const (
	_ uintptr = 64 - unsafe.Sizeof(Packet{}) // assert 64 >= sizeof(Packet)
	_ uintptr = unsafe.Sizeof(Packet{}) - 64 // assert sizeof(Packet) >= 64
)

type slowPathType int8

const (
	slowPathSCMP               slowPathType = 0 // >=0 means it is an SCMP error
	slowPathRouterAlertIngress slowPathType = -1
	slowPathRouterAlertEgress  slowPathType = -2
)

// Keep this 4 bytes long. See comment for packet.
type slowPathRequest struct {
	pointer uint16
	spType  slowPathType
	code    slayers.SCMPCode
}

// initPacket configures the given blank packet (and returns it, for convenience).
func (p *Packet) init(buffer *[bufSize]byte) *Packet {
	p.buffer = buffer
	p.RawPacket = p.buffer[:]
	return p
}

// reset() makes the packet ready to receive a new underlay message. We adjust the RawPacket slice
// relative to the buffer, so there's enough headroom for any underlay headers.
func (p *Packet) reset(headroom int) {
	*p = Packet{
		buffer:    p.buffer,            // keep the buffer
		RawPacket: p.buffer[headroom:], // restore the full packet capacity (minus headroom).
	}
	// Everything else is reset to zero value.
}

// WithHeader returns the a slice of the underlying packet buffer that represents the same bytes as
// p.rawPacket[:] plus the n prededing bytes. This slice is meant to be used when receiving a raw
// packet with an n bytes header, such that the payload is exactly at p.rawPacket[0:]. p.RawPacket
// is *not* modified. This method panics if n is greater than the available headroom in the packet
// buffer.
func (p *Packet) WithHeader(n int) []byte {
	headroom := len(p.buffer) - cap(p.RawPacket) - n

	// A negative value is a panicable offense.
	return p.buffer[headroom:]
}

// PacketPool allocates and resets packets. There is one packet pool per instance of the dataplane,
// shared between all its underlay instances. This structure can be shared by copying (and doing so
// is more efficient) because headroom is never changed after construction and channel is a
// reference type.
type PacketPool struct {
	pool     chan *Packet
	headroom int
}

// Get fetches a packet from the pool and returns it initialized with the proper headroom. That is,
// pkt.rawPacket[0:] is where the packet's payload must go. Underlay providers may use any part of
// that, and MUST update the pkt.rawPacket slice to indicate where the packet's payload starts.
// However they may only use the preceding portion of the packet buffer to store a link-layer
// header. See also WithHeader
func (p *PacketPool) Get() *Packet {
	pkt := <-p.pool
	pkt.reset(p.headroom)
	return pkt
}

// Put returns the given packet to the pool.
func (p *PacketPool) Put(pkt *Packet) {
	p.pool <- pkt

}

// makePacketPool creates a packetpool of size poolSize, that configures packet buffers with the
// given headroom. The pool is initially empty. Packets must be added separately.
func makePacketPool(poolSize, headroom int) PacketPool {
	return PacketPool{pool: make(chan *Packet, poolSize), headroom: headroom}
}
