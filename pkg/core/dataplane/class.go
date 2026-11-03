package dataplane

import (
	"context"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// class is the service an arrival gets at ingest, read off its SCION common
// header before any queue.
type class uint8

const (
	// classData queues on the processor queue its flow hashes to.
	classData class = iota
	// classControl queues on the control queue, which a processor of its own
	// serves, and leaves on its egress link's control queue.
	classControl
	// classLink is the link's own liveness exchange, BFD: the receive loop
	// hands it to the link's session itself, so it never queues and is never
	// forwarded.
	classLink
)

const (
	// commonHdrLen is the length of the SCION common header, which holds
	// every field the classification reads.
	commonHdrLen = 12
	// nextHdrOffset is the offset of the common header's next header field.
	nextHdrOffset = 4
)

// controlShare bounds the control class on egress: while data waits, control
// takes at most one slot in this many of a batch.
const controlShare = 4

// classOf reads an arrival's class off its common header: link for BFD, by
// its next header; control for SCMP from any link, and for the control DSCP
// in the traffic class on the internal link alone, whose only senders are
// the node's own sockets; data otherwise, a packet too short for the header
// included. A message behind an extension header is data, as its first next
// header names the extension.
func classOf(raw []byte, internal bool) class {
	if len(raw) < commonHdrLen {
		return classData
	}
	switch slayers.L4ProtocolType(raw[nextHdrOffset]) {
	case slayers.L4BFD:
		return classLink
	case slayers.L4SCMP:
		return classControl
	}
	// The traffic class spans the low nibble of the first byte and the high
	// nibble of the second, the DSCP above its two ECN bits.
	trafficClass := raw[0]<<4 | raw[1]>>4
	if internal && trafficClass>>2 == underlay.ControlDSCP {
		return classControl
	}
	return classData
}

// bfdReader decodes the BFD arrivals of one link's receive loop. Its layers
// are reused from one arrival to the next, so one goroutine reads with it.
type bfdReader struct {
	scion slayers.SCION
	bfd   layers.BFD
}

// newBFDReader returns a reader whose SCION layer reuses its decoded paths.
func newBFDReader() *bfdReader {
	r := &bfdReader{}
	r.scion.RecyclePaths()
	return r
}

// read hands a SCION-framed BFD control packet over an empty or a one-hop
// path to the session, as the processor's BFD branch does, reporting whether
// it did: a packet it cannot decode, or a link without a session, hands
// nothing.
func (r *bfdReader) read(raw []byte, session Session) bool {
	if session == nil {
		return false
	}
	if err := r.scion.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
		return false
	}
	switch r.scion.PathType {
	case empty.PathType, onehop.PathType:
	default:
		return false
	}
	if err := r.bfd.DecodeFromBytes(r.scion.Payload, gopacket.NilDecodeFeedback); err != nil {
		return false
	}
	session.ReceiveMessage(&r.bfd)
	return true
}

// queueArrival queues an arrival on a processor queue, dropping it as a busy
// processor when the queue is full.
func queueArrival(
	q chan<- *Packet, p *Packet, pool PacketPool, metrics *InterfaceMetrics, sc sizeClass,
) {
	if !enqueue(q, p) {
		pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Add(context.Background(), 1)
	}
}

// egressQueue returns the egress queue of the packet's class among a link's
// two.
func egressQueue(p *Packet, data, control chan<- *Packet) chan<- *Packet {
	if p.control {
		return control
	}
	return data
}

// enqueue queues the packet without blocking, reporting whether the queue
// took it.
func enqueue(q chan<- *Packet, p *Packet) bool {
	select {
	case q <- p:
		return true
	default:
		return false
	}
}
