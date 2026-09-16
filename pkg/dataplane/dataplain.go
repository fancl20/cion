package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"math"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
)

var (
	ErrUnsupportedV4MappedV6Address  = errors.New("unsupported v4mapped IP v6 address")
	ErrUnsupportedUnspecifiedAddress = errors.New("unsupported unspecified address")
	ErrNoSVCBackend                  = errors.New("cannot find internal IP for the SVC")

	errInvalidSrcIA                  = errors.New("invalid source ISD-AS")
	errInvalidDstIA                  = errors.New("invalid destination ISD-AS")
	errInvalidSrcAddrForTransit      = errors.New("invalid source address for transit pkt")
	errInvalidDstAddr                = errors.New("invalid destination address")
	errCannotRoute                   = errors.New("cannot route, dropping pkt")
	errEmptyValue                    = errors.New("empty value")
	errMalformedPath                 = errors.New("malformed path content")
	errModifyExisting                = errors.New("modifying a running dataplane is not allowed")
	errUnsupportedPathType           = errors.New("unsupported path type")
	errUnsupportedPathTypeNextHeader = errors.New("unsupported combination")
	errNoSuchUnderlay                = errors.New("no such underlay provider")
	errNoBFDSessionFound             = errors.New("no BFD session was found")
	errPeeringEmptySeg0              = errors.New("zero-length segment[0] in peering path")
	errPeeringEmptySeg1              = errors.New("zero-length segment[1] in peering path")
	errPeeringNonemptySeg2           = errors.New("non-zero-length segment[2] in peering path")
	errBFDSessionDown                = errors.New("bfd session down")
	errExpiredHop                    = errors.New("expired hop")
	errIngressInterfaceInvalid       = errors.New("ingress interface invalid")
	errMacVerificationFailed         = errors.New("MAC verification failed")
	errBadPacketSize                 = errors.New("bad packet size")

	// zeroBuffer will be used to reset the Authenticator option in the
	// scionPacketProcessor.OptAuth
	zeroBuffer = make([]byte, 16)
)

type drkeyProvider interface {
	GetASHostKey(validTime time.Time, dstIA addr.IA, dstAddr addr.Host) (drkey.ASHostKey, error)
	GetKeyWithinAcceptanceWindow(validTime time.Time, timestamp uint64, dstIA addr.IA, dstAddr addr.Host) (drkey.ASHostKey, error)
}

type DataPlane struct {
	localIA       addr.IA
	localHost     addr.Host
	interfaces    [math.MaxUint16 + 1]Link
	numInterfaces int
	macFactory    func() hash.Hash
	underlays     []UnderlayProvider
	running       atomic.Bool
	// processors tracks the fast- and slow-path processor goroutines, so
	// Serve's graceful shutdown can wait for their exit.
	processors sync.WaitGroup

	RunConfig RunConfig

	// The pool that stores all the packet buffers as described in the design document. See
	// https://github.com/scionproto/scion/blob/master/doc/dev/design/BorderRouter.rst
	// To avoid garbage collection, most the meta-data that is produced during the processing of a
	// packet is kept in a data structure (packet struct) that is pooled and recycled along with
	// corresponding packet buffer. The packet struct refers permanently to the packet buffer. The
	// packet structure is fetched from the pool passed-around through the various channels and
	// returned to the pool. To reduce the cost of copying, the packet structure is passed by
	// reference.
	packetPool PacketPool

	// underlayHeadRoom is the minimum headroom that must be reserved at the front of every packet
	// to ensure that every underlay provider can prepend its underlay header without copying. It
	// is established by collecting the headroom requirement of every underlay provider. Underlay
	// providers deliver incoming packets such that the RawPacket slice starts exactly after the
	// link layer header. Underlay providers may use the preceding part of the packet buffer to
	// receive the link layer header.
	underlayHeadroom int
}

// NewDataPlane creates a data plane for the given IA. The links must include at most one
// link with IfID 0 (the internal link) and are indexed by their interface ID. All links
// must have been created by the given provider.
func NewDataPlane(
	ia addr.IA,
	host addr.Host,
	key []byte,
	provider UnderlayProvider,
	links []Link,
) (*DataPlane, error) {

	// Validate the key the same way the factory will use it.
	if _, err := scrypto.InitMac(key); err != nil {
		return nil, fmt.Errorf("initializing MAC: %w", err)
	}
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(key)
		return mac
	}
	d := &DataPlane{
		localIA:    ia,
		localHost:  host,
		macFactory: macFactory,
		underlays:  []UnderlayProvider{provider},
	}
	for _, l := range links {
		d.interfaces[l.IfID()] = l
	}
	d.numInterfaces = len(links)
	return d, nil
}

type RunConfig struct {
	NumProcessors         int
	NumSlowPathProcessors int
	BatchSize             int
	ReceiveBufferSize     int
	SendBufferSize        int
}

func (d *DataPlane) Serve(ctx context.Context) error {
	if d.numInterfaces == 0 {
		// Not stritcly an error but we really can't do anything.
		return nil
	}

	numConnections := 0
	for _, u := range d.underlays {
		numConnections += u.NumConnections()
	}
	processorQueueSize := max(
		numConnections*d.RunConfig.BatchSize/d.RunConfig.NumProcessors,
		d.RunConfig.BatchSize,
	)
	d.initPacketPool(processorQueueSize)
	procQs, slowQs := d.initQueues(processorQueueSize)
	d.setRunning()
	for _, u := range d.underlays {
		u.Start(ctx, d.packetPool, procQs)
	}
	for i := 0; i < d.RunConfig.NumProcessors; i++ {
		d.processors.Add(1)
		go func(i int) {
			defer handlePanic()
			defer d.processors.Done()
			d.runProcessor(ctx, i, procQs[i], slowQs[i%d.RunConfig.NumSlowPathProcessors])
		}(i)
	}
	for i := 0; i < d.RunConfig.NumSlowPathProcessors; i++ {
		d.processors.Add(1)
		go func(i int) {
			defer handlePanic()
			defer d.processors.Done()
			d.runSlowPathProcessor(ctx, i, slowQs[i])
		}(i)
	}

	<-ctx.Done()
	// Graceful shutdown (ADR-0006): the underlay stops ingesting and its
	// links flush and close, the processors drain their queues and exit, and
	// Serve returns with the underlay addresses released — the replacement
	// generation binds them next.
	for _, u := range d.underlays {
		u.Stop()
	}
	d.setStopping()
	d.processors.Wait()
	return nil
}

// setRunning configures the running state of the data plane to true. It is called once
// the dataplane is finished initializing and is ready to process packets.
func (d *DataPlane) setRunning() {
	d.running.Store(true)
}

// setStopping configures the running state of the data plane to false. There is no
// mechanism to restart a stopped dataplane.
func (d *DataPlane) setStopping() {
	d.running.Store(false)
}

// isRunning indicates whether the data plane is ready to process, or already
// processing, packets.
func (d *DataPlane) isRunning() bool {
	return d.running.Load()
}

// handlePanic logs a recovered panic. The goroutine terminates, but the process
// survives.
func handlePanic() {
	panicValue := recover()
	if panicValue == nil {
		return
	}
	slog.Error("Panic", "panic", panicValue, "stack", string(debug.Stack()))
}

// initializePacketPool calculates the size of the packet pool based on the
// current dataplane settings and allocates all the buffers
func (d *DataPlane) initPacketPool(processorQueueSize int) {
	// collect pool size and headroom reqs
	poolSize := d.numInterfaces*d.RunConfig.BatchSize +
		(d.RunConfig.NumProcessors+d.RunConfig.NumSlowPathProcessors)*(processorQueueSize+1) +
		d.numInterfaces*2*d.RunConfig.BatchSize
	headroom := 0
	for _, u := range d.underlays {
		h := u.Headroom()
		if headroom < h {
			headroom = h
		}
	}
	d.underlayHeadroom = headroom

	// We round-up the minimum headroom generously so that the extra room is sufficient to allow the
	// quoting of most packets by SCMP cheaply (that is, without moving the bytes). Our packet
	// buffers are sized at 9000 bytes while in most cases the interface MTU is lower.
	if headroom < minHeadroom {
		headroom = minHeadroom
	}
	d.packetPool = makePacketPool(poolSize, headroom)
	pktBuffers := make([][bufSize]byte, poolSize)
	pktStructs := make([]Packet, poolSize)
	for i := 0; i < poolSize; i++ {
		d.packetPool.Put(pktStructs[i].init(&pktBuffers[i]))
	}
}

// initializes the processing routines and queues
func (d *DataPlane) initQueues(processorQueueSize int) ([]chan *Packet, []chan *Packet) {
	procQs := make([]chan *Packet, d.RunConfig.NumProcessors)
	for i := 0; i < d.RunConfig.NumProcessors; i++ {
		procQs[i] = make(chan *Packet, processorQueueSize)
	}
	slowQs := make([]chan *Packet, d.RunConfig.NumSlowPathProcessors)
	for i := 0; i < d.RunConfig.NumSlowPathProcessors; i++ {
		slowQs[i] = make(chan *Packet, processorQueueSize)
	}
	return procQs, slowQs
}

func (d *DataPlane) runProcessor(ctx context.Context, id int, q <-chan *Packet, slowQ chan<- *Packet) {
	slog.Debug("Initialize processor", "id", id)
	processor := newPacketProcessor(d)
	for d.isRunning() {
		var p *Packet
		select {
		case <-ctx.Done():
			return
		case got, ok := <-q:
			if !ok {
				continue
			}
			p = got
		}
		disp := processor.processPkt(p)

		sc := ClassOfSize(len(p.RawPacket))
		metrics := p.Link.Metrics()
		metrics[sc].ProcessedPackets.Add(ctx, 1)

		switch disp {
		case pForward:
			// Normal processing proceeds.
		case pSlowPath:
			// Not an error, processing continues on the slow path.
			select {
			case slowQ <- p:
			default:
				metrics[sc].DroppedPacketsBusySlowPath.Add(ctx, 1)
				d.packetPool.Put(p)
			}
			continue
		case pDone: // Packets that don't need more processing (e.g. BFD)
			d.packetPool.Put(p)
			continue
		case pDiscard: // Everything else
			metrics[sc].DroppedPacketsInvalid.Add(ctx, 1)
			d.packetPool.Put(p)
			continue
		default: // Newly added dispositions need to be handled.
			slog.Debug("Unknown packet disposition", "disp", disp)
			d.packetPool.Put(p)
			continue
		}
		fwLink := d.interfaces[p.egress]
		if fwLink == nil {
			slog.Debug("Error determining forwarder. Egress is invalid", "egress", p.egress)
			d.packetPool.Put(p)
			metrics[sc].DroppedPacketsInvalid.Add(ctx, 1)
			continue
		}
		if !fwLink.Send(p) {
			d.packetPool.Put(p)
			metrics[sc].DroppedPacketsBusyForwarder.Add(ctx, 1)
		}
	}
}

func (d *DataPlane) runSlowPathProcessor(ctx context.Context, id int, q <-chan *Packet) {
	slog.Debug("Initialize slow-path processor", "id", id)
	processor := newSlowPathProcessor(d)
	for d.isRunning() {
		var p *Packet
		select {
		case <-ctx.Done():
			return
		case got, ok := <-q:
			if !ok {
				continue
			}
			p = got
		}
		err := processor.processPacket(p)
		if err != nil {
			slog.Debug("Error processing packet", "err", err)
			sc := ClassOfSize(len(p.RawPacket))
			p.Link.Metrics()[sc].DroppedPacketsInvalid.Add(ctx, 1)
			d.packetPool.Put(p)
			continue
		}
		// All slowpath packets are responses to the sender. Therefore, the egress link is always
		// the ingress link.
		egressLink := p.Link
		if egressLink == nil {
			slog.Debug("Error determining return link. No ingress link")
			d.packetPool.Put(p)
			continue
		}
		if !egressLink.Send(p) {
			d.packetPool.Put(p)
		}
	}
}

// resolveLocalDst updates the packet's remote address (from then on, its destination) by
// translating the given SCION address (host or service) into an underlay address.
func (d *DataPlane) resolveLocalDst(packet *Packet, s slayers.SCION, lastLayer gopacket.DecodingLayer) error {
	a, err := s.DstAddr()
	if err != nil {
		return errInvalidDstAddr
	}

	p := uint16(0)
	if a.Type() == addr.HostTypeIP {
		// In this case, we must find the destination SCION port so we have a chance to dispatch to
		// to the UDP port of the same number directly instead of going through the dispatcher.
		// It's our job to figure that; the underlay doesn't know the SCION header.
		p, err = d.dstScionPort(lastLayer)
		if err != nil {
			return err
		}
	}

	// Let the internal (it better be) link resolve the destination to an underlay address.
	return d.interfaces[packet.egress].Resolve(packet, a, p)
}

func (d *DataPlane) dstScionPort(lastLayer gopacket.DecodingLayer) (uint16, error) {
	// Parse UPD port and rewrite underlay IP/UDP port
	l4Type := nextHdr(lastLayer)
	port := uint16(EndhostPort)

	switch l4Type {
	case slayers.L4UDP:
		if len(lastLayer.LayerPayload()) < 8 {
			// TODO(JordiSubira): Treat this as a parameter problem
			return 0, fmt.Errorf("SCION/UDP header len too small: length: %d", len(lastLayer.LayerPayload()))
		}
		port = binary.BigEndian.Uint16(lastLayer.LayerPayload()[2:])
	case slayers.L4TCP:
		if len(lastLayer.LayerPayload()) < 20 {
			// TODO: Treat this as a parameter problem
			return 0, fmt.Errorf("SCION/TCP header len too small: length: %d",
				len(lastLayer.LayerPayload()))
		}
		port = binary.BigEndian.Uint16(lastLayer.LayerPayload()[2:])
	case slayers.L4SCMP:
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			// TODO(JordiSubira): Treat this as a parameter problem.
			return 0, fmt.Errorf("decoding SCMP layer for extracting endhost dst port: %w", err)
		}
		port, err = getDstPortSCMP(&scmpLayer)
		if err != nil {
			// TODO(JordiSubira): Treat this as a parameter problem.
			return 0, fmt.Errorf("getting dst port from SCMP message: %w", err)
		}
	default:
		// do nothing
	}
	return port, nil
}

func getDstPortSCMP(scmp *slayers.SCMP) (uint16, error) {
	// XXX(JordiSubira): This implementation is far too slow for the dataplane.
	// We should reimplement this with fewer helpers and memory allocations, since
	// our sole goal is to parse the L4 port or identifier in the offending packets.
	if scmp.TypeCode.Type() == slayers.SCMPTypeEchoRequest ||
		scmp.TypeCode.Type() == slayers.SCMPTypeTracerouteRequest {
		return EndhostPort, nil
	}
	if scmp.TypeCode.Type() == slayers.SCMPTypeEchoReply {
		var scmpEcho slayers.SCMPEcho
		err := scmpEcho.DecodeFromBytes(scmp.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return 0, err
		}
		return scmpEcho.Identifier, nil
	}
	if scmp.TypeCode.Type() == slayers.SCMPTypeTracerouteReply {
		var scmpTraceroute slayers.SCMPTraceroute
		err := scmpTraceroute.DecodeFromBytes(scmp.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return 0, err
		}
		return scmpTraceroute.Identifier, nil
	}

	// Drop unknown SCMP error messages.
	if scmp.NextLayerType() == gopacket.LayerTypePayload {
		return 0, fmt.Errorf("unsupported SCMP error message: type: %d", scmp.TypeCode.Type())
	}
	l, err := decodeSCMP(scmp)
	if err != nil {
		return 0, err
	}
	if len(l) != 2 {
		return 0, fmt.Errorf("SCMP error message without payload")
	}
	gpkt := gopacket.NewPacket(*l[1].(*gopacket.Payload), slayers.LayerTypeSCION,
		gopacket.DecodeOptions{
			NoCopy: true,
		},
	)

	// If the offending packet was UDP/SCION, use the source port to deliver.
	if udp := gpkt.Layer(slayers.LayerTypeSCIONUDP); udp != nil {
		port := udp.(*slayers.UDP).SrcPort
		// XXX(roosd): We assume that the zero value means the UDP header is
		// truncated. This flags packets of misbehaving senders as truncated, if
		// they set the source port to 0. But there is no harm, since those
		// packets are destined to be dropped anyway.
		if port == 0 {
			return 0, fmt.Errorf("SCMP error with truncated UDP header")
		}
		return port, nil
	}

	// If the offending packet was SCMP/SCION, and it is an echo or traceroute,
	// use the Identifier to deliver. In all other cases, the message is dropped.
	if scmp := gpkt.Layer(slayers.LayerTypeSCMP); scmp != nil {

		tc := scmp.(*slayers.SCMP).TypeCode
		// SCMP Error messages in response to an SCMP error message are not allowed.
		if !tc.InfoMsg() {
			return 0, fmt.Errorf("SCMP error message in response to SCMP error message: type: %d", tc.Type())
		}
		// We only support echo and traceroute requests.
		t := tc.Type()
		if t != slayers.SCMPTypeEchoRequest && t != slayers.SCMPTypeTracerouteRequest {
			return 0, fmt.Errorf("unsupported SCMP info message: type: %d", t)
		}

		var port uint16
		// Extract the port from the echo or traceroute ID field.
		if echo := gpkt.Layer(slayers.LayerTypeSCMPEcho); echo != nil {
			port = echo.(*slayers.SCMPEcho).Identifier
		} else if tr := gpkt.Layer(slayers.LayerTypeSCMPTraceroute); tr != nil {
			port = tr.(*slayers.SCMPTraceroute).Identifier
		} else {
			return 0, fmt.Errorf("SCMP error with truncated payload")
		}
		return port, nil
	}
	return 0, fmt.Errorf("unknown SCION SCMP content")
}

// decodeSCMP decodes the SCMP payload. WARNING: Decoding is done with NoCopy set.
func decodeSCMP(scmp *slayers.SCMP) ([]gopacket.SerializableLayer, error) {
	gpkt := gopacket.NewPacket(scmp.Payload, scmp.NextLayerType(),
		gopacket.DecodeOptions{NoCopy: true})
	layers := gpkt.Layers()
	if len(layers) == 0 || len(layers) > 2 {
		return nil, fmt.Errorf("invalid number of SCMP layers: count: %d", len(layers))
	}
	ret := make([]gopacket.SerializableLayer, len(layers))
	for i, l := range layers {
		s, ok := l.(gopacket.SerializableLayer)
		if !ok {
			return nil, fmt.Errorf("invalid SCMP layer, not serializable: index: %d", i)
		}
		ret[i] = s
	}
	return ret, nil
}

func nextHdr(layer gopacket.DecodingLayer) slayers.L4ProtocolType {
	switch v := layer.(type) {
	case *slayers.SCION:
		return v.NextHdr
	case *slayers.EndToEndExtnSkipper:
		return v.NextHdr
	case *slayers.HopByHopExtnSkipper:
		return v.NextHdr
	default:
		return slayers.L4None
	}
}
