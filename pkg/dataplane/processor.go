package dataplane

import (
	"crypto/subtle"
	"fmt"
	"hash"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/spao"
)

const (
	// e2eAuthHdrLen is the length in bytes of added information when a SCMP packet
	// needs to be authenticated: 16B (e2e.option.Len()) + 16B (CMAC_tag.Len()).
	e2eAuthHdrLen = 32
)

func newPacketProcessor(d *DataPlane) *scionPacketProcessor {
	p := &scionPacketProcessor{
		d:              d,
		mac:            d.macFactory(),
		macInputBuffer: make([]byte, path.MACBufferSize),
	}
	p.scionLayer.RecyclePaths()
	return p
}

// scionPacketProcessor processes packets. It contains pre-allocated per-packet
// mutable state and context information which should be reused.
type scionPacketProcessor struct {
	d               *DataPlane    // The dataplane instance that initiated this processor.
	pkt             *Packet       // Packet currently being processed by this processor.
	ingressFromLink uint16        // IfID associated with the ingress link, if any.
	mac             hash.Hash     // hasher for the MAC computation.
	scionLayer      slayers.SCION // scionLayer is the SCION gopacket layer.
	hbhLayer        slayers.HopByHopExtnSkipper
	e2eLayer        slayers.EndToEndExtnSkipper
	lastLayer       gopacket.DecodingLayer // Last parsed layer: &scionLayer, &hbhLayer or &e2eLayer
	path            *scion.Raw             // Raw SCION path. Will be set during processing.
	hopField        path.HopField          // Current hop field, updated during processing.
	infoField       path.InfoField         // Current info field, updated during processing.
	effectiveXover  bool                   // Whether a segment cross-over was done.
	peering         bool                   // Whether the current hop field is a peering hop field.
	cachedMac       []byte                 // Full MAC. For a Xover, that of the down segment.
	macInputBuffer  []byte                 // Reusable buffer for MAC computation.
	bfdLayer        layers.BFD             // Reusable buffer for parsing BFD messages
}

func (p *scionPacketProcessor) reset() error {
	p.pkt = nil
	p.ingressFromLink = 0
	// p.scionLayer // cannot easily be reset
	p.path = nil
	p.hopField = path.HopField{}
	p.infoField = path.InfoField{}
	p.effectiveXover = false
	p.peering = false
	p.mac.Reset()
	p.cachedMac = nil
	// Reset hbh layer
	p.hbhLayer = slayers.HopByHopExtnSkipper{}
	// Reset e2e layer
	p.e2eLayer = slayers.EndToEndExtnSkipper{}
	return nil
}

// Convenience function to log an error and return the pDiscard disposition.
// We do almost nothing with errors, so, we shouldn't invest in creating them.
func errorDiscard(ctx ...any) disposition {
	// TODO: logging discard
	return pDiscard
}

func (p *scionPacketProcessor) processPkt(pkt *Packet) disposition {
	if err := p.reset(); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt = pkt
	p.ingressFromLink = pkt.Link.IfID()

	// parse SCION header and skip extensions;
	var err error
	p.lastLayer, err = decodeLayers(pkt.RawPacket, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return errorDiscard("error", err)
	}

	pld := p.lastLayer.LayerPayload()

	pathType := p.scionLayer.PathType
	switch pathType {
	case empty.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			return p.processBFD(pld)
		}
		return errorDiscard("error", errUnsupportedPathTypeNextHeader)

	case onehop.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			_, ok := p.scionLayer.Path.(*onehop.Path)
			if !ok {
				return errorDiscard("error", errMalformedPath)
			}
			return p.processBFD(pld)
		}
		return p.processOHP()
	case scion.PathType:
		return p.processSCION()
	case epic.PathType:
		return errorDiscard("error", errUnsupportedPathType)
	default:
		return errorDiscard("error", errUnsupportedPathType)
	}
}

func (p *scionPacketProcessor) processBFD(data []byte) disposition {
	session := p.pkt.Link.BFDSession()
	if session == nil {
		return errorDiscard("error", errNoBFDSessionFound)
	}
	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return errorDiscard("error", err)
	}
	session.ReceiveMessage(bfd)
	return pDone // All's fine. That packet's journey ends here.
}

func (p *scionPacketProcessor) processSCION() disposition {
	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", errMalformedPath)
	}
	return p.process()
}

func (p *scionPacketProcessor) processOHP() disposition {
	s := p.scionLayer
	ohp, ok := s.Path.(*onehop.Path)
	if !ok {
		return errorDiscard("error", errMalformedPath)
	}
	if !ohp.Info.ConsDir {
		return errorDiscard("error", errMalformedPath)
	}

	// OHP leaving our IA
	if p.ingressFromLink == 0 {
		if !p.d.localIA.Equal(s.SrcIA) {
			return errorDiscard("error", errCannotRoute)
		}
		mac := path.MAC(p.mac, ohp.Info, ohp.FirstHop, p.macInputBuffer[:path.MACBufferSize])
		if subtle.ConstantTimeCompare(ohp.FirstHop.Mac[:], mac[:]) == 0 {
			// TODO parameter problem -> invalid MAC
			return errorDiscard("error", errMacVerificationFailed)
		}
		ohp.Info.UpdateSegID(ohp.FirstHop.Mac)

		if err := updateSCIONLayer(p.pkt.RawPacket, s); err != nil {
			return errorDiscard("error", err)
		}
		p.pkt.egress = ohp.FirstHop.ConsEgress
		return pForward
	}

	// OHP entering our IA
	if !p.d.localIA.Equal(s.DstIA) {
		return errorDiscard("error", errCannotRoute)
	}

	ohp.SecondHop = path.HopField{
		ConsIngress: p.ingressFromLink,
		ExpTime:     ohp.FirstHop.ExpTime,
	}
	// XXX(roosd): Here we leak the buffer into the SCION packet header.
	// This is okay because we do not operate on the buffer or the packet
	// for the rest of processing.
	ohp.SecondHop.Mac = path.MAC(p.mac, ohp.Info, ohp.SecondHop,
		p.macInputBuffer[:path.MACBufferSize])

	if err := updateSCIONLayer(p.pkt.RawPacket, s); err != nil {
		return errorDiscard("error", err)
	}
	err := p.d.resolveLocalDst(p.pkt, s, p.lastLayer)
	if err != nil {
		return errorDiscard("error", err)
	}

	return pForward
}

func (p *scionPacketProcessor) parsePath() disposition {
	var err error
	p.hopField, err = p.path.GetCurrentHopField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", err)
	}
	p.infoField, err = p.path.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", err)
	}
	// Segments without the Peering flag must consist of at least two HFs:
	// https://github.com/scionproto/scion/issues/4524
	hasSingletonSegment := p.path.PathMeta.SegLen[0] == 1 ||
		p.path.PathMeta.SegLen[1] == 1 ||
		p.path.PathMeta.SegLen[2] == 1
	if !p.infoField.Peer && hasSingletonSegment {
		return errorDiscard("error", errMalformedPath)
	}
	if !p.path.CurrINFMatchesCurrHF() {
		return errorDiscard("error", errMalformedPath)
	}
	return pForward
}

func determinePeer(pathMeta scion.MetaHdr, inf path.InfoField) (bool, error) {
	if !inf.Peer {
		return false, nil
	}

	if pathMeta.SegLen[0] == 0 {
		return false, errPeeringEmptySeg0
	}
	if pathMeta.SegLen[1] == 0 {
		return false, errPeeringEmptySeg1
	}
	if pathMeta.SegLen[2] != 0 {
		return false, errPeeringNonemptySeg2
	}

	// The peer hop fields are the last hop field on the first path
	// segment (at SegLen[0] - 1) and the first hop field of the second
	// path segment (at SegLen[0]). The below check applies only
	// because we already know this is a well-formed peering path.
	currHF := pathMeta.CurrHF
	segLen := pathMeta.SegLen[0]
	return currHF == segLen-1 || currHF == segLen, nil
}

func (p *scionPacketProcessor) determinePeer() disposition {
	peer, err := determinePeer(p.path.PathMeta, p.infoField)
	p.peering = peer
	if err != nil {
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) validateHopExpiry() disposition {
	expiration := time.Unix(int64(p.infoField.Timestamp), 0).
		Add(path.ExpTimeToDuration(p.hopField.ExpTime))
	expired := expiration.Before(time.Now())
	if !expired {
		return pForward
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodePathExpired,
		pointer: p.currentHopPointer(),
	}
	return pSlowPath
}

func (p *scionPacketProcessor) validateIngressID() disposition {
	hdrIngressID := p.hopField.ConsIngress
	errCode := slayers.SCMPCodeUnknownHopFieldIngress
	if !p.infoField.ConsDir {
		hdrIngressID = p.hopField.ConsEgress
		errCode = slayers.SCMPCodeUnknownHopFieldEgress
	}
	if p.ingressFromLink != 0 && p.ingressFromLink != hdrIngressID {
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    errCode,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) validateSrcDstIA() disposition {
	srcIsLocal := (p.scionLayer.SrcIA == p.d.localIA)
	dstIsLocal := (p.scionLayer.DstIA == p.d.localIA)
	if p.ingressFromLink == 0 {
		// Outbound
		// Only check SrcIA if first hop, for transit this already checked by ingress router.
		// Note: SCMP error messages triggered by the sibling router may use paths that
		// don't start with the first hop.
		if p.path.IsFirstHop() && !srcIsLocal {
			return p.respInvalidSrcIA()
		}
		if dstIsLocal {
			return p.respInvalidDstIA()
		}
	} else {
		// Inbound
		if srcIsLocal {
			return p.respInvalidSrcIA()
		}
		if p.path.IsLastHop() != dstIsLocal {
			return p.respInvalidDstIA()
		}
	}
	return pForward
}

// invalidSrcIA is a helper to return an SCMP error for an invalid SrcIA.
func (p *scionPacketProcessor) respInvalidSrcIA() disposition {
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeInvalidSourceAddress,
		pointer: uint16(slayers.CmnHdrLen + addr.IABytes),
	}
	return pSlowPath
}

// invalidDstIA is a helper to return an SCMP error for an invalid DstIA.
func (p *scionPacketProcessor) respInvalidDstIA() disposition {
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeInvalidDestinationAddress,
		pointer: uint16(slayers.CmnHdrLen),
	}
	return pSlowPath
}

// validateTransitUnderlaySrc prevents malicious end hosts in the local AS from bypassing the SrcIA
// checks by disguising packets as transit traffic: each sibling link ensures that the src address
// of a packet is that of their expected sibling router. But we must verify that the right sibling
// link was used in the first place.
func (p *scionPacketProcessor) validateTransitUnderlaySrc() disposition {
	if p.path.IsFirstHop() || p.ingressFromLink != 0 {
		// Locally originated traffic, or came in via an external link. Not our concern.
		return pForward
	}
	pktIngressID := p.ingressInterface()        // Where this was *supposed* to enter the AS
	ingressLink := p.d.interfaces[pktIngressID] // Our own link to *that* sibling router

	// Is that the link that the packet came through (e.g. not the internal link)? The
	// comparison should be cheap. Links are implemented by pointers.
	if ingressLink != p.pkt.Link {
		// Drop
		return errorDiscard("error", errInvalidSrcAddrForTransit)
	}
	return pForward
}

// Validates the egress interface referenced by the current hop. This is not called for
// packets to be delivered to the local AS, so pkt.egress is never 0.
// If pkt.Ingress is zero, the packet can be coming from either a local end-host or a
// sibling router. In either of these cases, it must be leaving via a locally owned external
// interface (i.e. it can't be going to a sibling router or to a local end-host). On the other
// hand, a packet coming directly from another AS can be going anywhere: local delivery,
// to another AS directly, or via a sibling router.
func (p *scionPacketProcessor) validateEgressID() disposition {
	egressID := p.pkt.egress
	egressLink := p.d.interfaces[egressID]

	// egress interface must be a known interface
	// egress is never the internal interface (already checked)
	// packet coming from internal interface, must go to an external interface
	// Note that, for now, ingress == 0 is also true for sibling interfaces. That might change.
	if egressLink == nil || (p.ingressFromLink == 0 && egressLink.Scope() == Sibling) {
		errCode := slayers.SCMPCodeUnknownHopFieldEgress
		if !p.infoField.ConsDir {
			errCode = slayers.SCMPCodeUnknownHopFieldIngress
		}
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    errCode,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}

	return pForward
}

func (p *scionPacketProcessor) updateNonConsDirIngressSegID() disposition {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// For packets destined to peer links this shouldn't be updated.
	if !p.infoField.ConsDir && p.ingressFromLink != 0 && !p.peering {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			return errorDiscard("error", err)
		}
	}
	return pForward
}

func (p *scionPacketProcessor) currentInfoPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*int(p.path.PathMeta.CurrINF))
}

func (p *scionPacketProcessor) currentHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*p.path.NumINF + path.HopLen*int(p.path.PathMeta.CurrHF))
}

func (p *scionPacketProcessor) verifyCurrentMAC() disposition {
	fullMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macInputBuffer[:path.MACBufferSize])
	if subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], fullMac[:path.MacLen]) == 0 {
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    slayers.SCMPCodeInvalidHopFieldMAC,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC does not need to recalculate it.
	p.cachedMac = fullMac

	return pForward
}

func (p *scionPacketProcessor) resolveInbound() disposition {
	// The internal link is by definition unbound; we need to update the destination.
	err := p.d.resolveLocalDst(p.pkt, p.scionLayer, p.lastLayer)

	switch err {
	case nil:
		return pForward
	case ErrNoSVCBackend:
		p.pkt.slowPathRequest = slowPathRequest{
			spType: slowPathType(slayers.SCMPTypeDestinationUnreachable),
			code:   slayers.SCMPCodeNoRoute,
		}
		return pSlowPath
	case errInvalidDstAddr, ErrUnsupportedV4MappedV6Address, ErrUnsupportedUnspecifiedAddress:
		p.pkt.slowPathRequest = slowPathRequest{
			spType: slowPathType(slayers.SCMPTypeParameterProblem),
			code:   slayers.SCMPCodeInvalidDestinationAddress,
		}
		return pSlowPath
	default:
		return errorDiscard("error", err)
	}
}

func (p *scionPacketProcessor) processEgress() disposition {
	// We are the egress router and if we go in construction direction we
	// need to update the SegID (unless we are effecting a peering hop).
	// When we're at a peering hop, the SegID for this hop and for the next
	// are one and the same, both hops chain to the same parent. So do not
	// update SegID.
	if p.infoField.ConsDir && !p.peering {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			// TODO parameter problem invalid path
			return errorDiscard("error", err)
		}
	}
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) doXover() disposition {
	p.effectiveXover = true
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	var err error
	if p.hopField, err = p.path.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	if p.infoField, err = p.path.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) ingressInterface() uint16 {
	info := p.infoField
	hop := p.hopField
	if !p.peering && p.path.IsFirstHopAfterXover() {
		var err error
		info, err = p.path.GetInfoField(int(p.path.PathMeta.CurrINF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
		hop, err = p.path.GetHopField(int(p.path.PathMeta.CurrHF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
	}
	if info.ConsDir {
		return hop.ConsIngress
	}
	return hop.ConsEgress
}

func (p *scionPacketProcessor) egressInterface() uint16 {
	if p.infoField.ConsDir {
		return p.hopField.ConsEgress
	}
	return p.hopField.ConsIngress
}

func (p *scionPacketProcessor) validateEgressUp() disposition {
	egressID := p.pkt.egress
	egressLink := p.d.interfaces[egressID]
	if !egressLink.IsUp() {
		if egressLink.Scope() != External {
			p.pkt.slowPathRequest = slowPathRequest{
				spType: slowPathType(slayers.SCMPTypeInternalConnectivityDown),
				code:   0,
			}
		} else {
			p.pkt.slowPathRequest = slowPathRequest{
				spType: slowPathType(slayers.SCMPTypeExternalInterfaceDown),
				code:   0,
			}
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) handleIngressRouterAlert() disposition {
	if p.ingressFromLink == 0 {
		return pForward
	}
	alert := p.ingressRouterAlertFlag()
	if !*alert {
		return pForward
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathRouterAlertIngress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) ingressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.EgressRouterAlert
	}
	return &p.hopField.IngressRouterAlert
}

func (p *scionPacketProcessor) handleEgressRouterAlert() disposition {
	alert := p.egressRouterAlertFlag()
	if !*alert {
		return pForward
	}
	if p.d.interfaces[p.pkt.egress].Scope() != External {
		// the egress router is not this one.
		return pForward
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathRouterAlertEgress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) egressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.IngressRouterAlert
	}
	return &p.hopField.EgressRouterAlert
}

func (p *slowPathPacketProcessor) handleSCMPTraceRouteRequest(ifID uint16) error {
	if p.lastLayer.NextLayerType() != slayers.LayerTypeSCMP {
		return nil
	}
	scionPld := p.lastLayer.LayerPayload()
	var scmpH slayers.SCMP
	if err := scmpH.DecodeFromBytes(scionPld, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	if scmpH.TypeCode != slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0) {
		return nil
	}
	var scmpP slayers.SCMPTraceroute
	if err := scmpP.DecodeFromBytes(scmpH.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	scmpP = slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         p.d.localIA,
		Interface:  uint64(ifID),
	}
	return p.packSCMP(slayers.SCMPTypeTracerouteReply, 0, &scmpP, false)
}

func (p *scionPacketProcessor) validatePktLen() disposition {
	if int(p.scionLayer.PayloadLen) == len(p.scionLayer.Payload) {
		return pForward
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeInvalidPacketSize,
		pointer: 0,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) validateSrcHost() disposition {
	// We pay for this check only on the first hop.
	if p.scionLayer.SrcIA != p.d.localIA {
		return pForward
	}
	src, err := p.scionLayer.SrcAddr()
	if err == nil && src.IP().Is4In6() {
		err = ErrUnsupportedV4MappedV6Address
	}
	if err == nil {
		return pForward
	}

	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathType(slayers.SCMPTypeParameterProblem),
		code:   slayers.SCMPCodeInvalidSourceAddress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) process() disposition {
	if disp := p.parsePath(); disp != pForward {
		return disp
	}
	if disp := p.determinePeer(); disp != pForward {
		return disp
	}
	if disp := p.validateHopExpiry(); disp != pForward {
		return disp
	}
	if disp := p.validateIngressID(); disp != pForward {
		return disp
	}
	if disp := p.validatePktLen(); disp != pForward {
		return disp
	}
	if disp := p.validateTransitUnderlaySrc(); disp != pForward {
		return disp
	}
	if disp := p.validateSrcDstIA(); disp != pForward {
		return disp
	}
	if disp := p.validateSrcHost(); disp != pForward {
		return disp
	}
	if disp := p.updateNonConsDirIngressSegID(); disp != pForward {
		return disp
	}
	if disp := p.verifyCurrentMAC(); disp != pForward {
		return disp
	}
	if disp := p.handleIngressRouterAlert(); disp != pForward {
		return disp
	}
	// Inbound: pkt destined to the local IA.
	if p.scionLayer.DstIA == p.d.localIA {
		disp := p.resolveInbound()
		if disp != pForward {
			return disp
		}
		p.pkt.trafficType = ttIn
		return pForward
	}

	// Outbound: pkt leaving the local IA. This Could be:
	// * Pure outbound: from this AS, in via internal, out via external.
	// * ASTransit in: from another AS, in via external, out via internal to other BR.
	// * ASTransit out: from another AS, in via internal from other BR, out via external.
	// * BRTransit: from another AS, in via external, out via external.
	if p.path.IsXover() && !p.peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if disp := p.doXover(); disp != pForward {
			return disp
		}
		// doXover() has changed the current segment and hop field.
		// We need to validate the new hop field.
		if disp := p.validateHopExpiry(); disp != pForward {
			return disp
		}
		// verify the new block
		if disp := p.verifyCurrentMAC(); disp != pForward {
			return disp
		}
	}

	// Assign egress interface to the packet early. ICMP responses, if we make any, will need this.
	// Even if the egress interface is not valid, it can be useful in SCMP reporting.
	egressID := p.egressInterface()
	p.pkt.egress = egressID
	if disp := p.validateEgressID(); disp != pForward {
		return disp
	}

	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if disp := p.handleEgressRouterAlert(); disp != pForward {
		return disp
	}
	if disp := p.validateEgressUp(); disp != pForward {
		return disp
	}
	if p.d.interfaces[egressID].Scope() == External {
		// Not ASTransit in
		if disp := p.processEgress(); disp != pForward {
			return disp
		}
		// Finish deciding the trafficType...
		var tt trafficType
		if p.scionLayer.SrcIA == p.d.localIA {
			// Pure outbound
			tt = ttOut
		} else if p.ingressFromLink == 0 {
			// ASTransit out
			tt = ttOutTransit
		} else {
			// Therefore it is BRTransit
			tt = ttBrTransit
		}
		p.pkt.trafficType = tt
		return pForward
	}

	// ASTransit in: pkt leaving this AS through another BR.
	// We already know the egressID is valid. The packet can go straight to forwarding.
	p.pkt.trafficType = ttInTransit
	return pForward
}

func newSlowPathProcessor(d *DataPlane) *slowPathPacketProcessor {
	p := &slowPathPacketProcessor{
		d:              d,
		macInputBuffer: make([]byte, spao.MACBufferSize),
		validAuthBuf:   make([]byte, 16),
	}
	p.scionLayer.RecyclePaths()
	return p
}

type slowPathPacketProcessor struct {
	d               *DataPlane
	pkt             *Packet
	ingressFromLink uint16 // This is the IfID associated with the ingress link, if any.
	scionLayer      slayers.SCION
	hbhLayer        slayers.HopByHopExtnSkipper
	e2eLayer        slayers.EndToEndExtnSkipper
	lastLayer       gopacket.DecodingLayer
	path            *scion.Raw

	// macInputBuffer avoid allocating memory during processing.
	macInputBuffer []byte

	// optAuth is a reusable Packet Authenticator Option
	optAuth slayers.PacketAuthOption
	// validAuthBuf is a reusable buffer for the authentication tag
	// to be used in the hasValidAuth() method.
	validAuthBuf []byte

	// drkeyProvider derives DRKey material for authenticating SCMP
	// messages. CION runs without DRKey — the drafts leave SCMP
	// authentication experimental — so the field is nil and SCMP messages
	// are sent unauthenticated; see needsAuth and hasValidAuth.
	drkeyProvider drkeyProvider
}

func (p *slowPathPacketProcessor) reset() {
	p.path = nil
	p.ingressFromLink = 0
	p.hbhLayer = slayers.HopByHopExtnSkipper{}
	p.e2eLayer = slayers.EndToEndExtnSkipper{}
}

func (p *slowPathPacketProcessor) processPacket(pkt *Packet) error {
	var err error
	p.reset()
	p.pkt = pkt
	p.ingressFromLink = pkt.Link.IfID()

	p.lastLayer, err = decodeLayers(pkt.RawPacket, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return err
	}
	pathType := p.scionLayer.PathType
	switch pathType {
	case scion.PathType:
		var ok bool
		p.path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return errMalformedPath
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return errMalformedPath
		}
		p.path = epicPath.ScionPath
		if p.path == nil {
			return errMalformedPath
		}
	default:
		// unsupported path type
		return fmt.Errorf("Path type not supported for slow-path: type: %s", pathType)
	}

	s := pkt.slowPathRequest
	switch s.spType {
	case slowPathRouterAlertIngress: // Traceroute
		return p.handleSCMPTraceRouteRequest(p.ingressFromLink)
	case slowPathRouterAlertEgress: // Traceroute
		return p.handleSCMPTraceRouteRequest(p.pkt.egress)
	default: // SCMP
		var layer gopacket.SerializableLayer
		scmpType := slayers.SCMPType(s.spType)
		switch scmpType {
		case slayers.SCMPTypeParameterProblem:
			layer = &slayers.SCMPParameterProblem{Pointer: s.pointer}
		case slayers.SCMPTypeDestinationUnreachable:
			layer = &slayers.SCMPDestinationUnreachable{}
		case slayers.SCMPTypeExternalInterfaceDown:
			layer = &slayers.SCMPExternalInterfaceDown{
				IA:   p.d.localIA,
				IfID: uint64(p.pkt.egress),
			}
		case slayers.SCMPTypeInternalConnectivityDown:
			layer = &slayers.SCMPInternalConnectivityDown{
				IA:      p.d.localIA,
				Ingress: uint64(p.ingressFromLink),
				Egress:  uint64(p.pkt.egress),
			}
		default:
			panic(fmt.Errorf("unsupported slow-path type: %d", scmpType))
		}
		return p.packSCMP(scmpType, s.code, layer, true)
	}
}

func (p *slowPathPacketProcessor) packSCMP(typ slayers.SCMPType, code slayers.SCMPCode, scmpP gopacket.SerializableLayer, isError bool) error {
	// check invoking packet was an SCMP error:
	if p.lastLayer.NextLayerType() == slayers.LayerTypeSCMP {
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(p.lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			return fmt.Errorf("decoding SCMP layer: %w", err)
		}
		if !scmpLayer.TypeCode.InfoMsg() {
			return fmt.Errorf("SCMP error for SCMP error pkt -> DROP")
		}
	}

	if err := p.prepareSCMP(typ, code, scmpP, isError); err != nil {
		return fmt.Errorf("cannot route, dropping pkt: %w", err)
	}

	// We're about to send a packet that has little to do with the one we received.
	// The original traffic type, if one had been set, no-longer applies.
	p.pkt.trafficType = ttOther

	// The packet does not need any addressing: the slowpath processor always sends the packet back
	// on the link that delivered it (p.pkt.link). In case the link is an unconnected one, it did
	// set p.pkt.RemoteAddr on the way in; so it's good to go.

	return nil
}

func (p *slowPathPacketProcessor) prepareSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	isError bool,
) error {
	// *copy* and reverse path -- the original path should not be modified as this writes directly
	// back to rawPkt (quote).
	var path *scion.Raw
	pathType := p.scionLayer.Path.Type()
	switch pathType {
	case scion.PathType:
		var ok bool
		path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return fmt.Errorf("unsupported path type: path type: %s", pathType)
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return fmt.Errorf("unsupported path type: path type: %s", pathType)
		}
		path = epicPath.ScionPath
	default:
		return fmt.Errorf("unsupported path type: path type: %s", pathType)

	}
	decPath, err := path.ToDecoded()
	if err != nil {
		return fmt.Errorf("decoding raw path: %w", err)
	}
	revPathTmp, err := decPath.Reverse()
	if err != nil {
		return fmt.Errorf("reversing path for SCMP: %w", err)
	}
	revPath := revPathTmp.(*scion.Decoded)

	peering, err := determinePeer(revPath.PathMeta, revPath.InfoFields[revPath.PathMeta.CurrINF])
	if err != nil {
		return fmt.Errorf("peering cannot be determined: %w", err)
	}

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() && !peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if err := revPath.IncPath(); err != nil {
			return fmt.Errorf("reverting cross over for SCMP: %w", err)
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	// This is an SCMP response to pkt, so the egress link will be the ingress link.
	if p.pkt.Link.Scope() == External {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir && !peering {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.Mac)
		}
		if err := revPath.IncPath(); err != nil {
			return fmt.Errorf("incrementing path for SCMP: %w", err)
		}
	}

	// create new SCION header for reply.
	var scionL slayers.SCION
	scionL.FlowID = p.scionLayer.FlowID
	scionL.TrafficClass = p.scionLayer.TrafficClass
	scionL.PathType = revPath.Type()
	scionL.Path = revPath
	scionL.DstIA = p.scionLayer.SrcIA
	scionL.SrcIA = p.d.localIA
	scionL.DstAddrType = p.scionLayer.SrcAddrType
	scionL.RawDstAddr = p.scionLayer.RawSrcAddr
	scionL.NextHdr = slayers.L4SCMP

	if err := scionL.SetSrcAddr(p.d.localHost); err != nil {
		return fmt.Errorf("setting src addr: %w", err)
	}
	typeCode := slayers.CreateSCMPTypeCode(typ, code)
	scmpH := slayers.SCMP{TypeCode: typeCode}
	scmpH.SetNetworkLayerForChecksum(&scionL)

	// SCMP errors and authenticated traceroute replies need DRKey material;
	// without a DRKey provider they are sent unauthenticated — the drafts
	// leave SCMP authentication experimental — rather than crashing the slow
	// path.
	needsAuth := p.drkeyProvider != nil && (isError ||
		(scmpH.TypeCode.Type() == slayers.SCMPTypeTracerouteReply &&
			p.hasValidAuth(time.Now())))

	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	var serBuf serializeProxy

	// First write the SCMP message only without the SCION header(s) to get a buffer that we can
	// feed to the MAC computation. If this is an error response, then it has to include a quote of
	// the packet at the end of the SCMP message.

	if isError {
		// There is headroom built into the packet buffer so we can wrap the whole packet into a new
		// one without copying it. We need to reclaim that headroom so we can prepend. We can figure
		// the current headroom, even if it was changed, by comparing the capacity of the slice with
		// our constant buffer size.
		quoteLen := len(p.pkt.RawPacket)
		headroom := len(p.pkt.buffer) - cap(p.pkt.RawPacket)
		hdrLen := slayers.CmnHdrLen + scionL.AddrHdrLen() + scionL.Path.Len() +
			slayers.ScmpHeaderSize(scmpH.TypeCode.Type())

		if needsAuth {
			hdrLen += e2eAuthHdrLen
		}
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if quoteLen > maxQuoteLen {
			quoteLen = maxQuoteLen
		}
		// Now that we know the length, we can serialize the SCMP headers and the quoted packet. If
		// we don't fit in the headroom we copy the quoted packet to the end. We are required to
		// leave space for a worst-case underlay header too. TODO(multi_underlay): since we know
		// that this goes back via the link it came from, we could be content with leaving just
		// enough headroom for this specific underlay.
		if hdrLen+p.d.underlayHeadroom > headroom {
			// Not enough headroom. Pack at end.
			quote := p.pkt.RawPacket[:quoteLen]
			serBuf = newSerializeProxy(p.pkt.RawPacket)
			err = gopacket.SerializeLayers(&serBuf, sopts, &scmpH, scmpP, gopacket.Payload(quote))
			if err != nil {
				return fmt.Errorf("serializing SCMP message: %w", err)
			}
		} else {
			// Serialize in front of the quoted packet. The quoted packet must be included in the
			// serialize buffer before we pack the SCMP header in from of it. AppendBytes will do
			// that; it exposes the underlying buffer but doesn't modify it.
			p.pkt.RawPacket = p.pkt.buffer[0:(quoteLen + headroom)]
			serBuf = newSerializeProxyStart(p.pkt.RawPacket, headroom)
			_, _ = serBuf.AppendBytes(quoteLen) // Implementation never fails.
			err = scmpP.SerializeTo(&serBuf, sopts)
			if err != nil {
				return fmt.Errorf("serializing SCMP message: %w", err)
			}
			err = scmpH.SerializeTo(&serBuf, sopts)
			if err != nil {
				return fmt.Errorf("serializing SCMP message: %w", err)
			}
		}
	} else {
		// We do not need to preserve the packet. Just pack our headers at the end of the buffer.
		// (this is what serializeProxy does by default).
		serBuf = newSerializeProxy(p.pkt.RawPacket)
		err = gopacket.SerializeLayers(&serBuf, sopts, &scmpH, scmpP)
		if err != nil {
			return fmt.Errorf("serializing SCMP message: %w", err)
		}
	}

	// serBuf now starts with the SCMP Headers and ends with the truncated quoted packet, if any.
	// This is what gets checksumed.
	if needsAuth {
		var e2e slayers.EndToEndExtn
		scionL.NextHdr = slayers.End2EndClass

		now := time.Now()
		dstA, err := scionL.DstAddr()
		if err != nil {
			return fmt.Errorf("parsing destination address: %w", err)
		}
		key, err := p.drkeyProvider.GetASHostKey(now, scionL.DstIA, dstA)
		if err != nil {
			return fmt.Errorf("retrieving DRKey: %w", err)
		}
		if err := p.resetSPAOMetadata(key, now); err != nil {
			return fmt.Errorf("resetting SPAO header: %w", err)
		}

		e2e.Options = []*slayers.EndToEndOption{p.optAuth.EndToEndOption}
		e2e.NextHdr = slayers.L4SCMP
		_, err = spao.ComputeAuthCMAC(
			spao.MACInput{
				Key:        key.Key[:],
				Header:     p.optAuth,
				ScionLayer: &scionL,
				PldType:    slayers.L4SCMP,
				Pld:        serBuf.Bytes(),
			},
			p.macInputBuffer,
			p.optAuth.Authenticator(),
		)
		if err != nil {
			return fmt.Errorf("computing CMAC: %w", err)
		}
		if err := e2e.SerializeTo(&serBuf, sopts); err != nil {
			return fmt.Errorf("serializing SCION E2E headers: %w", err)
		}
	} else {
		scionL.NextHdr = slayers.L4SCMP
	}

	// Our SCION header is ready. Prepend it.
	if err := scionL.SerializeTo(&serBuf, sopts); err != nil {
		return fmt.Errorf("serializing SCION header: %w", err)
	}

	// serBuf now has the exact slice that represents the packet.
	p.pkt.RawPacket = serBuf.Bytes()

	return nil
}

func (p *slowPathPacketProcessor) resetSPAOMetadata(key drkey.ASHostKey, now time.Time) error {
	// For creating SCMP responses we use sender side.
	dir := slayers.PacketAuthSenderSide
	drkeyType := slayers.PacketAuthASHost

	spi, err := slayers.MakePacketAuthSPIDRKey(uint16(drkey.SCMP), drkeyType, dir)
	if err != nil {
		return err
	}

	timestamp, err := spao.RelativeTimestamp(key.Epoch, now)
	if err != nil {
		return err
	}

	return p.optAuth.Reset(slayers.PacketAuthOptionParams{
		SPI:         spi,
		Algorithm:   slayers.PacketAuthCMAC,
		TimestampSN: timestamp,
		Auth:        zeroBuffer,
	})
}

func (p *slowPathPacketProcessor) hasValidAuth(t time.Time) bool {
	// Without a DRKey provider an authenticator can never be verified.
	if p.drkeyProvider == nil {
		return false
	}
	// Check if e2eLayer was parsed for this packet
	if !p.lastLayer.CanDecode().Contains(slayers.LayerTypeEndToEndExtn) {
		return false
	}
	// Parse incoming authField
	e2eLayer := &slayers.EndToEndExtn{}
	if err := e2eLayer.DecodeFromBytes(
		p.e2eLayer.Contents,
		gopacket.NilDecodeFeedback,
	); err != nil {
		return false
	}
	e2eOption, err := e2eLayer.FindOption(slayers.OptTypeAuthenticator)
	if err != nil {
		return false
	}
	authOption, err := slayers.ParsePacketAuthOption(e2eOption)
	if err != nil {
		return false
	}
	// Computing authField
	// the sender should have used the receiver side key, i.e., K_{localIA-remoteIA:remoteHost}
	// where remoteIA == p.scionLayer.SrcIA and remoteHost == srcAddr
	// (for the incoming packet).
	srcAddr, err := p.scionLayer.SrcAddr()
	if err != nil {
		return false
	}
	key, err := p.drkeyProvider.GetKeyWithinAcceptanceWindow(
		t,
		authOption.TimestampSN(),
		p.scionLayer.SrcIA,
		srcAddr,
	)
	if err != nil {
		return false
	}

	_, err = spao.ComputeAuthCMAC(
		spao.MACInput{
			Key:        key.Key[:],
			Header:     authOption,
			ScionLayer: &p.scionLayer,
			PldType:    slayers.L4SCMP,
			Pld:        p.lastLayer.LayerPayload(),
		},
		p.macInputBuffer,
		p.validAuthBuf,
	)
	if err != nil {
		return false
	}
	// compare incoming authField with computed authentication tag
	return subtle.ConstantTimeCompare(authOption.Authenticator(), p.validAuthBuf) != 0
}

// updateSCIONLayer rewrites the SCION header at the start of the given raw packet buffer; replacing
// it with the serialization of the given new SCION header. This works only if the new header is of
// the same size as the old one. This function has no knowledge of the actual size of the headers;
// it only ensures that the new one ends exactly where the old one did. It is possible to use this
// function to replace a header with a smaller one; but the RawPacket's slice must be fixed
// afterwards (and the preceding headers, if any).
func updateSCIONLayer(rawPkt []byte, s slayers.SCION) error {
	payloadOffset := len(rawPkt) - len(s.LayerPayload())

	// Prepends must go just before payload. (and any Append will wreck it)
	serBuf := newSerializeProxyStart(rawPkt, payloadOffset)
	return s.SerializeTo(&serBuf, gopacket.SerializeOptions{})
}

// decodeLayers implements roughly the functionality of
// gopacket.DecodingLayerParser, but customized to our use case with a "base"
// layer and additional, optional layers in the given order.
// Returns the last decoded layer.
func decodeLayers(data []byte, base gopacket.DecodingLayer,
	opts ...gopacket.DecodingLayer,
) (gopacket.DecodingLayer, error) {
	if err := base.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	last := base
	for _, opt := range opts {
		if opt.CanDecode().Contains(last.NextLayerType()) {
			data := last.LayerPayload()
			if err := opt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				return nil, err
			}
			last = opt
		}
	}
	return last, nil
}
