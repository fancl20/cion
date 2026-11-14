package dataplane

// The ECN bits of the SCION common header: the low two bits of its traffic
// class, which are bits 5 and 4 of the header's second byte. No checksum
// covers them.
const (
	ecnMask = 0x30
	ecnECT1 = 0x10
	ecnECT0 = 0x20
	ecnCE   = 0x30
)

// markArrival sets CE on an ECN-capable packet that came in over an
// external link, once its path has validated, when the congestion policy
// marks it given the fill of that link's data egress queue. A packet that
// comes back over a link most often answers traffic that left by it — an
// echo reply always does — so that queue is the one the traffic it answers
// waits in. A link whose queue is empty asks the policy nothing.
func (p *scionPacketProcessor) markArrival() {
	policy := p.d.RunConfig.Congestion
	if policy == nil || p.ingressFromLink == 0 {
		return
	}
	raw := p.pkt.RawPacket
	if ecn := raw[1] & ecnMask; ecn != ecnECT0 && ecn != ecnECT1 {
		return
	}
	if fill := p.d.interfaces[p.ingressFromLink].EgressFill(); fill > 0 && policy.Mark(p.ingressFromLink, fill) {
		raw[1] |= ecnCE
	}
}
