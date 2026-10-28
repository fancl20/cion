package scion

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
)

// InterfaceDownHold is how long a recognized interface-down signal holds:
// the retention the drafts describe as current practice. A held signal only
// deprioritizes, so a short hold prices a forged signal at one skipped path.
const InterfaceDownHold = 10 * time.Second

// InterfaceDownSignal is one recognized SCMP External Interface Down
// message: the signaled ISD-AS and interface, the quoted packet's
// destination, whose path just failed, and the quoted echo request, whose
// sender waits for a reply that will not come.
type InterfaceDownSignal struct {
	// IA is the ISD-AS whose interface is signaled down.
	IA addr.IA
	// IfID is the signaled interface ID.
	IfID uint16
	// Dst is the quoted packet's destination ISD-AS; zero when the quote
	// does not decode.
	Dst addr.IA
	// Echo is the quoted packet's SCMP echo request; nil when the quote
	// carries none.
	Echo *Echo
}

// parseInterfaceDownPacket recognizes an SCMP External Interface Down
// error in a received packet: the signaled ISD-AS and interface from the
// message, the failed destination and any echo request from the quote.
// Anything else — every packet that is not a type-5 error — reports false.
func parseInterfaceDownPacket(raw []byte) (InterfaceDownSignal, bool) {
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scmpL := pkt.Layer(slayers.LayerTypeSCMP)
	if scmpL == nil {
		return InterfaceDownSignal{}, false
	}
	scmp := scmpL.(*slayers.SCMP)
	if scmp.TypeCode.Type() != slayers.SCMPTypeExternalInterfaceDown {
		return InterfaceDownSignal{}, false
	}
	var hdr slayers.SCMPExternalInterfaceDown
	if err := hdr.DecodeFromBytes(scmp.Payload, gopacket.NilDecodeFeedback); err != nil {
		return InterfaceDownSignal{}, false
	}
	sig := InterfaceDownSignal{IA: hdr.IA, IfID: uint16(hdr.IfID)}
	// The quote follows the message: its destination names whose path just
	// failed.
	quote := hdr.LayerPayload()
	if len(quote) >= slayers.CmnHdrLen+addr.IABytes {
		var scn slayers.SCION
		if err := scn.DecodeFromBytes(quote, gopacket.NilDecodeFeedback); err == nil {
			sig.Dst = scn.DstIA
			sig.Echo = quotedEcho(&scn)
		}
	}
	return sig, true
}

// quotedEcho decodes the SCMP echo request a quoted packet carries: its
// identifier and sequence, which name the requesting socket and its
// request. Nil for any other packet, and for a quote cut short before the
// sequence.
func quotedEcho(scn *slayers.SCION) *Echo {
	if scn.NextHdr != slayers.L4SCMP {
		return nil
	}
	var scmp slayers.SCMP
	if err := scmp.DecodeFromBytes(scn.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	if scmp.TypeCode.Type() != slayers.SCMPTypeEchoRequest {
		return nil
	}
	var echo slayers.SCMPEcho
	if err := echo.DecodeFromBytes(scmp.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	return &Echo{Identifier: echo.Identifier, Seq: echo.SeqNumber}
}
