package scion

import (
	"errors"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/dataplane"
)

// Echo is one SCMP echo message. The identifier is port-shaped: a request
// carries its sender's underlay port, so the data plane delivers the reply —
// which repeats the request's identifier — back to the requesting socket
// (pkg/dataplane/dataplain.go's getDstPortSCMP).
type Echo struct {
	// Reply reports an echo reply; false is an echo request.
	Reply bool
	// Identifier is the echo identifier the reply returns to.
	Identifier uint16
	// Seq is the echo sequence number.
	Seq uint16
	// Payload is the echo data block.
	Payload []byte
}

// WriteEchoRequestTo sends an SCMP echo request to the peer, stamping the
// connection's own port as the identifier so the reply is delivered back
// here. The peer address carries a path like any other write.
func (c *Conn) WriteEchoRequestTo(peer *Addr, seq uint16, payload []byte) error {
	return c.writeEchoTo(peer, slayers.SCMPTypeEchoRequest, c.LocalPort(), seq, payload)
}

// WriteEchoReplyTo sends an SCMP echo reply repeating the request's
// identifier and sequence, addressed to the request's arrival address — the
// reversed arrival path returns it by the road the request came by.
func (c *Conn) WriteEchoReplyTo(peer *Addr, id, seq uint16, payload []byte) error {
	return c.writeEchoTo(peer, slayers.SCMPTypeEchoReply, id, seq, payload)
}

func (c *Conn) writeEchoTo(
	peer *Addr,
	typ slayers.SCMPType,
	id, seq uint16,
	payload []byte,
) error {

	raw, err := c.writePacket(peer, slayers.L4SCMP, func(scn *slayers.SCION) ([]byte, error) {
		return serializeEcho(scn, typ, id, seq, payload)
	})
	if err != nil {
		return err
	}
	_, err = c.conn.WriteToUDP(raw, c.internal)
	return err
}

// serializeEcho wraps the payload in the SCION/SCMP/echo layers after the
// given header, computing the SCMP checksum over it.
func serializeEcho(
	scn *slayers.SCION,
	typ slayers.SCMPType,
	id, seq uint16,
	payload []byte,
) ([]byte, error) {

	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(typ, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	echo := &slayers.SCMPEcho{Identifier: id, SeqNumber: seq}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, scn, scmp, echo, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ReadEchoFrom reads the next SCMP echo message, returning it with the
// sender's address, whose path is the reversed arrival path. Packets that
// are not SCMP echo are dropped silently, as ReadFrom drops non-UDP ones —
// unless they are the interface-down signal the cache recognizes.
func (c *Conn) ReadEchoFrom() (Echo, *Addr, error) {
	buf := make([]byte, dataplane.BufferSize)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return Echo{}, nil, err
		}
		echo, from, err := parseEchoPacket(buf[:n])
		if err != nil {
			c.recordInterfaceDown(buf[:n])
			continue
		}
		return echo, from, nil
	}
}

// parseEchoPacket extracts the echo message and the sender's address from a
// received SCMP packet. Like the data plane, the parse does not verify the
// SCMP checksum: SCMP runs unauthenticated in CION, and the data plane
// computes checksums only on the messages it originates.
func parseEchoPacket(raw []byte) (Echo, *Addr, error) {
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scnL := pkt.Layer(slayers.LayerTypeSCION)
	if scnL == nil {
		return Echo{}, nil, errors.New("no SCION layer")
	}
	scn := scnL.(*slayers.SCION)
	scmpL := pkt.Layer(slayers.LayerTypeSCMP)
	if scmpL == nil {
		return Echo{}, nil, errors.New("no SCMP layer")
	}
	scmp := scmpL.(*slayers.SCMP)
	echoL := pkt.Layer(slayers.LayerTypeSCMPEcho)
	if echoL == nil {
		return Echo{}, nil, errors.New("no echo layer")
	}
	echo := echoL.(*slayers.SCMPEcho)
	from, err := peerAddr(scn)
	if err != nil {
		return Echo{}, nil, err
	}
	return Echo{
		Reply:      scmp.TypeCode.Type() == slayers.SCMPTypeEchoReply,
		Identifier: echo.Identifier,
		Seq:        echo.SeqNumber,
		Payload:    echo.LayerPayload(),
	}, from, nil
}

// PathExpiry returns the earliest expiration time of a path's hop fields:
// the send-side moment from which the routers start dropping it. A pinger
// re-resolves before then.
func PathExpiry(p *spath.Decoded) time.Time {
	earliest := time.Time{}
	hop := 0
	for i, info := range p.InfoFields {
		segLen := int(p.PathMeta.SegLen[i])
		for h := 0; h < segLen; h++ {
			expiry := util.SecsToTime(info.Timestamp).
				Add(path.ExpTimeToDuration(p.HopFields[hop+h].ExpTime))
			if earliest.IsZero() || expiry.Before(earliest) {
				earliest = expiry
			}
		}
		hop += segLen
	}
	return earliest
}
