package dataplane

import (
	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/slayers"
)

// Processor handles SCION packet processing.
type Processor struct {
}

// ProcessPacket decodes a SCION packet.
func (p *Processor) ProcessPacket(data []byte) error {
	var scionLayer slayers.SCION
	var udpLayer slayers.UDP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION,
		&scionLayer,
		&udpLayer,
		&payload,
	)

	var decoded []gopacket.LayerType
	return parser.DecodeLayers(data, &decoded)
}
