package dataplane

import (
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
)

func TestProcessor_ProcessPacket_ValidUDP(t *testing.T) {
	// 1. Construct SCION Header
	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0,
		FlowID:       123,
		NextHdr:      slayers.L4UDP,
		PathType:     empty.PathType,
		DstAddrType:  slayers.T4Ip,
		SrcAddrType:  slayers.T4Ip,
		DstIA:        addr.MustParseIA("1-ff00:0:111"),
		SrcIA:        addr.MustParseIA("1-ff00:0:110"),
		Path:         &empty.Path{},
	}
	// Set addresses using addr.HostIP
	err := scionL.SetDstAddr(addr.HostIP(netip.MustParseAddr("10.0.0.2")))
	if err != nil {
		t.Fatalf("SetDstAddr: %v", err)
	}
	err = scionL.SetSrcAddr(addr.HostIP(netip.MustParseAddr("10.0.0.1")))
	if err != nil {
		t.Fatalf("SetSrcAddr: %v", err)
	}

	// 2. Construct UDP Header
	udpL := &slayers.UDP{
		SrcPort: 1234,
		DstPort: 5678,
	}
	udpL.SetNetworkLayerForChecksum(scionL)

	// 3. Payload
	payload := gopacket.Payload([]byte("hello world"))

	// 4. Serialize
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buffer, opts, scionL, udpL, payload)
	if err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}

	// 5. Process
	p := &Processor{}
	err = p.ProcessPacket(buffer.Bytes())
	if err != nil {
		t.Errorf("ProcessPacket failed: %v", err)
	}
}
