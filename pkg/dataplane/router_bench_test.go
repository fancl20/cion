package dataplane

import (
	"hash"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

type mockHash struct {
	sum []byte
}

func (m *mockHash) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockHash) Sum(b []byte) []byte               { return append(b, m.sum...) }
func (m *mockHash) Reset()                            {}
func (m *mockHash) Size() int                         { return len(m.sum) }
func (m *mockHash) BlockSize() int                    { return 16 }

func BenchmarkRouter_Process(b *testing.B) {
	localIA := addr.MustParseIA("1-ff00:0:1")
	neighborRouterIP := netip.MustParseAddrPort("192.168.1.1:50000")
	now := uint32(time.Now().Unix())

	// Mock MAC that returns all 0s (length 6)
	mockMac := [6]byte{0, 0, 0, 0, 0, 0}

	router := &Router{
		LocalIA: localIA,
		ExternalNextHops: map[uint16]netip.AddrPort{
			2: neighborRouterIP,
		},
		MacFactory: func() hash.Hash {
			return &mockHash{sum: mockMac[:]}
		},
	}

	// Construct Packet
	scionLayer := &slayers.SCION{
		DstIA:       addr.MustParseIA("1-ff00:0:2"),
		PathType:    scion.PathType,
		DstAddrType: slayers.T4Ip,
	}
	scionLayer.SetDstAddr(addr.HostIP(netip.MustParseAddr("10.0.0.100")))

	decodedPath := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  0,
				SegLen:  [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []path.InfoField{
			{ConsDir: true, Timestamp: now},
		},
		HopFields: []path.HopField{
			{ConsIngress: 1, ConsEgress: 2, ExpTime: 63, Mac: mockMac},
			{ConsIngress: 0, ConsEgress: 0, ExpTime: 63},
		},
	}

	rawPath := make([]byte, decodedPath.Len())
	if err := decodedPath.SerializeTo(rawPath); err != nil {
		b.Fatalf("Failed to serialize path: %v", err)
	}
	scionLayer.Path = &scion.Raw{
		Base: decodedPath.Base,
		Raw:  rawPath,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := scionLayer.SerializeTo(buffer, opts); err != nil {
		b.Fatalf("Failed to serialize SCION layer: %v", err)
	}
	rawPacket := buffer.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Copy packet to simulate fresh receive
		// In reality, we modify in place, so reusing the same buffer
		// would cause the Path Index to increment until overflow.
		// So we must reset the packet or copy it.
		// Copying adds overhead, but it's necessary for correctness of the loop.
		// To minimize overhead, we only copy.

		pktCopy := make([]byte, len(rawPacket))
		copy(pktCopy, rawPacket)

		_, err := router.Process(pktCopy, 1)
		if err != nil {
			b.Fatalf("Process failed: %v", err)
		}
	}
}
