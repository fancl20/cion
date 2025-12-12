package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

func TestRouter_Process(t *testing.T) {
	localIA := addr.MustParseIA("1-ff00:0:1")
	neighborRouterIP1 := netip.MustParseAddrPort("192.168.1.1:50000")
	neighborRouterIP2 := netip.MustParseAddrPort("192.168.1.2:50000")
	destIP := netip.MustParseAddr("10.0.0.100")
	now := uint32(time.Now().Unix())

	router := &Router{
		LocalIA: localIA,
		ExternalNextHops: map[uint16]netip.AddrPort{
			1: neighborRouterIP1,
			2: neighborRouterIP2,
		},
	}

	tests := []struct {
		name        string
		ingressID   uint16
		path        scion.Decoded
		dstIA       addr.IA
		dstAddr     netip.Addr
		wantNextHop NextHop
		wantErr     bool
		wantCurrHF  uint8
	}{
		{
			name:      "Ingress - Destination Local",
			ingressID: 1,
			dstIA:     localIA,
			dstAddr:   destIP,
			path: scion.Decoded{
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
					{ConsIngress: 1, ConsEgress: 0, ExpTime: 63}, // Current Hop: In=1, Out=0 (Local)
					{ConsIngress: 0, ConsEgress: 0, ExpTime: 63}, // Next Hop (Irrelevant here)
				},
			},
			wantNextHop: NextHop{Addr: netip.AddrPortFrom(destIP, 0)},
			wantCurrHF:  0, // No increment for Ingress -> Local
		},
		{
			name:      "Ingress - Transit (Forward External)",
			ingressID: 1,
			dstIA:     addr.MustParseIA("1-ff00:0:2"), // Transit
			path: scion.Decoded{
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
					{ConsIngress: 1, ConsEgress: 2, ExpTime: 63}, // In=1, Out=2 (External)
					{ConsIngress: 0, ConsEgress: 0, ExpTime: 63},
				},
			},
			wantNextHop: NextHop{Addr: neighborRouterIP2},
			wantCurrHF:  1, // Expect increment because we leave the AS
		},
		{
			name:      "Egress - Source (Forward External)",
			ingressID: 0, // From Local
			dstIA:     addr.MustParseIA("1-ff00:0:2"),
			path: scion.Decoded{
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
					{ConsIngress: 0, ConsEgress: 2, ExpTime: 63}, // Current Hop: In=0 (Source), Out=2 (External)
					{ConsIngress: 0, ConsEgress: 0, ExpTime: 63},
				},
			},
			wantNextHop: NextHop{Addr: neighborRouterIP2},
			wantCurrHF:  1, // Expect increment
		},
		{
			name:      "Error - Ingress Mismatch",
			ingressID: 3, // Wrong interface
			path: scion.Decoded{
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
					{ConsIngress: 1, ConsEgress: 0, ExpTime: 63},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct SCION Packet
			scionLayer := &slayers.SCION{
				DstIA:       tt.dstIA,
				PathType:    scion.PathType,
				DstAddrType: slayers.T4Ip, // Simplified
			}
			scionLayer.SetDstAddr(addr.HostIP(tt.dstAddr))

			// Encode Path
			rawPath := make([]byte, tt.path.Len())
			if err := tt.path.SerializeTo(rawPath); err != nil {
				t.Fatalf("Failed to serialize path: %v", err)
			}
			raw := &scion.Raw{
				Base: tt.path.Base,
				Raw:  rawPath,
			}
			scionLayer.Path = raw

			// Serialize to Bytes
			buffer := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			if err := scionLayer.SerializeTo(buffer, opts); err != nil {
				t.Fatalf("Failed to serialize SCION layer: %v", err)
			}
			packet := buffer.Bytes()

			// Run Process
			got, err := router.Process(packet, tt.ingressID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Router.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.wantNextHop, got, cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
					t.Errorf("Router.Process() mismatch (-want +got):\n%s", diff)
				}

				// Check Path Increment by re-parsing the MODIFIED packet
				var parsedScion slayers.SCION
				parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &parsedScion)
				parser.IgnoreUnsupported = true
				decodedLayers := []gopacket.LayerType{}
				parser.DecodeLayers(packet, &decodedLayers)

				parsedRawPath := parsedScion.Path.(*scion.Raw)

				var decoded scion.Decoded
				if err := decoded.DecodeFromBytes(parsedRawPath.Raw); err != nil {
					t.Errorf("Failed to decode path after process: %v", err)
				}
				if decoded.PathMeta.CurrHF != tt.wantCurrHF {
					t.Errorf("Path CurHF mismatch: want %d, got %d", tt.wantCurrHF, decoded.PathMeta.CurrHF)
				}
			}
		})
	}
}
