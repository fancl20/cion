package dataplane

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// freeUDPAddr returns a loopback UDP address with a port picked by the
// kernel, so that concurrent test runs do not collide on fixed ports.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

// node bundles one CION node of the two-node test topology.
type node struct {
	d        *DataPlane
	provider *UDPProvider
	ia       addr.IA
	internal string
}

// startTwoNodes brings up two directly connected CION nodes:
//
//	AS 1-ff00:0:1 (A)  if1 127.0.0.1:31151  if1 127.0.0.1:31152  (B) AS 1-ff00:0:2
//
// Both routers use the same forwarding key, as if the key distribution via
// the control plane had already happened.
func startTwoNodes(t *testing.T) (a, b *node) {
	t.Helper()
	key := []byte("0123456789abcdef") // 16 bytes: a valid CMAC key length

	newNode := func(ia addr.IA, internal, extLocal, extRemote string) *node {
		t.Helper()
		metrics, err := NewMetrics()
		if err != nil {
			t.Fatal(err)
		}
		provider := NewUDPProvider(64, 0, 0)
		il, err := provider.NewInternalLink(
			internal, 64, metrics.NewInterfaceMetrics(0, ia, 0),
		)
		if err != nil {
			t.Fatal(err)
		}
		el, err := provider.NewExternalLink(
			64, nil, extLocal, extRemote, 1, metrics.NewInterfaceMetrics(1, ia, 0),
		)
		if err != nil {
			t.Fatal(err)
		}
		local := addr.HostIP(netip.MustParseAddr("127.0.0.1"))
		d, err := NewDataPlane(ia, local, key, provider, []Link{il, el})
		if err != nil {
			t.Fatal(err)
		}
		d.RunConfig = RunConfig{
			NumProcessors:         2,
			NumSlowPathProcessors: 1,
			BatchSize:             64,
		}
		return &node{d: d, provider: provider, ia: ia, internal: internal}
	}

	ctx, cancel := context.WithCancel(context.Background())
	intA, intB := freeUDPAddr(t), freeUDPAddr(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a = newNode(addr.MustIAFrom(1, 0xff0000000001), intA, extA, extB)
	b = newNode(addr.MustIAFrom(1, 0xff0000000002), intB, extB, extA)

	go func() { _ = a.d.Serve(ctx) }()
	go func() { _ = b.d.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		a.provider.Stop()
		b.provider.Stop()
	})
	return a, b
}

// directPath returns a decoded two-hop path across the direct link between the
// two nodes, for traffic traveling in construction direction: an egress hop
// owned by the source AS (interface 1) and an ingress hop owned by the
// destination AS (interface 1). Both routers verify hop MACs with the same
// key; the second hop's MAC is chained over the SegID updated by the first.
func directPath(t *testing.T, key []byte, segID uint16) *scion.Decoded {
	t.Helper()
	now := util.TimeToSecs(time.Now())
	info := path.InfoField{SegID: segID, ConsDir: true, Timestamp: now}

	egressHop := path.HopField{ConsIngress: 0, ConsEgress: 1, ExpTime: 63}
	egressHop.Mac = computeMAC(t, key, info, egressHop)

	// The ingress router sees the SegID after the egress router's update.
	infoAfter := info
	infoAfter.UpdateSegID(egressHop.Mac)
	ingressHop := path.HopField{ConsIngress: 1, ConsEgress: 0, ExpTime: 63}
	ingressHop.Mac = computeMAC(t, key, infoAfter, ingressHop)

	p := &scion.Decoded{
		InfoFields: []path.InfoField{info},
		HopFields:  []path.HopField{egressHop, ingressHop},
	}
	p.NumINF = 1
	p.NumHops = 2
	p.PathMeta = scion.MetaHdr{SegLen: [3]uint8{2, 0, 0}}
	return p
}

func computeMAC(t *testing.T, key []byte, info path.InfoField, hf path.HopField) [path.MacLen]byte {
	t.Helper()
	mac, err := scrypto.InitMac(key)
	if err != nil {
		t.Fatal(err)
	}
	return path.MAC(mac, info, hf, nil)
}

// scmpPacket returns a serialized SCION packet carrying an SCMP echo
// message with the given identifier.
func scmpPacket(
	t *testing.T,
	srcIA, dstIA addr.IA,
	p *scion.Decoded,
	echoType slayers.SCMPType,
	identifier uint16,
) []byte {

	t.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4SCMP,
		PathType: scion.PathType,
		Path:     p,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}
	if err := scn.SetSrcAddr(addr.HostIP(netip.MustParseAddr("127.0.0.1"))); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(addr.HostIP(netip.MustParseAddr("127.0.0.1"))); err != nil {
		t.Fatal(err)
	}
	scmpL := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(echoType, 0)}
	echoL := &slayers.SCMPEcho{Identifier: identifier, SeqNumber: 7}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true}, scn, scmpL, echoL)
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// TestTwoNodeSCMPEcho sends an SCMP echo request from a host in AS A through
// both routers to an echo server in AS B, which replies through the reverse
// path. This is the packet-forwarding test of the direct-link proposal.
func TestTwoNodeSCMPEcho(t *testing.T) {
	key := []byte("0123456789abcdef")
	a, b := startTwoNodes(t)

	// The echo server in AS B listens on the endhost port; SCMP echo requests
	// are delivered to the port carried in the echo identifier.
	appB, err := net.ListenUDP("udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: EndhostPort})
	if err != nil {
		t.Fatal(err)
	}
	defer appB.Close()

	// The client in AS A binds an ephemeral port and uses it as echo
	// identifier so that the reply can be delivered.
	appA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer appA.Close()
	ident := uint16(appA.LocalAddr().(*net.UDPAddr).Port)

	// Request: A -> B via the direct link.
	request := scmpPacket(t, a.ia, b.ia, directPath(t, key, 0x111),
		slayers.SCMPTypeEchoRequest, ident)
	if _, err := appA.WriteToUDP(request, mustUDPAddr(t, a.internal)); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, bufSize)
	appB.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	n, err := appB.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	req := parseSCIONPacket(t, got[:n])
	if req.scmp.TypeCode.Type() != slayers.SCMPTypeEchoRequest {
		t.Fatalf("SCMP type = %v, want echo request", req.scmp.TypeCode.Type())
	}
	if req.scion.SrcIA != a.ia || req.scion.DstIA != b.ia {
		t.Fatalf("src/dst IA = %v/%v, want %v/%v",
			req.scion.SrcIA, req.scion.DstIA, a.ia, b.ia)
	}

	// Reply: B -> A via the direct link, addressed to the identifier.
	reply := scmpPacket(t, b.ia, a.ia, directPath(t, key, 0x222),
		slayers.SCMPTypeEchoReply, ident)
	if _, err := appB.WriteToUDP(reply, mustUDPAddr(t, b.internal)); err != nil {
		t.Fatal(err)
	}

	appA.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	n, err = appA.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	rep := parseSCIONPacket(t, got[:n])
	if rep.scmp.TypeCode.Type() != slayers.SCMPTypeEchoReply {
		t.Fatalf("SCMP type = %v, want echo reply", rep.scmp.TypeCode.Type())
	}
	if rep.echo.Identifier != ident {
		t.Fatalf("echo identifier = %d, want %d", rep.echo.Identifier, ident)
	}
}

type parsedPacket struct {
	scion *slayers.SCION
	scmp  *slayers.SCMP
	echo  *slayers.SCMPEcho
}

func parseSCIONPacket(t *testing.T, data []byte) parsedPacket {
	t.Helper()
	pkt := gopacket.NewPacket(data, slayers.LayerTypeSCION, gopacket.DecodeOptions{})
	layer := pkt.Layer(slayers.LayerTypeSCION)
	if layer == nil {
		t.Fatal("no SCION layer")
	}
	out := parsedPacket{scion: layer.(*slayers.SCION)}
	if layer := pkt.Layer(slayers.LayerTypeSCMP); layer != nil {
		out.scmp = layer.(*slayers.SCMP)
	}
	if layer := pkt.Layer(slayers.LayerTypeSCMPEcho); layer != nil {
		out.echo = layer.(*slayers.SCMPEcho)
	}
	if out.scmp == nil || out.echo == nil {
		t.Fatal("missing SCMP echo layers")
	}
	return out
}

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := ResolveAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return net.UDPAddrFromAddrPort(a)
}
