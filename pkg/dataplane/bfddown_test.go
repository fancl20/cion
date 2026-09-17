package dataplane

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
)

// downSession is a link's BFD session holding the down verdict: the flag
// the egress check reads, fed.
type downSession struct{}

func (downSession) ReceiveMessage(*layers.BFD) {}
func (downSession) IsUp() bool                 { return false }
func (downSession) SetRawWriter(RawWriter)     {}

// startDownNode brings up one node whose single external link's session
// holds the down verdict — the built-but-unreachable egress-down branch's
// first chance to run.
func startDownNode(t *testing.T) (n *node, key []byte) {
	t.Helper()
	key = []byte("0123456789abcdef")
	ia := addr.MustIAFrom(1, 0xff0000000001)
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := NewUDPProvider(64, 0, 0)
	internal, ext := freeUDPAddr(t), freeUDPAddr(t)
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	// The remote end is nothing at all: the link's own socket is connected
	// to an address no one binds, and the verdict is down regardless.
	el, err := provider.NewExternalLink(64, downSession{}, ext,
		freeUDPAddr(t), 1, metrics.NewInterfaceMetrics(1, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	local := addr.HostIP(netip.MustParseAddr("127.0.0.1"))
	d, err := NewDataPlane(ia, local, key, provider, []Link{il, el})
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = RunConfig{NumProcessors: 2, NumSlowPathProcessors: 1, BatchSize: 64}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		provider.Stop()
	})
	go func() { _ = d.Serve(ctx) }()
	return &node{d: d, provider: provider, ia: ia, internal: internal}, key
}

// TestEgressDownAnswersInterfaceDown checks the slow path the down verdict
// finally runs: a packet routed into the down link is dropped and answered
// toward its source with SCMP External Interface Down carrying the local
// ISD-AS, the egress interface, and the quoted packet.
func TestEgressDownAnswersInterfaceDown(t *testing.T) {
	a, key := startDownNode(t)
	bia := addr.MustIAFrom(1, 0xff0000000002)

	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ident := uint16(app.LocalAddr().(*net.UDPAddr).Port)

	request := scmpPacket(t, a.ia, bia, directPath(t, key, 0x111),
		slayers.SCMPTypeEchoRequest, ident)
	if _, err := app.WriteToUDP(request, mustUDPAddr(t, a.internal)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, bufSize)
	app.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	n, err := app.Read(buf)
	if err != nil {
		t.Fatalf("no answer from the down egress: %v", err)
	}
	pkt := gopacket.NewPacket(buf[:n], slayers.LayerTypeSCION, gopacket.NoCopy)
	scnL := pkt.Layer(slayers.LayerTypeSCION)
	if scnL == nil {
		t.Fatal("no SCION layer in the answer")
	}
	scn := scnL.(*slayers.SCION)
	if scn.SrcIA != a.ia || scn.DstIA != a.ia {
		t.Fatalf("answer src/dst IA = %v/%v, want the local %v both",
			scn.SrcIA, scn.DstIA, a.ia)
	}
	ifDown := pkt.Layer(slayers.LayerTypeSCMPExternalInterfaceDown)
	if ifDown == nil {
		t.Fatalf("SCMP layer = %v, want External Interface Down",
			pkt.Layer(slayers.LayerTypeSCMP))
	}
	msg := ifDown.(*slayers.SCMPExternalInterfaceDown)
	if msg.IA != a.ia {
		t.Errorf("signaled ISD-AS = %v, want the local %v", msg.IA, a.ia)
	}
	if msg.IfID != 1 {
		t.Errorf("signaled interface = %d, want the egress 1", msg.IfID)
	}
	// The quote names the offending packet: its destination is the far AS.
	quote := gopacket.NewPacket(msg.LayerPayload(), slayers.LayerTypeSCION,
		gopacket.NoCopy)
	quoted := quote.Layer(slayers.LayerTypeSCION)
	if quoted == nil {
		t.Fatal("the notification carries no quoted packet")
	}
	if got := quoted.(*slayers.SCION).DstIA; got != bia {
		t.Errorf("quoted destination = %v, want %v", got, bia)
	}
}

// TestEgressDownNotificationCap checks the per-interface rate cap: a burst
// of packets into the down link earns no more than the cap's notifications
// per second — exceeded ones dropped with the packet.
func TestEgressDownNotificationCap(t *testing.T) {
	a, key := startDownNode(t)
	bia := addr.MustIAFrom(1, 0xff0000000002)

	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ident := uint16(app.LocalAddr().(*net.UDPAddr).Port)

	// Start the burst early in a wall-clock second, so it cannot straddle
	// the cap's window boundary.
	for time.Now().Nanosecond() > 50_000_000 {
		time.Sleep(5 * time.Millisecond)
	}
	burst := 5 * notifyCapPerSecond
	for range burst {
		request := scmpPacket(t, a.ia, bia, directPath(t, key, 0x111),
			slayers.SCMPTypeEchoRequest, ident)
		if _, err := app.WriteToUDP(request, mustUDPAddr(t, a.internal)); err != nil {
			t.Fatal(err)
		}
	}

	notifications := 0
	buf := make([]byte, bufSize)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		app.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) //nolint:errcheck
		n, err := app.Read(buf)
		if err != nil {
			if notifications > 0 {
				break // the quiet after the capped burst
			}
			continue
		}
		pkt := gopacket.NewPacket(buf[:n], slayers.LayerTypeSCION, gopacket.NoCopy)
		if pkt.Layer(slayers.LayerTypeSCMPExternalInterfaceDown) != nil {
			notifications++
		}
		if notifications > notifyCapPerSecond {
			t.Fatalf("notifications = %d, exceeding the per-interface cap %d",
				notifications, notifyCapPerSecond)
		}
	}
	if notifications == 0 {
		t.Fatal("the burst earned no notification at all")
	}
	if notifications != notifyCapPerSecond {
		t.Errorf("notifications = %d, want the cap's %d", notifications, notifyCapPerSecond)
	}
}
