package wireguard

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// relayDouble is the bridge's relay connection double: it records the sends
// and answers nothing, the receive loop's share of the connection unused
// where the test drives the feed itself.
type relayDouble struct {
	mtx   sync.Mutex
	sends []sentDatagram
}

// sentDatagram is one datagram the bridge sent over the relay.
type sentDatagram struct {
	dst key.NodePublic
	pkt []byte
}

func (d *relayDouble) Recv() (derp.ReceivedMessage, error) {
	// Nothing arrives on the double's leg; the test feeds datagrams
	// through the socket directly, as the receive loop would.
	time.Sleep(time.Hour)
	return nil, net.ErrClosed
}

func (d *relayDouble) Send(dst key.NodePublic, pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	d.mtx.Lock()
	defer d.mtx.Unlock()
	d.sends = append(d.sends, sentDatagram{dst: dst, pkt: cp})
	return nil
}

func (d *relayDouble) sent() []sentDatagram {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return append([]sentDatagram(nil), d.sends...)
}

// captureBind is a host client's bind: its sends land in a channel the test
// reads, and its receives are whatever the test injects — the leg the test
// pretends each datagram arrived on. The once-guarded close is the shared
// bind pattern of the application's own binds, race-free for the same
// reason: the channel is created once and only closed.
type captureBind struct {
	sent   chan []byte
	recv   chan datagram
	closed chan struct{}
	once   sync.Once
}

func (b *captureBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.once = sync.Once{}
	b.sent = make(chan []byte, 256)
	b.recv = make(chan datagram, 256)
	b.closed = make(chan struct{})
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *captureBind) Close() error {
	// The device closes its bind before the first open; the once keeps a
	// channelless close harmless and a real one final.
	b.once.Do(func() {
		if b.closed != nil {
			close(b.closed)
		}
	})
	return nil
}
func (b *captureBind) SetMark(uint32) error { return nil }
func (b *captureBind) BatchSize() int       { return bindBatchSize }

func (b *captureBind) ParseEndpoint(string) (conn.Endpoint, error) {
	// The endpoint is a placeholder: the client only sends once, to start
	// the exchange, and the test carries every datagram from there.
	return &hostEndpoint{addr: netip.MustParseAddrPort("127.0.0.1:9")}, nil
}

func (b *captureBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		cp := make([]byte, len(buf))
		copy(cp, buf)
		select {
		case b.sent <- cp:
		case <-b.closed:
			return net.ErrClosed
		}
	}
	return nil
}

func (b *captureBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case dg := <-b.recv:
		copy(packets[0], dg.data)
		sizes[0] = len(dg.data)
		eps[0] = dg.src
		return 1, nil
	case <-b.closed:
		return 0, net.ErrClosed
	}
}

// TestDERPBridgeRoamsByLastArrival checks the relay fallback's node side
// (ADR-0011): a DERP-sourced datagram reaches the host device with the
// sender's key as its endpoint, the reply to a DERP endpoint leaves over
// the relay, and a later UDP-sourced datagram roams the peer to the UDP
// leg — whichever leg's authenticated packet arrived last.
func TestDERPBridgeRoamsByLastArrival(t *testing.T) {
	cnt := &counters{}
	nodeKey, nodePub := newKeyPair(t)
	hostKey, hostPub := newKeyPair(t)
	hostAddr := netip.MustParseAddr("100.64.1.10")

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	socket := newHostSocket(udpConn, cnt)
	go socket.run()

	relay := &relayDouble{}
	bridge := &derpBridge{cfg: derpBridgeConfig{Cnt: cnt}, conn: relay}
	nodePipe := newPipe("host", OverlayMTU, cnt)
	nodeDev := device.NewDevice(nodePipe, newHostBind(socket, bridge), testLogger)
	ipc := strings.Join([]string{
		"private_key=" + hex.EncodeToString(nodeKey[:]),
		"listen_port=" + strconv.Itoa(int(socket.LocalPort())),
		"replace_peers=true",
		"public_key=" + hostPub.String(),
		"allowed_ip=" + netip.PrefixFrom(hostAddr, 32).String(),
	}, "\n")
	if err := nodeDev.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := nodeDev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nodeDev.Close)

	// The host's client, its sends captured and its receives injected.
	hostPipe := newPipe("client", OverlayMTU, cnt)
	bind := &captureBind{}
	hostDev := device.NewDevice(hostPipe, bind, testLogger)
	hostIPC := strings.Join([]string{
		"private_key=" + hex.EncodeToString(hostKey[:]),
		"public_key=" + nodePub.String(),
		// The endpoint is a placeholder the bind parses and forgets; the
		// test carries every datagram from there.
		"endpoint=127.0.0.1:9",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=1",
	}, "\n")
	if err := hostDev.IpcSet(hostIPC); err != nil {
		t.Fatal(err)
	}
	if err := hostDev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hostDev.Close)

	// pump carries one exchange: the client's next datagram to the node
	// over the given leg, the node's relay sends back to the client, and
	// reports whether a decrypted packet arrived on the node's pipe. The
	// fed counter remembers which relay sends have already returned.
	fed := 0
	pump := func(leg conn.Endpoint) (*takeResult, bool) {
		select {
		case pkt := <-bind.sent:
			socket.deliver(pkt, leg)
		case <-time.After(5 * time.Second):
			t.Fatal("the host client sent nothing")
		}
		nodeEndpoint := &hostEndpoint{
			addr: socket.conn.LocalAddr().(*net.UDPAddr).AddrPort()}
		deadline := time.Now().Add(2 * time.Second)
		for {
			for _, s := range relay.sent()[fed:] {
				bind.recv <- datagram{data: s.pkt, src: nodeEndpoint}
				fed++
			}
			select {
			case pkt := <-nodePipe.outbound:
				return &takeResult{pkt: pkt}, true
			default:
			}
			if time.Now().After(deadline) {
				return nil, false
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// The exchange rides the relay: the handshake initiation arrives on
	// the DERP leg, and the node's reply — to the DERP endpoint — leaves
	// over the relay.
	derpLeg := &hostEndpoint{derp: hostPub}
	pump(derpLeg)
	sent := relay.sent()
	if len(sent) == 0 {
		t.Fatal("the reply to a DERP endpoint never left over the relay")
	}
	for _, s := range sent {
		if s.dst != nodePublicOf(hostPub) {
			t.Errorf("a relay send addressed %v, want the host's key", s.dst)
		}
	}

	// Transport data over the relay decrypts on the device.
	hostPipe.inbound <- ipPacket(t, hostAddr, netip.MustParseAddr("100.64.9.9"), []byte("d"))
	var got *takeResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ = pump(derpLeg); got != nil {
			break
		}
	}
	if got == nil || string(got.pkt[header.IPv4MinimumSize:]) != "d" {
		t.Fatal("the relay-sourced datagram never reached the device decrypted")
	}

	// A UDP-sourced datagram roams the peer to the UDP leg: the node's
	// next send goes to the arrival address, and the relay hears nothing.
	udpLeg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpLeg.Close() })
	udpAddr := udpLeg.LocalAddr().(*net.UDPAddr).AddrPort()
	before := len(relay.sent())
	// The client's next datagram (a keepalive, its interval a second)
	// arrives on the UDP leg.
	udpLegEP := &hostEndpoint{addr: udpAddr}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pump(udpLegEP)
		// A packet the node owes the host — its /32 routes to the device —
		// leaves on the UDP leg, not the relay.
		select {
		case nodePipe.inbound <- ipPacket(t, netip.MustParseAddr("100.64.9.9"), hostAddr, []byte("r")):
		default:
		}
		buf := make([]byte, 64<<10)
		_ = udpLeg.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, _, err := udpLeg.ReadFromUDP(buf); err == nil && n > 0 {
			// The node spoke on the UDP leg: the roam held.
			if relaySent := len(relay.sent()); relaySent != before {
				t.Fatalf("the relay carried %d sends after the roam, want none",
					relaySent-before)
			}
			return
		}
	}
	t.Fatal("the node never spoke on the UDP leg after the roam")
}

// takeResult carries one decrypted packet out of the pump.
type takeResult struct {
	pkt []byte
}
