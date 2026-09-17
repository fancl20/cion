package wireguard

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var testLogger = device.NewLogger(device.LogLevelSilent, "cion-wireguard-test")

// newKeyPair generates a WireGuard key pair in a throwaway directory.
func newKeyPair(t *testing.T) (PrivateKey, PublicKey) {
	t.Helper()
	key, err := LoadOrCreateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return key, key.PublicKey()
}

// newHostClient builds an in-process WireGuard client — a plain internet
// host: its own device on a real UDP socket, its peer the node's public key
// behind the shared port, its device interface a packet pipe the test owns.
func newHostClient(
	t *testing.T,
	nodeKey PublicKey,
	hostKey PrivateKey,
	nodeAddr netip.AddrPort,
) (*device.Device, *pipe) {

	t.Helper()
	pipe := newPipe("client", OverlayMTU, &counters{})
	dev := device.NewDevice(pipe, conn.NewDefaultBind(), testLogger)
	var ipc strings.Builder
	ipc.WriteString("private_key=" + hex.EncodeToString(hostKey[:]) + "\n")
	ipc.WriteString("public_key=" + nodeKey.String() + "\n")
	ipc.WriteString("endpoint=" + nodeAddr.String() + "\n")
	ipc.WriteString("allowed_ip=0.0.0.0/0\n")
	ipc.WriteString("persistent_keepalive_interval=1\n")
	if err := dev.IpcSet(ipc.String()); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dev.Close()
		_ = pipe.Close()
	})
	return dev, pipe
}

// TestSharedHostPortDemultiplexes checks the shared host-facing port's
// demultiplexing: every host device shares the node's key pair and receives
// every datagram, but only the device whose peer table holds the sender's
// public key completes the handshake — a key configured under another exit
// completes only on that exit's device, and a key no device holds is
// dropped.
func TestSharedHostPortDemultiplexes(t *testing.T) {
	cnt := &counters{}
	nodeKey, nodePub := newKeyPair(t)
	hostXKey, hostXPub := newKeyPair(t) // configured under exit X
	hostYKey, hostYPub := newKeyPair(t) // configured under exit Y
	rogueKey, _ := newKeyPair(t)        // configured nowhere

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	socket := newHostSocket(udpConn, cnt)
	go socket.run()
	nodeAddr := udpConn.LocalAddr().(*net.UDPAddr).AddrPort()

	// Two host devices behind the shared port, one per exit.
	newHostDevice := func(name string, peerKey PublicKey, peerAddr netip.Addr) *pipe {
		pipe := newPipe(name, OverlayMTU, cnt)
		dev := device.NewDevice(pipe, newHostBind(socket), testLogger)
		ipc := strings.Join([]string{
			"private_key=" + hex.EncodeToString(nodeKey[:]),
			"listen_port=" + strconv.Itoa(int(nodeAddr.Port())),
			"replace_peers=true",
			"public_key=" + peerKey.String(),
			"allowed_ip=" + netip.PrefixFrom(peerAddr, 32).String(),
		}, "\n")
		if err := dev.IpcSet(ipc); err != nil {
			t.Fatal(err)
		}
		if err := dev.Up(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			dev.Close()
			_ = pipe.Close()
		})
		return pipe
	}
	addrX := netip.MustParseAddr("10.64.1.10")
	addrY := netip.MustParseAddr("10.64.1.20")
	pipeX := newHostDevice("host-x", hostXPub, addrX)
	pipeY := newHostDevice("host-y", hostYPub, addrY)

	// Exit X's host exchanges through the shared port: its packet, decrypted,
	// arrives on X's device only.
	_, clientXPipe := newHostClient(t, nodePub, hostXKey, nodeAddr)
	clientXPipe.inbound <- ipPacket(t, addrX, netip.MustParseAddr("10.64.9.9"), []byte("x"))
	select {
	case pkt := <-pipeX.outbound:
		if got := pkt[header.IPv4MinimumSize:]; string(got) != "x" {
			t.Errorf("payload = %q, want %q", got, "x")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exit X's host traffic never reached X's device")
	}
	select {
	case pkt := <-pipeY.outbound:
		t.Fatalf("exit X's host traffic leaked to Y's device: %x", pkt)
	default:
	}

	// Exit Y's host completes only on Y's device.
	_, clientYPipe := newHostClient(t, nodePub, hostYKey, nodeAddr)
	clientYPipe.inbound <- ipPacket(t, addrY, netip.MustParseAddr("10.64.9.9"), []byte("y"))
	select {
	case pkt := <-pipeY.outbound:
		if got := pkt[header.IPv4MinimumSize:]; string(got) != "y" {
			t.Errorf("payload = %q, want %q", got, "y")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exit Y's host traffic never reached Y's device")
	}

	// A public key no device holds is dropped: the rogue client's handshake
	// completes nowhere and its traffic reaches no pipe.
	_, roguePipe := newHostClient(t, nodePub, rogueKey, nodeAddr)
	roguePipe.inbound <- ipPacket(t, addrX, netip.MustParseAddr("10.64.9.9"), []byte("r"))
	select {
	case pkt := <-pipeX.outbound:
		t.Fatalf("an unconfigured key's traffic reached X's device: %x", pkt)
	case pkt := <-pipeY.outbound:
		t.Fatalf("an unconfigured key's traffic reached Y's device: %x", pkt)
	case <-time.After(2 * time.Second):
	}
}
