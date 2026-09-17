package controlplane

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
)

// bfdIA and bfdPeer name the two sides of a test session's link.
var (
	bfdIA   = addr.MustIAFrom(20, 0xfd00000000a1)
	bfdPeer = addr.MustIAFrom(20, 0xfd00000000a2)
)

// fakeWriter is the link's raw socket in miniature: the control packets a
// session transmits, counted and kept.
type fakeWriter struct {
	packets [][]byte
}

func (w *fakeWriter) WriteRaw(b []byte) error {
	pkt := make([]byte, len(b))
	copy(pkt, b)
	w.packets = append(w.packets, pkt)
	return nil
}

// newTestSession starts a session on the fake writer, at the production
// timers' cadence.
func newTestSession(t *testing.T) (*BFDSession, *fakeWriter) {
	t.Helper()
	w := &fakeWriter{}
	mac, err := initMac([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	s := newBFDSession(bfdIA, mac, BFDTransmissionInterval, BFDDetectMultiplier,
		7, bfdPeer,
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"))
	s.SetRawWriter(w)
	return s, w
}

// peerMessage builds the peer's control message as the data plane hands it
// to the session: the decoded layer processBFD delivers.
func peerMessage(
	state layers.BFDState,
	myDisc, yourDisc uint32,
) *layers.BFD {

	return &layers.BFD{
		Version:              bfdVersion,
		State:                state,
		DetectMultiplier:     layers.BFDDetectMultiplier(BFDDetectMultiplier),
		MyDiscriminator:      layers.BFDDiscriminator(myDisc),
		YourDiscriminator:    layers.BFDDiscriminator(yourDisc),
		DesiredMinTxInterval: layers.BFDTimeInterval(BFDTransmissionInterval.Microseconds()),
		RequiredMinRxInterval: layers.BFDTimeInterval(
			BFDTransmissionInterval.Microseconds()),
	}
}

// lastPacket returns the session's latest transmitted control packet.
func lastPacket(t *testing.T, w *fakeWriter) []byte {
	t.Helper()
	if len(w.packets) == 0 {
		t.Fatal("the session transmitted nothing")
	}
	return w.packets[len(w.packets)-1]
}

// decodeControl splits a transmitted packet the way the data plane's BFD
// branch does: the SCION layer, then the control header it carries.
func decodeControl(
	t *testing.T,
	raw []byte,
) (*slayers.SCION, *layers.BFD) {

	t.Helper()
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scnL := pkt.Layer(slayers.LayerTypeSCION)
	if scnL == nil {
		t.Fatal("no SCION layer")
	}
	scn := scnL.(*slayers.SCION)
	// The processor's own dispatch: the layer after the SCION header is a
	// BFD control message exactly when NextHdr says 203.
	if got := scn.NextLayerType(); got != layers.LayerTypeBFD {
		t.Fatalf("next layer = %v, want BFD (NextHdr 203)", got)
	}
	var bfd layers.BFD
	if err := bfd.DecodeFromBytes(scn.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("decoding BFD control message: %v", err)
	}
	return scn, &bfd
}

// TestBFDControlPacketFrame checks the frame: a transmitted control packet
// is the SCION-framed form the data plane's own BFD branch parses — NextHdr
// 203 over a one-hop path on the link's interface — carrying the session's
// state and timers.
func TestBFDControlPacketFrame(t *testing.T) {
	s, w := newTestSession(t)
	s.tick()

	scn, bfd := decodeControl(t, lastPacket(t, w))
	if scn.PathType != onehop.PathType {
		t.Errorf("path type = %v, want the one-hop path", scn.PathType)
	}
	ohp, ok := scn.Path.(*onehop.Path)
	if !ok {
		t.Fatalf("path = %T, want one-hop", scn.Path)
	}
	if ohp.FirstHop.ConsEgress != s.IfID() {
		t.Errorf("first hop egress = %d, want the link's interface %d",
			ohp.FirstHop.ConsEgress, s.IfID())
	}
	if scn.SrcIA != bfdIA || scn.DstIA != bfdPeer {
		t.Errorf("src/dst IA = %v/%v, want %v/%v", scn.SrcIA, scn.DstIA, bfdIA, bfdPeer)
	}
	if bfd.Version != bfdVersion {
		t.Errorf("version = %d, want %d", bfd.Version, bfdVersion)
	}
	if bfd.State != layers.BFDStateDown {
		t.Errorf("state = %v, want the initial Down", bfd.State)
	}
	if bfd.DetectMultiplier != layers.BFDDetectMultiplier(BFDDetectMultiplier) {
		t.Errorf("detect multiplier = %d, want %d", bfd.DetectMultiplier, BFDDetectMultiplier)
	}
	if bfd.MyDiscriminator == 0 {
		t.Error("my discriminator is zero")
	}
	if want := layers.BFDTimeInterval(BFDTransmissionInterval.Microseconds()); bfd.DesiredMinTxInterval != want {
		t.Errorf("desired min tx = %d, want %d", bfd.DesiredMinTxInterval, want)
	}
	if bfd.YourDiscriminator != 0 {
		t.Errorf("your discriminator = %d, want zero before the peer's first arrival",
			bfd.YourDiscriminator)
	}
}

// TestBFDSessionStateMachine checks the async subset: Down on the peer's
// Down from our own Down becomes Init, the peer's Init or Up brings Up, and
// the peer's Down from Up returns Down — the peer's discriminator learned
// from every arrival. Each step's state is read from the packet the next
// interval transmits.
func TestBFDSessionStateMachine(t *testing.T) {
	s, w := newTestSession(t)
	peerDisc := uint32(0x2a2a2a2a)

	receiveAndTick := func(state layers.BFDState) *layers.BFD {
		s.ReceiveMessage(peerMessage(state, peerDisc, s.myDisc))
		w.packets = nil
		s.tick()
		_, bfd := decodeControl(t, lastPacket(t, w))
		return bfd
	}

	bfd := receiveAndTick(layers.BFDStateDown)
	if bfd.State != layers.BFDStateInit {
		t.Errorf("state after the peer's Down = %v, want Init", bfd.State)
	}
	if bfd.YourDiscriminator != layers.BFDDiscriminator(peerDisc) {
		t.Errorf("your discriminator = %d, want the peer's %d",
			bfd.YourDiscriminator, peerDisc)
	}

	if bfd := receiveAndTick(layers.BFDStateInit); bfd.State != layers.BFDStateUp {
		t.Errorf("state after the peer's Init = %v, want Up", bfd.State)
	}

	bfd = receiveAndTick(layers.BFDStateDown)
	if bfd.State != layers.BFDStateDown {
		t.Errorf("state after the peer's Down = %v, want Down", bfd.State)
	}
	if bfd.Diagnostic != layers.BFDDiagnosticNeighborSignalDown {
		t.Errorf("diagnostic = %v, want Neighbor Signaled Session Down", bfd.Diagnostic)
	}
}

// TestBFDSessionRejectsForeignDiscriminator checks the demultiplexing: a
// message naming another session's discriminator is not ours and changes
// nothing.
func TestBFDSessionRejectsForeignDiscriminator(t *testing.T) {
	s, _ := newTestSession(t)
	s.ReceiveMessage(peerMessage(layers.BFDStateUp, 1, s.myDisc+1))
	if s.localStateOf() != layers.BFDStateDown {
		t.Error("a foreign discriminator advanced the session")
	}
	// A zero discriminator is the bootstrapping form: the peer has not
	// learned ours yet, and the message is ours.
	s.ReceiveMessage(peerMessage(layers.BFDStateUp, 1, 0))
	if s.localStateOf() != layers.BFDStateUp {
		t.Error("a bootstrapping message was refused")
	}
	if !s.IsUp() {
		t.Error("verdict = down after an arrival")
	}
}

// TestBFDVerdictDownAtSilence checks the verdict: up until the detect
// multiplier expires without an arrival, down the moment it does — and
// transmitting throughout, including while down, with the expiry named in
// the diagnostic. The silence is a fake-time sleep in the bubble, instant
// and exactly at the window's edge.
func TestBFDVerdictDownAtSilence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, w := newTestSession(t)
		if !s.IsUp() {
			t.Fatal("a fresh session's verdict is down; a node restarts with every link up")
		}
		s.tick()
		if !s.IsUp() {
			t.Fatal("the verdict went down before the silence window passed")
		}

		time.Sleep(time.Duration(BFDDetectMultiplier) * BFDTransmissionInterval)
		before := len(w.packets)
		s.tick()
		if s.IsUp() {
			t.Fatal("the verdict stayed up past the detect multiplier's silence")
		}
		if len(w.packets) != before+1 {
			t.Fatal("the session stopped transmitting while down; recovery is seen by the stream")
		}
		_, bfd := decodeControl(t, lastPacket(t, w))
		if bfd.State != layers.BFDStateDown ||
			bfd.Diagnostic != layers.BFDDiagnosticTimeExpired {
			t.Fatalf("state/diagnostic = %v/%v, want Down/Control Detection Time Expired",
				bfd.State, bfd.Diagnostic)
		}

		// The next answered arrival is the up edge, whatever the negotiated
		// state: the peer's packet arriving is the link carrying traffic.
		s.ReceiveMessage(peerMessage(layers.BFDStateDown, 1, 0))
		if !s.IsUp() {
			t.Fatal("the verdict stayed down after an arrival")
		}
	})
}

// TestBFDVerdictSettles checks the hysteresis by construction: an
// alternating arrive-and-silence stream — never three intervals of silence,
// never a quiet verdict flip — settles with the link up and crosses neither
// edge twice in a window. The stream's intervals are fake-time sleeps in
// the bubble.
func TestBFDVerdictSettles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _ := newTestSession(t)
		flips := 0
		last := s.IsUp()
		for i := range 12 {
			// Arrive, then two intervals of quiet: the silence never reaches
			// the detect multiplier, so the verdict never goes down.
			s.ReceiveMessage(peerMessage(layers.BFDStateUp, 1, 0))
			time.Sleep(2 * BFDTransmissionInterval)
			s.tick()
			time.Sleep(BFDTransmissionInterval)
			if got := s.IsUp(); got != last {
				flips++
				last = got
			}
			if i == 0 && !s.IsUp() {
				t.Fatal("the verdict dropped on sub-window silence")
			}
		}
		if flips != 0 {
			t.Fatalf("the verdict crossed an edge %d times on an arrive-and-silence stream", flips)
		}
	})
}

// TestBFDStop checks the departed link: a stopped session records no
// arrival and transmits nothing.
func TestBFDStop(t *testing.T) {
	s, w := newTestSession(t)
	s.stop()
	s.tick()
	s.ReceiveMessage(peerMessage(layers.BFDStateUp, 1, 0))
	if got := len(w.packets); got != 0 {
		t.Fatalf("a stopped session transmitted %d packets", got)
	}
	if !s.IsUp() {
		t.Error("a stopped session's verdict changed")
	}
}

// localStateOf reads the session's protocol state for the assertions.
func (s *BFDSession) localStateOf() layers.BFDState {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.localState
}

// TestBFDControlPacketRoundTripThroughWire checks the control header's
// serialization the other way: the bytes the session builds decode as the
// data plane decodes them, field for field.
func TestBFDControlPacketRoundTripThroughWire(t *testing.T) {
	s, w := newTestSession(t)
	s.ReceiveMessage(peerMessage(layers.BFDStateInit, 0x11223344, 0))
	s.tick()

	// The SCION header's length bookkeeping carries the whole control
	// message, so the frame re-parses from the wire bytes alone.
	_, bfd := decodeControl(t, lastPacket(t, w))
	if bfd.YourDiscriminator != layers.BFDDiscriminator(0x11223344) {
		t.Errorf("your discriminator = %x, want 11223344", bfd.YourDiscriminator)
	}
}
