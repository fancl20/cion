package liveness

import (
	"fmt"
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

// sessionIn returns a session brought to the given state by the peer's
// arrivals, as the handshake brings it.
func sessionIn(t *testing.T, state layers.BFDState) *BFDSession {
	t.Helper()
	s, _ := newTestSession(t)
	steps := map[layers.BFDState][]layers.BFDState{
		layers.BFDStateDown: nil,
		layers.BFDStateInit: {layers.BFDStateDown},
		layers.BFDStateUp:   {layers.BFDStateDown, layers.BFDStateInit},
	}[state]
	for _, remote := range steps {
		s.ReceiveMessage(peerMessage(remote, 0x2a2a2a2a, s.myDisc))
	}
	if got := s.localStateOf(); got != state {
		t.Fatalf("session brought to %v, want %v", got, state)
	}
	return s
}

// TestBFDSessionStateMachine checks RFC 5880's reception rules transition
// by transition (Section 6.8.6): the handshake's Down, Init, Up; an Up
// session's fall on the peer's Down; the peer's AdminDown downing any
// session not Down; and every other pair leaving the state as it is. The
// state each step reaches is the one the next interval transmits.
func TestBFDSessionStateMachine(t *testing.T) {
	down, initial, up, admin := layers.BFDStateDown, layers.BFDStateInit,
		layers.BFDStateUp, layers.BFDStateAdminDown
	none, signaled := layers.BFDDiagnosticNone, layers.BFDDiagnosticNeighborSignalDown
	for _, tc := range []struct {
		from, remote, want layers.BFDState
		diag               layers.BFDDiagnostic
	}{
		{down, down, initial, none},
		{down, initial, up, none},
		{down, up, down, none},
		{down, admin, down, none},
		{initial, down, initial, none},
		{initial, initial, up, none},
		{initial, up, up, none},
		{initial, admin, down, signaled},
		{up, down, down, signaled},
		{up, initial, up, none},
		{up, up, up, none},
		{up, admin, down, signaled},
	} {
		t.Run(fmt.Sprintf("%v on the peer's %v", tc.from, tc.remote), func(t *testing.T) {
			s := sessionIn(t, tc.from)
			w := &fakeWriter{}
			s.SetRawWriter(w)
			s.ReceiveMessage(peerMessage(tc.remote, 0x2a2a2a2a, s.myDisc))
			s.tick()
			_, bfd := decodeControl(t, lastPacket(t, w))
			if bfd.State != tc.want || bfd.Diagnostic != tc.diag {
				t.Errorf("state/diagnostic = %v/%v, want %v/%v",
					bfd.State, bfd.Diagnostic, tc.want, tc.diag)
			}
			if bfd.YourDiscriminator != layers.BFDDiscriminator(0x2a2a2a2a) {
				t.Errorf("your discriminator = %d, want the peer's", bfd.YourDiscriminator)
			}
		})
	}
}

// TestBFDSessionRejectsForeignDiscriminator checks the demultiplexing: a
// message naming another session's discriminator is not ours and changes
// nothing, while a zero discriminator — the peer has not learned ours yet —
// is ours.
func TestBFDSessionRejectsForeignDiscriminator(t *testing.T) {
	s, _ := newTestSession(t)
	s.ReceiveMessage(peerMessage(layers.BFDStateDown, 1, s.myDisc+1))
	if s.localStateOf() != layers.BFDStateDown {
		t.Error("a foreign discriminator advanced the session")
	}
	s.ReceiveMessage(peerMessage(layers.BFDStateDown, 1, 0))
	if s.localStateOf() != layers.BFDStateInit {
		t.Error("a bootstrapping message was refused")
	}
}

// TestBFDVerdictDownAtSilence checks the silence edge: an Up session silent
// for the detection time goes Down with the expiry named in the diagnostic,
// its verdict with it, and keeps transmitting; a lone arrival then raises
// nothing, and only the completed handshake raises the verdict again. The
// silence is a fake-time sleep in the bubble, instant and exactly at the
// window's edge.
func TestBFDVerdictDownAtSilence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := sessionIn(t, layers.BFDStateUp)
		w := &fakeWriter{}
		s.SetRawWriter(w)
		s.tick()
		if !s.IsUp() {
			t.Fatal("the verdict went down before the silence window passed")
		}

		time.Sleep(time.Duration(BFDDetectMultiplier) * BFDTransmissionInterval)
		before := len(w.packets)
		s.tick()
		if s.IsUp() {
			t.Fatal("the verdict stayed up past the detection time's silence")
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

		// A lone arrival proves one direction: the session moves to Init,
		// and the verdict stays down.
		s.ReceiveMessage(peerMessage(layers.BFDStateDown, 0x2a2a2a2a, 0))
		if s.IsUp() {
			t.Fatal("a lone arrival raised the verdict")
		}
		// The peer's Init completes the handshake.
		s.ReceiveMessage(peerMessage(layers.BFDStateInit, 0x2a2a2a2a, s.myDisc))
		if !s.IsUp() {
			t.Fatal("the completed handshake left the verdict down")
		}
	})
}

// TestBFDVerdictSettles checks the hysteresis by construction: on an Up
// session, an alternating arrive-and-silence stream — never a detection
// time of silence — keeps the verdict up and crosses no edge. The stream's
// intervals are fake-time sleeps in the bubble.
func TestBFDVerdictSettles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := sessionIn(t, layers.BFDStateUp)
		flips := 0
		last := s.IsUp()
		for range 12 {
			// Arrive, then two intervals of quiet: the silence never reaches
			// the detection time, so the verdict never goes down.
			s.ReceiveMessage(peerMessage(layers.BFDStateUp, 0x2a2a2a2a, s.myDisc))
			time.Sleep(2 * BFDTransmissionInterval)
			s.tick()
			time.Sleep(BFDTransmissionInterval)
			if got := s.IsUp(); got != last {
				flips++
				last = got
			}
		}
		if !last || flips != 0 {
			t.Fatalf("verdict %v after %d edges on an arrive-and-silence stream, want up and none",
				last, flips)
		}
	})
}

// TestBFDStartupGrace checks a new session's verdict: up for one detection
// time while the handshake completes, and down after it when no handshake
// did. The grace is a fake-time sleep in the bubble.
func TestBFDStartupGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _ := newTestSession(t)
		if !s.IsUp() {
			t.Fatal("a new session's verdict is down; a node restarts with every link up")
		}
		time.Sleep(time.Duration(BFDDetectMultiplier)*BFDTransmissionInterval - time.Nanosecond)
		s.tick()
		if !s.IsUp() {
			t.Fatal("the verdict fell inside the startup grace")
		}
		time.Sleep(time.Nanosecond)
		s.tick()
		if s.IsUp() {
			t.Fatal("the verdict stayed up past the grace with no handshake")
		}
	})
}

// pairWriter carries one session's transmissions to its peer session, each
// packet decoded as the data plane's BFD branch decodes it and held until
// the test delivers it, unless the direction drops.
type pairWriter struct {
	t       *testing.T
	queue   []*layers.BFD
	dropped bool
}

func (w *pairWriter) WriteRaw(b []byte) error {
	if w.dropped {
		return nil
	}
	_, bfd := decodeControl(w.t, b)
	w.queue = append(w.queue, bfd)
	return nil
}

// deliver hands the queued packets to the receiving session.
func (w *pairWriter) deliver(to *BFDSession) {
	for _, msg := range w.queue {
		to.ReceiveMessage(msg)
	}
	w.queue = nil
}

// TestBFDSessionPair checks the verdict on two sessions wired back to back:
// the startup grace ends with both down when every packet drops; a lone
// direction raises neither; the handshake raises both once it completes;
// dropping one direction downs both ends, the deaf end on silence and the
// other on the deaf end's signaled Down; and restoring it brings both up by
// the handshake. Each step is one interval of fake time in the bubble.
func TestBFDSessionPair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, _ := newTestSession(t)
		b, _ := newTestSession(t)
		ab, ba := &pairWriter{t: t}, &pairWriter{t: t}
		a.SetRawWriter(ab)
		b.SetRawWriter(ba)
		step := func() {
			time.Sleep(BFDTransmissionInterval)
			a.tick()
			b.tick()
			ab.deliver(b)
			ba.deliver(a)
		}
		verdicts := func(want bool, what string) {
			t.Helper()
			if a.IsUp() != want || b.IsUp() != want {
				t.Fatalf("%s: verdicts %v/%v, want both %v", what, a.IsUp(), b.IsUp(), want)
			}
		}

		ab.dropped, ba.dropped = true, true
		for range BFDDetectMultiplier {
			step()
		}
		verdicts(false, "the grace ended with every packet dropped")

		ba.dropped = false
		for range BFDDetectMultiplier {
			step()
		}
		verdicts(false, "one direction carrying")

		ab.dropped = false
		step()
		step()
		verdicts(true, "the handshake completed")

		ab.dropped = true
		for range BFDDetectMultiplier + 1 {
			step()
		}
		verdicts(false, "one direction dropped")

		ab.dropped = false
		for range 3 {
			step()
		}
		verdicts(true, "the direction restored")
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
