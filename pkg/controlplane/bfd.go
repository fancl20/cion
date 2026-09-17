package controlplane

import (
	"crypto/rand"
	"encoding/binary"
	"hash"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"

	"github.com/fancl20/cion/pkg/dataplane"
)

// The link's liveness constants (ADR-0008's fifth point): every session
// shares them — a one-second transmission interval and a detect multiplier
// of three, the same detection latency the greeting timeout derived before
// BFD took the question.
const (
	// BFDTransmissionInterval is the interval every session transmits on.
	BFDTransmissionInterval = time.Second
	// BFDDetectMultiplier is the count of transmission intervals without an
	// arrival that marks the link down.
	BFDDetectMultiplier = 3
)

// bfdVersion is RFC 5880's version, the only one the drafts frame.
const bfdVersion = 1

// BFDSession is one link's liveness session: the drafts' async-mode subset
// of RFC 5880 — Down, Init, Up, advanced by the peer's arriving state and
// our own, no authentication, demand mode, or echo function — its control
// packets SCION-framed (NextHdr 203) on the link's one-hop path and sent on
// the link's own underlay socket, beneath the forwarding plane. The session
// doubles as the link's verdict: up until the detect multiplier expires
// without an arrival, up again on the next answered one, both edges the
// session's own timers damp — a lossy link settles into whichever state its
// evidence sustains rather than flapping. The verdict is volatile: a node
// restarts with every link up and re-derives within one silence window.
type BFDSession struct {
	ifID        uint16
	myDisc      uint32
	interval    time.Duration
	detectMult  uint8
	macFactory  func() hash.Hash
	now         func() time.Time
	transmitted atomic.Uint64

	// writer is the link's own socket, attached at construction and
	// re-attached by every generation that rebinds the link.
	writer dataplane.RawWriter

	mtx sync.Mutex
	// localState, diagnostic, remoteState, and yourDisc are the protocol
	// state the arrivals advance.
	localState  layers.BFDState
	diagnostic  layers.BFDDiagnostic
	remoteState layers.BFDState
	yourDisc    uint32
	// header describes this session's frames: the two ISD-ASes and hosts.
	localIA    addr.IA
	neighborIA addr.IA
	localHost  netip.Addr
	remoteHost netip.Addr
	// lastRX is the last arrival; the detect multiplier expires from it.
	lastRX  time.Time
	stopped bool

	up atomic.Bool
}

// newBFDSession starts a session on the link's interface: transmitting at
// once, its protocol state Down per RFC 5880, its verdict up by default
// until the first silence window says otherwise.
func newBFDSession(
	localIA addr.IA,
	macFactory func() hash.Hash,
	interval time.Duration,
	detectMult uint8,
	now func() time.Time,
	ifID uint16,
	neighbor addr.IA,
	localHost, remoteHost netip.Addr,
) *BFDSession {

	disc := make([]byte, 4)
	if _, err := rand.Read(disc); err != nil {
		panic("Error while generating BFD discriminator")
	}
	if now == nil {
		now = time.Now
	}
	s := &BFDSession{
		ifID:       ifID,
		myDisc:     binary.BigEndian.Uint32(disc) | 1,
		interval:   interval,
		detectMult: detectMult,
		macFactory: macFactory,
		now:        now,
		localState: layers.BFDStateDown,
		localIA:    localIA,
		neighborIA: neighbor,
		localHost:  localHost,
		remoteHost: remoteHost,
	}
	s.lastRX = s.now()
	s.up.Store(true)
	return s
}

// IfID returns the interface the session serves.
func (s *BFDSession) IfID() uint16 { return s.ifID }

// IsUp returns the session's verdict — the flag behind the data plane's
// egress check.
func (s *BFDSession) IsUp() bool { return s.up.Load() }

// Transmitted returns the count of control packets the session has sent —
// the stream keeps leaving on the link's own socket, down verdict included.
func (s *BFDSession) Transmitted() uint64 { return s.transmitted.Load() }

// SetRawWriter attaches the link's writer for prebuilt packets; every
// generation that rebinds the link calls it again, the session's state and
// timers untouched.
func (s *BFDSession) SetRawWriter(w dataplane.RawWriter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.writer = w
}

// update retargets the session's frames at the entry's current addresses —
// the store's entry, not the construction-time snapshot, is the truth.
func (s *BFDSession) update(neighbor addr.IA, localHost, remoteHost netip.Addr) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.neighborIA = neighbor
	s.localHost = localHost
	s.remoteHost = remoteHost
}

// stop ends the session: nothing further is transmitted and no arrival is
// recorded. The link left the serving set — retired or demoted — and its
// interface ID is held back from reuse.
func (s *BFDSession) stop() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.stopped = true
	s.writer = nil
}

// ReceiveMessage hands one received control message to the session — the
// data plane's BFD branch calls it for every arrival on the link. Any
// decodable control packet is the up edge: the peer's session transmitting
// is the link carrying traffic.
func (s *BFDSession) ReceiveMessage(msg *layers.BFD) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.stopped {
		return
	}
	if msg.Version != bfdVersion {
		return
	}
	if msg.YourDiscriminator != 0 && uint32(msg.YourDiscriminator) != s.myDisc {
		return
	}
	if msg.MyDiscriminator != 0 {
		s.yourDisc = uint32(msg.MyDiscriminator)
	}
	s.remoteState = msg.State
	s.advance(msg.State)
	s.lastRX = s.now()
	if !s.up.Swap(true) {
		slog.Info("Link up", "interface", s.ifID, "neighbor", s.neighborIA)
	}
}

// advance moves the local state one step of RFC 5880's async machine: Down
// on the peer's Down from Init or Up, Init on the peer's Down from our own
// Down, Up once the peer reports Init or Up toward us.
func (s *BFDSession) advance(remote layers.BFDState) {
	switch s.localState {
	case layers.BFDStateDown:
		switch remote {
		case layers.BFDStateDown:
			s.localState = layers.BFDStateInit
		case layers.BFDStateInit, layers.BFDStateUp:
			s.localState = layers.BFDStateUp
		}
		s.diagnostic = layers.BFDDiagnosticNone
	case layers.BFDStateInit:
		switch remote {
		case layers.BFDStateDown:
			s.localState = layers.BFDStateDown
		case layers.BFDStateInit, layers.BFDStateUp:
			s.localState = layers.BFDStateUp
		}
		s.diagnostic = layers.BFDDiagnosticNone
	case layers.BFDStateUp:
		if remote == layers.BFDStateDown {
			s.localState = layers.BFDStateDown
			s.diagnostic = layers.BFDDiagnosticNeighborSignalDown
		}
	}
}

// tick runs the session's interval: expire the verdict if the detect
// multiplier passed without an arrival, then transmit a control packet
// either way — the stream survives its own down verdict, which is how
// recovery is seen.
func (s *BFDSession) tick() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.stopped {
		return
	}
	now := s.now()
	if now.Sub(s.lastRX) >= time.Duration(s.detectMult)*s.interval {
		if s.localState != layers.BFDStateDown ||
			s.diagnostic != layers.BFDDiagnosticTimeExpired {

			s.localState = layers.BFDStateDown
			s.diagnostic = layers.BFDDiagnosticTimeExpired
			if s.up.Swap(false) {
				slog.Info("Link down", "interface", s.ifID, "neighbor", s.neighborIA,
					"why", "bfd silence")
			}
		}
	}
	if s.writer == nil {
		return
	}
	raw, err := s.controlPacket(now)
	if err != nil {
		slog.Error("Building BFD control packet", "interface", s.ifID, "err", err)
		return
	}
	if err := s.writer.WriteRaw(raw); err != nil {
		// A generation swap closes the writer for the milliseconds its
		// replacement takes to rebind; the next interval transmits again.
		slog.Debug("Sending BFD control packet", "interface", s.ifID, "err", err)
		return
	}
	s.transmitted.Add(1)
}

// controlPacket builds one SCION-framed control packet — the BFD control
// header after a SCION header with NextHdr 203 over a fresh one-hop path,
// exactly the frame the data plane's BFD branch parses on arrival. Must be
// called with the mutex held: the one-hop hop-field MAC uses the shared
// hasher.
func (s *BFDSession) controlPacket(now time.Time) ([]byte, error) {
	segID := make([]byte, 2)
	if _, err := rand.Read(segID); err != nil {
		return nil, err
	}
	info := path.InfoField{
		SegID:     binary.BigEndian.Uint16(segID),
		ConsDir:   true,
		Timestamp: util.TimeToSecs(now),
	}
	firstHop := path.HopField{ConsIngress: 0, ConsEgress: s.ifID, ExpTime: 63}
	firstHop.Mac = path.MAC(s.macFactory(), info, firstHop, nil)

	scn := &slayers.SCION{
		NextHdr:  slayers.L4BFD,
		PathType: onehop.PathType,
		Path:     &onehop.Path{Info: info, FirstHop: firstHop},
		SrcIA:    s.localIA,
		DstIA:    s.neighborIA,
	}
	if err := scn.SetSrcAddr(addr.HostIP(s.localHost)); err != nil {
		return nil, err
	}
	if err := scn.SetDstAddr(addr.HostIP(s.remoteHost)); err != nil {
		return nil, err
	}
	bfd := &layers.BFD{
		Version:              bfdVersion,
		Diagnostic:           s.diagnostic,
		State:                s.localState,
		DetectMultiplier:     layers.BFDDetectMultiplier(s.detectMult),
		MyDiscriminator:      layers.BFDDiscriminator(s.myDisc),
		YourDiscriminator:    layers.BFDDiscriminator(s.yourDisc),
		DesiredMinTxInterval: layers.BFDTimeInterval(s.interval.Microseconds()),
		RequiredMinRxInterval: layers.BFDTimeInterval(
			s.interval.Microseconds()),
	}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true}, scn, bfd)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// initMac validates the forwarding key the way the factory will use it.
func initMac(key []byte) (func() hash.Hash, error) {
	if _, err := scrypto.InitMac(key); err != nil {
		return nil, err
	}
	return func() hash.Hash {
		mac, _ := scrypto.InitMac(key)
		return mac
	}, nil
}
