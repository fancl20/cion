package responder

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// TestResponderReleasesOnCancel checks the responder's stop: once its
// context ends, Run returns nil with its socket closed and released, and
// the address binds again at once. The socket binds on the package's own
// loopback host, where only a wildcard bind can take the released port.
func TestResponderReleasesOnCancel(t *testing.T) {
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           responderIA,
		Bind:         "127.0.0.133:0",
		InternalAddr: "127.0.0.133:9",
		MACKey:       make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := conn.LocalAddr().(*scion.Addr).Addr
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- New(conn, func(uint16, time.Time) {}).Run(ctx) }()
	cancel()
	if err := <-returned; err != nil {
		t.Fatalf("Run = %v, want nil once its context ended", err)
	}
	rebound, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bound))
	if err != nil {
		t.Fatalf("the responder's address did not bind again: %v", err)
	}
	_ = rebound.Close()
}

// The two ends of the requests the responder answers.
var (
	responderIA = addr.MustIAFrom(1, 0xff0000000110)
	neighborIA  = addr.MustIAFrom(1, 0xff0000000111)
)

// echoRequest builds a neighbor's echo request to the responder's host over
// the path, as the data plane delivers it.
func echoRequest(t *testing.T, pathType path.Type, p path.Path) []byte {
	t.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4SCMP,
		PathType: pathType,
		Path:     p,
		SrcIA:    neighborIA,
		DstIA:    responderIA,
	}
	if err := scn.SetSrcAddr(addr.HostIP(netip.MustParseAddr("127.0.0.134"))); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(addr.HostIP(netip.MustParseAddr("127.0.0.133"))); err != nil {
		t.Fatal(err)
	}
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, scn, scmp, &slayers.SCMPEcho{Identifier: 40441, SeqNumber: 1}); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// requests records the echo requests a responder hands on.
type requests struct {
	mu   sync.Mutex
	took []request
}

// request is one echo request handed on: its link and arrival.
type request struct {
	ifID uint16
	at   time.Time
}

func (r *requests) take(ifID uint16, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.took = append(r.took, request{ifID: ifID, at: at})
}

func (r *requests) taken() []request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.took)
}

// TestResponderHandsOnLinkRequests checks the requests the responder hands
// on: one that crossed one link to the node, over a one-hop path whose second
// hop names the link it came in on, with that link and its arrival; a probe
// through the node over a full path not at all. Each request's reply, which
// the conn sends to its internal address, marks its handling.
func TestResponderHandsOnLinkRequests(t *testing.T) {
	internal, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.133:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = internal.Close() }()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           responderIA,
		Bind:         "127.0.0.133:0",
		InternalAddr: internal.LocalAddr().String(),
		MACKey:       make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	var handed requests
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- New(conn, handed.take).Run(ctx) }()
	defer func() {
		cancel()
		if err := <-returned; err != nil {
			t.Errorf("Run = %v, want nil once its context ended", err)
		}
	}()
	sender, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(conn.LocalAddr().(*scion.Addr).Addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	answered := func(what string, request []byte) {
		t.Helper()
		if _, err := sender.Write(request); err != nil {
			t.Fatal(err)
		}
		if err := internal.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := internal.Read(make([]byte, 2048)); err != nil {
			t.Fatalf("no reply to %s: %v", what, err)
		}
	}

	const ifID = 5
	info := path.InfoField{ConsDir: true, SegID: 0x222, Timestamp: util.TimeToSecs(time.Now())}
	answered("a probe over a full path", echoRequest(t, spath.PathType, &spath.Decoded{
		PathMeta:   spath.MetaHdr{CurrHF: 1, SegLen: [3]uint8{2, 0, 0}},
		NumINF:     1,
		NumHops:    2,
		InfoFields: []path.InfoField{info},
		HopFields:  []path.HopField{{ConsEgress: 9, ExpTime: 63}, {ConsIngress: ifID, ExpTime: 63}},
	}))
	if got := handed.taken(); len(got) != 0 {
		t.Errorf("a probe over a full path was handed on: %+v", got)
	}

	before := time.Now()
	answered("a request over a link", echoRequest(t, onehop.PathType, &onehop.Path{
		Info:      info,
		FirstHop:  path.HopField{ConsEgress: 9, ExpTime: 63},
		SecondHop: path.HopField{ConsIngress: ifID, ExpTime: 63},
	}))
	got := handed.taken()
	if len(got) != 1 || got[0].ifID != ifID || got[0].at.Before(before) || got[0].at.After(time.Now()) {
		t.Errorf("requests handed on = %+v, want the one over link %d at its arrival", got, ifID)
	}
}
