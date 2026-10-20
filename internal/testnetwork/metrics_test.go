package testnetwork

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// The discard episode's shape: the burst of unroutable packets pushed
// through B crosses the per-processor cap the discard lines answer to, and
// the cap's own figure is what the episode expects to read.
const (
	discardBurst    = 15
	discardCapLines = 10
)

// The discard reasons the episodes read by name, the data plane's own
// error strings.
const (
	errCannotRouteText     = "cannot route, dropping pkt"
	errMacVerificationText = "MAC verification failed"
)

// TestMetricsScrapedOverTheVerifiedChannel is the line lab's metrics
// episode: after pings flow, one node reads another's mount over the
// verified channel — input, output, and processed counters above zero,
// each node's traffic separated by its local_as label — and the packets
// the fast path refuses raise the dropping node's invalid counter with, at
// debug, the capped discard lines naming each reason, while a run at info
// raises the same counter in silence. The harness configures nothing per
// node: the process's provider serves every node's mount, and the scrape
// rides a member's chain. The lab is sequential, for the discard episodes
// flip the process's default logger.
func TestMetricsScrapedOverTheVerifiedChannel(t *testing.T) {
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA},
		links: [][2]addr.IA{{coreIA, nodeIA}, {nodeIA, lineCIA}},
	})
	a, b, c := nodes[coreIA], nodes[nodeIA], nodes[lineCIA]
	ctx := t.Context()

	// The join pipeline C's resolution waits on, budgeted at the restart
	// lab's patience like the ping episodes'.
	PollFor(t, RestartTimeout, "path from C to A", func() bool {
		_, err := c.app.Provider().Path(ctx, coreIA)
		return err == nil
	})

	// The baseline read precedes the traffic it measures; the first scrape
	// also proves a member's reader reaches the mount at all.
	var base map[string]map[addr.IA]int64
	Poll(t, "C reads B's mount", func() bool {
		base = servedSums(scrapeMetrics(t, c, b.app.IA()))
		return base != nil
	})

	report, err := ping.Run(ctx, ping.Config{
		Conn:     c.conn(t),
		Paths:    c.app.Provider(),
		Dst:      coreIA,
		DstHost:  a.host,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Wait:     5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Received != 3 {
		t.Fatalf("received %d of %d replies, want 3 of 3", report.Received, report.Sent)
	}

	// The pings' counters, each node's share named by its own local_as.
	var flowed map[string]map[addr.IA]int64
	Poll(t, "the pings reached the counters", func() bool {
		if flowed = servedSums(scrapeMetrics(t, c, b.app.IA())); flowed == nil {
			return false
		}
		return servedGrew(base, flowed, "dataplane_input_packets_total", a, b, c)
	})
	for _, name := range []string{
		"dataplane_input_packets_total", "dataplane_output_packets_total",
		"dataplane_processed_packets_total",
	} {
		if !servedGrew(base, flowed, name, a, b, c) {
			t.Errorf("%s did not grow on every node's local_as over the pings", name)
		}
	}

	// The discard episode. One crafted OHP serves both ends: leaving C —
	// submitted to its internal link — its zero first-hop MAC fails the
	// verification C's own key performs, the leaving branch the fast path
	// checks MACs in (a transit MAC failure answering by SCMP reply
	// instead); crossing B — written to its C-link socket, addressed
	// through it to the core — no one-hop path serves the destination and
	// the route is refused. Fifteen identical bytes hash to one processor,
	// so the cap holds B's lines at ten.
	bToC := entryOf(ctx, b.assemblyNode, c.app.IA())
	if bToC == nil {
		t.Fatal("B holds no link to C")
	}
	bcB, err := underlay.ResolveAddrPort(bToC.Local.String())
	if err != nil {
		t.Fatal(err)
	}
	cInternal, err := underlay.ResolveAddrPort(c.internal)
	if err != nil {
		t.Fatal(err)
	}
	crafted := ohpPacket(t, c.app.IA(), coreIA, c.host)

	var lines lockedLines
	prev := slog.Default()
	dropped := func(ia addr.IA) int64 {
		return servedSum(scrapeMetrics(t, c, b.app.IA()),
			"dataplane_dropped_packets_total", ia)
	}
	droppedBaseB, droppedBaseC := dropped(b.app.IA()), dropped(c.app.IA())
	slog.SetDefault(slog.New(slog.NewTextHandler(&lines,
		&slog.HandlerOptions{Level: slog.LevelDebug})))
	writeRaw(t, crafted, cInternal)
	for range discardBurst {
		writeRaw(t, crafted, bcB)
	}
	Poll(t, "B dropped the unroutable burst", func() bool {
		return dropped(b.app.IA()) >= droppedBaseB+discardBurst
	})
	Poll(t, "C dropped the failed verification", func() bool {
		return dropped(c.app.IA()) >= droppedBaseC+1
	})
	slog.SetDefault(prev)

	served := lines.String()
	if got := strings.Count(served, errCannotRouteText); got != discardCapLines {
		t.Errorf("B's discard lines naming the refusal = %d, want the cap's %d",
			got, discardCapLines)
	}
	if !strings.Contains(served, errMacVerificationText) {
		t.Error("no discard line names the failed MAC verification")
	}

	// The same refusal at info: the counter rises — the drop is the plane's,
	// not the logger's — and no line names it.
	lines.Reset()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lines,
		&slog.HandlerOptions{Level: slog.LevelInfo})))
	droppedBaseB = dropped(b.app.IA())
	for range discardBurst {
		writeRaw(t, crafted, bcB)
	}
	Poll(t, "B dropped the second burst", func() bool {
		return dropped(b.app.IA()) >= droppedBaseB+discardBurst
	})
	slog.SetDefault(prev)
	if served := lines.String(); strings.Contains(served, errCannotRouteText) ||
		strings.Contains(served, errMacVerificationText) {
		t.Errorf("an info-level run logged the discards: %q", served)
	}
}

// scrapeMetrics reads the peer's /metrics mount over the verified channel:
// the member's chain presented, the peer's verified, the request riding
// the SCION path the client's own provider resolves. An empty body
// reports a scrape still warming, for the episodes poll.
func scrapeMetrics(t *testing.T, from *staticNode, dst addr.IA) string {
	t.Helper()
	clt := from.app.PeerClient().VerifiedClient()
	peer := &scion.Addr{IA: dst, Service: addr.SvcCS}
	req, err := http.NewRequestWithContext(t.Context(), "GET",
		"https://"+scionrpc.PeerAuthority(peer)+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := clt.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	return string(body)
}

// servedSums sums the served counter lines per family name and local_as.
func servedSums(body string) map[string]map[addr.IA]int64 {
	if body == "" {
		return nil
	}
	sums := make(map[string]map[addr.IA]int64)
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, "dataplane_") {
			continue
		}
		// The family's name, then its label block and value.
		name, rest, ok := strings.Cut(line, "{")
		if !ok {
			continue
		}
		i := strings.Index(rest, `local_as="`)
		if i < 0 {
			continue
		}
		rest = rest[i+len(`local_as="`):]
		ia, err := addr.ParseIA(rest[:strings.IndexByte(rest, '"')])
		if err != nil {
			continue
		}
		_, value, ok := strings.Cut(line, "} ")
		if !ok {
			continue
		}
		sum, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		if sums[name] == nil {
			sums[name] = make(map[addr.IA]int64)
		}
		sums[name][ia] += sum
	}
	return sums
}

// servedSum reads one family's sum for one node out of a scrape.
func servedSum(body, name string, ia addr.IA) int64 {
	sums := servedSums(body)
	if sums == nil {
		return 0
	}
	return sums[name][ia]
}

// servedGrew reports whether the family's sum grew past the baseline for
// every named node.
func servedGrew(base, now map[string]map[addr.IA]int64, name string, nodes ...*staticNode) bool {
	for _, n := range nodes {
		if now[name][n.app.IA()] <= base[name][n.app.IA()] {
			return false
		}
	}
	return true
}

// ohpPacket crafts a one-hop-path SCION packet with a zero first-hop MAC:
// the leaving router's own verification refuses the tag, and a router the
// packet only crosses refuses the destination no one-hop path serves —
// both before any egress the hop names is read.
func ohpPacket(t *testing.T, src, dst addr.IA, host netip.Addr) []byte {
	t.Helper()
	scn := &slayers.SCION{
		NextHdr:  slayers.L4UDP,
		PathType: onehop.PathType,
		Path: &onehop.Path{
			Info:     path.InfoField{SegID: 0x111, ConsDir: true, Timestamp: util.TimeToSecs(time.Now())},
			FirstHop: path.HopField{ExpTime: 63},
		},
		SrcIA: src,
		DstIA: dst,
	}
	if err := scn.SetSrcAddr(addr.HostIP(host)); err != nil {
		t.Fatal(err)
	}
	if err := scn.SetDstAddr(addr.HostIP(host)); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, gopacket.Payload([]byte("cion metrics lab"))); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// writeRaw submits a crafted packet to one of the node's sockets as the
// underlay would deliver it.
func writeRaw(t *testing.T, pkt []byte, to netip.AddrPort) {
	t.Helper()
	conn, err := net.Dial("udp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
}

// lockedLines collects the lines the recording handler writes, locked for
// the node goroutines that log through it concurrently.
type lockedLines struct {
	mtx   sync.Mutex
	lines strings.Builder
}

func (l *lockedLines) Write(p []byte) (int, error) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	return l.lines.Write(p)
}

func (l *lockedLines) String() string {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	return l.lines.String()
}

func (l *lockedLines) Reset() {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.lines.Reset()
}
