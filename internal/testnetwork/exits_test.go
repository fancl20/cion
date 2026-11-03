package testnetwork

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/libs/bus"
)

// The exits suite rides the coordination topology: the core and the leaf,
// every node an exit in a host's netmap, and a tailnet host on the leaf.
// The lab's internet is a documentation range the host addresses through
// its exit, and each node's harness internet maps it onto that node's own
// loopback services, so the service that answers names the exit that
// carried the flow. The range stands in for loopback services the host
// cannot reach directly: the client's netstack drops any packet from the
// loopback range as martian, and the egress answers each flow from the
// destination the host addressed.

// The lab's internet: the addresses the host reaches through its exit.
var (
	// labEcho is the echo, TCP and UDP at one address.
	labEcho = netip.MustParseAddrPort("198.51.100.7:7")
	// labResolver is the resolver the founding core's --dns.resolvers
	// names, at the DNS port a netmap's resolver address implies.
	labResolver = netip.MustParseAddrPort("198.51.100.53:53")
)

// exitAttempt bounds one exchange through the host, so a poll retries an
// exchange the forming sessions lost instead of waiting on it.
const exitAttempt = 5 * time.Second

// labInternet is one node's share of the lab's internet: an echo and a
// resolver on the node's loopback host, each serving TCP and UDP at one
// port and answering in the node's name. The echo writes the name before
// it echoes a stream and prefixes it to each datagram, and the resolver
// answers every A query with the node's own answer.
type labInternet struct {
	name   string
	answer netip.Addr
	// echo and resolver are the services' loopback addresses.
	echo     netip.AddrPort
	resolver netip.AddrPort
}

// standInternet serves a node's share of the lab's internet on its loopback
// host until the test ends.
func standInternet(t *testing.T, host netip.Addr, name string, answer netip.Addr) *labInternet {
	t.Helper()
	l := &labInternet{name: name, answer: answer}
	echoStream, echoPackets := listenPair(t, host)
	l.echo = echoPackets.LocalAddr().(*net.UDPAddr).AddrPort()
	go serveStreams(echoStream, func(conn net.Conn) {
		if _, err := io.WriteString(conn, name+"\n"); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	})
	go servePackets(echoPackets, func(datagram []byte) []byte {
		return append([]byte(name+":"), datagram...)
	})
	resolverStream, resolverPackets := listenPair(t, host)
	l.resolver = resolverPackets.LocalAddr().(*net.UDPAddr).AddrPort()
	go serveStreams(resolverStream, func(conn net.Conn) { serveDNSStream(conn, answer) })
	go servePackets(resolverPackets, func(query []byte) []byte { return dnsAnswer(query, answer) })
	return l
}

// reach is the node's harness internet: each lab address maps onto the
// node's service, and every other destination stands.
func (l *labInternet) reach(dst netip.AddrPort) netip.AddrPort {
	switch dst {
	case labEcho:
		return l.echo
	case labResolver:
		return l.resolver
	}
	return dst
}

// listenPair binds a TCP listener and a UDP socket at one port of the host,
// closed when the test ends: the one service address a lab address maps
// onto, whichever transport a flow rides. The port is the pinned band's
// next free one, for the host's ephemeral range holds the node's fixed
// host-facing port.
func listenPair(t *testing.T, host netip.Addr) (net.Listener, *net.UDPConn) {
	t.Helper()
	for range pinnedPortSpan {
		at := netip.AddrPortFrom(host, pinnedPortBase+uint16(pinnedPortDraws.Add(1)%pinnedPortSpan))
		packets, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(at))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		stream, err := net.Listen("tcp4", at.String())
		if err != nil {
			_ = packets.Close()
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = stream.Close()
			_ = packets.Close()
		})
		return stream, packets
	}
	t.Fatalf("the pinned port band on %v is drawn dry", host)
	return nil, nil
}

// serveStreams hands each connection the listener accepts to serve, which
// the connection's close follows, until the listener closes.
func serveStreams(ln net.Listener, serve func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			serve(conn)
		}()
	}
}

// servePackets answers each datagram the socket reads with what answer
// makes of it, nil answering nothing, until the socket closes.
func servePackets(conn *net.UDPConn, answer func([]byte) []byte) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if out := answer(buf[:n]); out != nil {
			_, _ = conn.WriteToUDPAddrPort(out, from)
		}
	}
}

// serveDNSStream answers the queries a DNS connection carries, each framed
// by its two-byte length, until the connection ends or carries no query.
func serveDNSStream(conn net.Conn, answer netip.Addr) {
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		out := dnsAnswer(query, answer)
		if out == nil {
			return
		}
		framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(out)), uint16(len(out)))
		if _, err := conn.Write(append(framed, out...)); err != nil {
			return
		}
	}
}

// dnsAnswer answers a DNS query: an A question with the answer, any other
// with no record; nil for a message that is no query.
func dnsAnswer(query []byte, answer netip.Addr) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	resp := dnsmessage.Message{
		ID: h.ID, Response: true,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true,
		Questions: []dnsmessage.Question{q},
	}
	if q.Type == dnsmessage.TypeA {
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
			},
			Body: &dnsmessage.AResource{A: answer.As4()},
		}}
	}
	out, err := resp.Pack()
	if err != nil {
		panic(fmt.Sprintf("packing the resolver's answer: %v", err))
	}
	return out
}

// servingAddresses maps each node's ISD-AS to its serving address — the
// slice's first, the address the allocator never issues.
func servingAddresses(t *testing.T, a *Node) map[addr.IA]netip.Addr {
	t.Helper()
	directory, err := wireguardOf(a).Directory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	serving := make(map[addr.IA]netip.Addr, len(directory.Nodes))
	for _, entry := range directory.Nodes {
		serving[entry.IA] = entry.Overlay.Masked().Addr().Next()
	}
	return serving
}

// tailnetHolds reports whether the node's tailnet view holds the host: the
// node applied a directory naming it, its host device programmed with it.
func tailnetHolds(n *Node, host netip.Addr) bool {
	return slices.ContainsFunc(n.app.Bus().Tailnet().Latest().Hosts,
		func(h bus.TailnetHost) bool { return h.Addr == host })
}

// coordinationOf returns the core's booted coordination application, whose
// presence the labs read the way the console does.
func coordinationOf(n *Node) *coordination.App {
	return n.app.Application("coordination").(*coordination.App)
}

// fetchVia GETs the URL through the host's tailnet and returns the body of
// its 200 answer, the connection closing with the exchange.
func fetchVia(ctx context.Context, srv *tsnet.Server, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, exitAttempt)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Close = true
	resp, err := srv.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s = %s", url, resp.Status)
	}
	return body, nil
}

// echoStream exchanges the payload with the lab's echo over TCP through
// the host and returns the name the answering service wrote.
func echoStream(ctx context.Context, srv *tsnet.Server, payload string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, exitAttempt)
	defer cancel()
	conn, err := srv.Dial(ctx, "tcp", labEcho.String())
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	r := bufio.NewReader(conn)
	name, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading the answering service's name: %w", err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		return "", err
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(r, echo); err != nil {
		return "", fmt.Errorf("reading the echo: %w", err)
	}
	if string(echo) != payload {
		return "", fmt.Errorf("the echo returned %q, want %q", echo, payload)
	}
	return strings.TrimSuffix(name, "\n"), nil
}

// echoDatagram sends the payload to the lab's echo over UDP through the
// host and returns the name the answering service prefixed to its reply.
func echoDatagram(ctx context.Context, srv *tsnet.Server, payload string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, exitAttempt)
	defer cancel()
	conn, err := srv.Dial(ctx, "udp", labEcho.String())
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, payload); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("reading the reply: %w", err)
	}
	name, echo, ok := strings.Cut(string(buf[:n]), ":")
	if !ok || echo != payload {
		return "", fmt.Errorf("the reply %q echoes no %q", buf[:n], payload)
	}
	return name, nil
}

// resolveVia asks the host's own resolver for the name's A record and
// returns the answer beside the upstream resolvers the host asked.
func resolveVia(ctx context.Context, srv *tsnet.Server, name string) (netip.Addr, []string, error) {
	lc, err := srv.LocalClient()
	if err != nil {
		return netip.Addr{}, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, exitAttempt)
	defer cancel()
	res, resolvers, err := lc.QueryDNS(ctx, name, "A")
	if err != nil {
		return netip.Addr{}, nil, err
	}
	var upstreams []string
	for _, r := range resolvers {
		upstreams = append(upstreams, r.Addr)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(res); err != nil {
		return netip.Addr{}, upstreams, fmt.Errorf("parsing the answer: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, upstreams, fmt.Errorf("parsing the answer: %w", err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return netip.Addr{}, upstreams, fmt.Errorf("parsing the answer: %w", err)
	}
	for _, a := range answers {
		if body, ok := a.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(body.A), upstreams, nil
		}
	}
	return netip.Addr{}, upstreams, errors.New("the answer holds no A record")
}

// selectExit makes the node at the serving address the host's exit, named
// by address the way a client's user names one.
func selectExit(t *testing.T, srv *tsnet.Server, exit netip.Addr) {
	t.Helper()
	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	prefs := &ipn.MaskedPrefs{ExitNodeIPSet: true}
	if err := prefs.SetExitNodeIP(exit.String(), status); err != nil {
		t.Fatalf("naming %s the exit: %v", exit, err)
	}
	if _, err := lc.EditPrefs(t.Context(), prefs); err != nil {
		t.Fatalf("selecting %s as the exit: %v", exit, err)
	}
}

// exitsLab is what the suite's checks read: the core, whose presence names
// the host's exit, and the host with its node key.
type exitsLab struct {
	core    *Node
	host    *tsnet.Server
	hostKey wireguard.PublicKey
}

// assertExit checks the host's internet leaves through the selected exit:
// the TCP and UDP echoes come back from the exit's own services, and the
// host's query for any name is answered by the exit's resolver, the one
// the netmap names for every exit. The host's resolver races the query
// over UDP from the operating system's own sockets, outside the tunnel,
// against TCP through the dialer that follows the tunnel's routes, so the
// query reaches the exit over TCP. The core's presence then names the exit
// as the host's. Each wait covers the selection taking effect and the
// session with the exit forming.
func (l *exitsLab) assertExit(t *testing.T, exit *Node, via *labInternet) {
	t.Helper()
	ctx := t.Context()
	PollErr(t, "the TCP echo through "+via.name, func() error {
		name, err := echoStream(ctx, l.host, "a stream through "+via.name)
		if err == nil && name != via.name {
			err = fmt.Errorf("the TCP echo answered from %s, want %s", name, via.name)
		}
		return err
	})
	PollErr(t, "the UDP echo through "+via.name, func() error {
		name, err := echoDatagram(ctx, l.host, "a datagram through "+via.name)
		if err == nil && name != via.name {
			err = fmt.Errorf("the UDP echo answered from %s, want %s", name, via.name)
		}
		return err
	})
	PollErr(t, "the DNS query through "+via.name, func() error {
		answer, upstreams, err := resolveVia(ctx, l.host, "exit.example.")
		if err != nil {
			return err
		}
		if want := []string{labResolver.Addr().String()}; !slices.Equal(upstreams, want) {
			return fmt.Errorf("the host asked %v, want the exits' resolvers %v", upstreams, want)
		}
		if answer != via.answer {
			return fmt.Errorf("the query was answered %s, want %s's %s", answer, via.name, via.answer)
		}
		return nil
	})
	Poll(t, "the core's presence naming "+via.name+" the host's exit", func() bool {
		return coordinationOf(l.core).Presence()[l.hostKey].Exit == exit.app.IA()
	})
}

// assertServes checks the node's serving address reaches the node beside
// whatever exit the host selected: the host's own provider fetch, the
// address naming the node's peer before any route is consulted.
func (l *exitsLab) assertServes(t *testing.T, node *Node, at netip.Addr) {
	t.Helper()
	PollErr(t, fmt.Sprintf("the provider at %v's serving address", node.app.IA()), func() error {
		_, err := fetchVia(t.Context(), l.host, "http://"+at.String()+"/mihomo")
		return err
	})
}

// labProxy is the part of a provider's instance the suite checks.
type labProxy struct {
	Name       string `json:"name"`
	ControlURL string `json:"control-url"`
	ExitNode   string `json:"exit-node"`
}

// TestExitsRelayedByTheHostsNode is the exits proof on the coordination
// topology: a host on the leaf holds both nodes as exits in its netmap, and
// the founding core's --dns.resolvers names the lab's resolver for every
// exit. With no exit selected, the core's serving address answers through
// the leaf's relay, the leaf counting the relayed datagrams, and the
// provider the leaf serves through the tailnet lists both exits at their
// serving addresses. With the core selected by its serving address, the
// host's TCP and UDP flows and its DNS query leave through the core and the
// core's services answer them; with the leaf selected, the leaf's; and with
// the core selected again, the core's once more — the host's sessions with
// both nodes sharing the leaf's host port throughout, each node's serving
// address still reaching that node. After each selection the core's
// presence names the selected exit.
func TestExitsRelayedByTheHostsNode(t *testing.T) {
	t.Parallel()
	wpki := packageWebPKI
	place := placeCoordination(t)
	coreHost, leafHost := HostSlot(t), HostSlot(t)
	coreNet := standInternet(t, coreHost, "core", netip.MustParseAddr("192.0.2.1"))
	leafNet := standInternet(t, leafHost, "leaf", netip.MustParseAddr("192.0.2.2"))
	a := coordCore(t, wpki, coreHost, place, func(cfg *services.NodeConfig) {
		cfg.Resolvers = []string{labResolver.Addr().String()}
		cfg.Internet = coreNet.reach
	})
	b := coordLeaf(t, wpki, leafHost, a, place, func(cfg *services.NodeConfig) {
		cfg.Internet = leafNet.reach
	})
	t.Cleanup(func() {
		t.Logf("node A counters: %v", wireguardOf(a).Counters())
		t.Logf("node B counters: %v", wireguardOf(b).Counters())
	})

	// The mesh stands in both directions before the host joins, and the
	// registry holds both nodes' entries, each with its slice.
	Poll(t, "the leaf reaches the core", func() bool {
		return pingFrom(t.Context(), b, a.app.IA(), a.host)
	})
	Poll(t, "the core reaches the leaf", func() bool {
		return pingFrom(t.Context(), a, b.app.IA(), b.host)
	})
	Poll(t, "the core's registry holding both nodes' entries", func() bool {
		return holdsHostEndpoint(t, a, a.app.IA()) && holdsHostEndpoint(t, a, b.app.IA())
	})
	serving := servingAddresses(t, a)
	coreAddr, leafAddr := serving[a.app.IA()], serving[b.app.IA()]

	// One host, on the leaf its key names.
	l := &exitsLab{core: a}
	l.host = tailnetHost(t, "host-exits", place.controlURL, labKey(b.app.IA()))
	ips := hostUp(t, l.host)
	if len(ips) != 1 || !ips[0].Is4() || !TailnetRange.Contains(ips[0]) {
		t.Fatalf("the host's addresses = %v, want one of the tailnet range", ips)
	}
	if got := ownerOf(t, a, ips[0]); got != b.app.IA() {
		t.Fatalf("the host landed on %s, want the leaf its key names", got)
	}
	lc, err := l.host.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	copy(l.hostKey[:], status.Self.PublicKey.AppendTo(nil))
	// Every node serves every host: both host devices hold the host before
	// it speaks, for a device that does not drops the host's handshake.
	Poll(t, "both nodes' host devices holding the host", func() bool {
		return tailnetHolds(a, ips[0]) && tailnetHolds(b, ips[0])
	})

	// No exit selected: the core's serving address reaches the core, its
	// session riding the leaf's host port and the leaf's relay carrying it
	// on to the core.
	relayed := wireguardOf(b).Counters()["wireguard.relayed_datagrams_total"]
	l.assertServes(t, a, coreAddr)
	if got := wireguardOf(b).Counters()["wireguard.relayed_datagrams_total"]; got <= relayed {
		t.Errorf("the leaf's relayed datagrams = %d once the core answered, want above %d",
			got, relayed)
	}

	// The provider, fetched through the tailnet from the host's own node,
	// lists both exits at their serving addresses, every instance logging
	// in where the host itself did.
	want := []labProxy{
		{Name: a.app.IA().String(), ControlURL: place.controlURL, ExitNode: coreAddr.String()},
		{Name: b.app.IA().String(), ControlURL: place.controlURL, ExitNode: leafAddr.String()},
	}
	PollErr(t, "the leaf's provider listing both exits", func() error {
		body, err := fetchVia(t.Context(), l.host, "http://"+leafAddr.String()+"/mihomo")
		if err != nil {
			return err
		}
		var doc struct {
			Proxies []labProxy `json:"proxies"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("decoding the provider %s: %w", body, err)
		}
		if diff := cmp.Diff(want, doc.Proxies, cmpopts.SortSlices(func(x, y labProxy) bool {
			return x.Name < y.Name
		})); diff != "" {
			return fmt.Errorf("the provider's instances (-want +got):\n%s", diff)
		}
		return nil
	})

	// The core selected: the host's internet leaves through the core, its
	// session relayed by the leaf, while the leaf's serving address still
	// reaches the leaf.
	selectExit(t, l.host, coreAddr)
	l.assertExit(t, a, coreNet)
	l.assertServes(t, b, leafAddr)

	// The leaf selected: the host's internet leaves through its own node,
	// and the core's serving address still reaches the core. Both sessions
	// arrive from the leaf's host port, which the client keys to one peer
	// alone; the client finds each session by its receiver index.
	selectExit(t, l.host, leafAddr)
	l.assertExit(t, b, leafNet)
	l.assertServes(t, a, coreAddr)

	// The core selected again: the relayed session carries the host's
	// internet once more.
	selectExit(t, l.host, coreAddr)
	l.assertExit(t, a, coreNet)
	l.assertServes(t, b, leafAddr)
}
