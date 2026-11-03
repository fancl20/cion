package coordination

import (
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// The netmap's constants: the tailnet range, the IDs the map gives its own
// node and the home node's peer, and the one DERP region the core serves.
const (
	// Tailnet is the overlay's host space, the range every slice is a
	// slice of.
	Tailnet = "100.64.0.0/10"

	// selfNodeID is the map's own node's ID, and homeNodeID the ID of the
	// peer of the node the host connects to.
	selfNodeID tailcfg.NodeID = 1
	homeNodeID tailcfg.NodeID = 2

	// derpRegionID is the one region the core's relay serves.
	derpRegionID = 1
	// derpRegionCode names the region in the map's grammar.
	derpRegionCode = "cion"
	// derpNodeName is the relay's node name within the region.
	derpNodeName = "cion-core"

	// mapResend is how often an open map stream re-reads the registry: the
	// bound on how long a peer change hides from a connected host.
	mapResend = 2 * time.Second
	// mapKeepAlive paces an idle stream's keepalive frames — well inside
	// the client protocol's two-minute watchdog.
	mapKeepAlive = 60 * time.Second
	// maxMapStreams bounds the open map streams the application serves:
	// past the bound the map answers one full map and closes the stream —
	// the protocol's own degradation, no error, the client's polling
	// carrying the rest. One stream per connected host; CION is
	// non-scalable by design.
	maxMapStreams = 128

	// maxMapBody bounds one map request.
	maxMapBody = 1 << 20
)

// servedCapabilityVersion is the one capability version the service serves and
// advertises — the vendored client protocol's own current version, the pin of
// the standing compatibility commitment: the vendor's and mihomo's client
// lines are verified against it, and a vendored upgrade that moves it moves
// this with it or fails the pin's test.
const servedCapabilityVersion = tailcfg.CurrentCapabilityVersion

// handleMap answers one netmap request. Each host's map names every node as
// a peer and an exit, each under its own WireGuard key — the host's own node
// holding the hosts' addresses, every other node its serving address alone
// — beside the host's own allocated address and the relay, and the record
// names the machine: the channel's authenticated machine is what the request
// owes beside the node key. No delta compression, no peer change machinery:
// a map holds one peer per node, CION is non-scalable by design, and a full
// map is the smallest correct answer. The first map goes out at once; a
// streaming request's body stays open, keepalives holding it and a re-read
// registry resending the map when what it names changed — and an open stream
// holds one of a bounded set, past which the map answers once and closes.
// Each answered request is the host's sighting — its arrival, its claims,
// the exit it reports, its open stream — kept in memory as its presence.
func (a *App) handleMap(w http.ResponseWriter, r *http.Request,
	machine key.MachinePublic) {

	arrived := time.Now()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxMapBody))
	if err != nil {
		http.Error(w, "reading the map request", http.StatusBadRequest)
		return
	}
	var req tailcfg.MapRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "malformed map request", http.StatusBadRequest)
		return
	}
	directory, err := a.cfg.Store.List(r.Context())
	if err != nil {
		http.Error(w, "the registry is unavailable", http.StatusInternalServerError)
		slog.Error("Coordination reading the registry", "err", err)
		return
	}
	var hostinfo tailcfg.HostinfoView
	if req.Hostinfo != nil {
		hostinfo = req.Hostinfo.View()
	}
	resp, err := a.netmap(r.Context(), req.NodeKey, machine, directory,
		req.DiscoKey, hostinfo, arrived)
	if err != nil {
		// A key the registry does not hold maps nothing — nor does a
		// machine the record does not name: the client retries, and the
		// refusal names the register it must complete.
		http.Error(w, "no registration for the key", http.StatusForbidden)
		return
	}
	// The request is the host's sighting: its arrival, its claims, the exit
	// it reports, and — while it streams — its open stream.
	nodeKey := nodeKeyOf(req.NodeKey)
	a.observe(nodeKey, hostinfo, directory)
	// An open stream holds one of a bounded set, taken before the first map
	// goes out: past the bound the map answers once, and the stream closes —
	// no error, the client's own polling carrying the rest.
	streaming := false
	if req.Stream {
		select {
		case a.mapStreams <- struct{}{}:
			streaming = true
			defer func() { <-a.mapStreams }()
			a.streamOpened(nodeKey)
			defer a.streamClosed(nodeKey)
		default:
		}
	}
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := writeMapFrame(w, resp); err != nil {
		return
	}
	if flusher != nil {
		flusher.Flush()
	}
	if !streaming {
		return
	}

	resend := a.cfg.MapResend
	if resend == 0 {
		resend = mapResend
	}
	reread := time.NewTicker(resend)
	keepAlive := time.NewTicker(mapKeepAlive)
	defer reread.Stop()
	defer keepAlive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			if err := writeMapFrame(w, &tailcfg.MapResponse{KeepAlive: true}); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		case <-reread.C:
			directory, err := a.cfg.Store.List(r.Context())
			if err != nil {
				slog.Warn("Coordination re-reading the registry", "err", err)
				continue
			}
			updated, err := a.netmap(r.Context(), req.NodeKey, machine, directory,
				req.DiscoKey, hostinfo, arrived)
			if err != nil {
				// The registration vanished beneath an open stream;
				// closing the stream is the honest answer.
				return
			}
			if netmapsEqual(updated, resp) {
				continue
			}
			resp = updated
			if err := writeMapFrame(w, resp); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// netmap builds one host's full map from the registry, for the machine the
// record names: the node key alone maps nothing, the channel's authenticated
// machine is what the request owes beside it, and a record from before the
// machine claim binds the first machine to present it, under the admission
// lock.
//
// The map names one peer per node holding a slice, each an exit under the
// node's own key. A client sends a destination to the peer whose addresses
// name it before it consults routes, so the home node — the node the host
// connects to — holds every host's address beside its own serving address,
// and every other node holds its serving address alone; every peer's allowed
// IPs add the default routes, which the client programs for its selected
// exit and no other. The addresses are single-IP Tailscale addresses rather
// than the covering /10, the form the client lines route unconditionally: a
// covering prefix is an advertised subnet route behind the client's own
// route-all preference, which no host of this network is asked to hold. The
// host reaches its own node alone, so every peer's endpoint is the home
// node's host-facing one, and the home node relays the sessions of every
// other node's key.
//
// No peer carries a disco key — each a wireguard-only peer with a static
// endpoint, the model the client lines already serve for third-party exits —
// and that is the served form, a fact of the code with no runtime switch
// anywhere. The client takes a wireguard-only exit at capability version 26
// or above to serve a DNS proxy of its own, which no node serves, and
// crashes on one below it that carries no hostinfo: every peer carries
// version 0, hostinfo naming its node, and the configured resolvers.
//
// The client requires a key never to move between node IDs within its map:
// the home node's peer holds homeNodeID, and every other node's ID derives
// from its ISD-AS. The peers sort by ID, and the request's arrival stamps
// every creation and sighting, so an unchanged registry rebuilds an equal
// map and an open stream resends nothing. The packet filter is a single rule
// admitting the member's traffic: membership is the tailnet's one policy,
// and no engine stands behind the rule to configure.
func (a *App) netmap(ctx context.Context, node key.NodePublic,
	machine key.MachinePublic, directory wireguard.Directory,
	reqDisco key.DiscoPublic, reqHostinfo tailcfg.HostinfoView,
	arrived time.Time) (*tailcfg.MapResponse, error) {

	var self *wireguard.HostEntry
	for i := range directory.Hosts {
		if directory.Hosts[i].PublicKey == nodeKeyOf(node) {
			self = &directory.Hosts[i]
			break
		}
	}
	if self == nil {
		return nil, errors.New("no registration for the key")
	}
	bound, err := a.bindOnMap(ctx, self, machine)
	if err != nil {
		return nil, fmt.Errorf("binding the record's machine: %w", err)
	}
	if !bound {
		return nil, errors.New("no registration for the key")
	}
	var home *wireguard.Entry
	for i := range directory.Nodes {
		if directory.Nodes[i].IA.Equal(self.IA) {
			home = &directory.Nodes[i]
			break
		}
	}
	if home == nil {
		return nil, fmt.Errorf("the owning node %s holds no directory entry", self.IA)
	}
	if !home.HostEndpoint.IsValid() {
		return nil, fmt.Errorf("the owning node %s published no host endpoint", self.IA)
	}
	var endpoints []netip.AddrPort
	if !a.cfg.RelayOnly {
		endpoints = []netip.AddrPort{home.HostEndpoint}
	}
	homePeer := a.peer(*home, homeNodeID, homeAddresses(directory, *home), endpoints, arrived)
	homePeer.HomeDERP = derpRegionID
	peers := make([]*tailcfg.Node, 0, len(directory.Nodes))
	peers = append(peers, homePeer)
	for _, entry := range directory.Nodes {
		if entry.IA.Equal(home.IA) || !entry.Overlay.IsValid() {
			continue
		}
		peers = append(peers, a.peer(entry, nodeID(entry.IA),
			[]netip.Prefix{servingAddress(entry)}, endpoints, arrived))
	}
	slices.SortFunc(peers, func(x, y *tailcfg.Node) int { return cmp.Compare(x.ID, y.ID) })
	address := netip.PrefixFrom(self.Addr, 32)
	return &tailcfg.MapResponse{
		Node: &tailcfg.Node{
			ID:         selfNodeID,
			User:       registerUserID,
			Key:        node,
			StableID:   stableID(self.PublicKey),
			Machine:    machine,
			Addresses:  []netip.Prefix{address},
			AllowedIPs: []netip.Prefix{address},
			// The client's own claims, echoed the way a control answers:
			// its disco key from the request, its hostinfo beside them.
			DiscoKey:          reqDisco,
			Hostinfo:          reqHostinfo,
			MachineAuthorized: true,
			Cap:               servedCapabilityVersion,
			Created:           arrived,
		},
		Peers:   peers,
		DERPMap: a.derpMap(),
		PacketFilter: []tailcfg.FilterRule{{
			SrcIPs: []string{Tailnet},
			DstPorts: []tailcfg.NetPortRange{{
				IP:    "*",
				Ports: tailcfg.PortRangeAny,
			}},
		}},
		Domain: a.cfg.Domain,
	}, nil
}

// peer builds one node's peer, an exit: the node's key and stable ID, a name
// of its ISD-AS with each colon a dash beneath the tailnet's domain, the
// addresses with the default routes beside them in its allowed IPs, the
// endpoints, no capability version, hostinfo naming the node, and the
// configured resolvers.
func (a *App) peer(entry wireguard.Entry, id tailcfg.NodeID, addrs []netip.Prefix,
	endpoints []netip.AddrPort, arrived time.Time) *tailcfg.Node {

	ia := entry.IA.String()
	online := true
	return &tailcfg.Node{
		ID:                   id,
		StableID:             stableID(entry.PublicKey),
		Name:                 strings.ReplaceAll(ia, ":", "-") + "." + a.cfg.Domain + ".",
		User:                 registerUserID,
		Key:                  nodePublicOf(entry.PublicKey),
		Addresses:            addrs,
		AllowedIPs:           slices.Concat(addrs, tsaddr.ExitRoutes()),
		Endpoints:            endpoints,
		Hostinfo:             (&tailcfg.Hostinfo{Hostname: ia}).View(),
		Created:              arrived,
		LastSeen:             &arrived,
		Online:               &online,
		MachineAuthorized:    true,
		IsWireGuardOnly:      true,
		ExitNodeDNSResolvers: a.exitResolvers(),
	}
}

// exitResolvers lists the configured resolvers as an exit names them. An
// empty list names none, and a client selecting the exit keeps its own
// resolver.
func (a *App) exitResolvers() []*dnstype.Resolver {
	var resolvers []*dnstype.Resolver
	for _, r := range a.cfg.Resolvers {
		resolvers = append(resolvers, &dnstype.Resolver{Addr: r.String()})
	}
	return resolvers
}

// nodeID is the ID of a node's peer: its ISD-AS with the sign bit cleared.
// Every node holds the founding core's ISD, within the private range 16 to
// 63, so the ID is the ISD-AS itself — the node's for its life, distinct
// from every other node's, and far above selfNodeID and homeNodeID.
func nodeID(ia addr.IA) tailcfg.NodeID {
	return tailcfg.NodeID(ia & math.MaxInt64)
}

// stableID names a node for the client's own records: the first bytes of
// its key in hex, stable by the key's own durability. The client lines key
// the profile a login persists in on the map's own node id, and a host
// whose map carries none stays unprofiled — every start a fresh login, a
// fresh node key, a fresh admission. A client reports its selected exit by
// the exit peer's.
func stableID(k wireguard.PublicKey) tailcfg.StableNodeID {
	return tailcfg.StableNodeID("n" + hex.EncodeToString(k[:6]))
}

// homeAddresses lists the home node's addresses as /32s, sorted: every host
// the registry holds beside the node's own serving address.
func homeAddresses(directory wireguard.Directory, home wireguard.Entry) []netip.Prefix {
	addrs := make([]netip.Prefix, 0, len(directory.Hosts)+1)
	for _, host := range directory.Hosts {
		addrs = append(addrs, netip.PrefixFrom(host.Addr, 32))
	}
	addrs = append(addrs, servingAddress(home))
	slices.SortFunc(addrs, func(x, y netip.Prefix) int {
		return x.Addr().Compare(y.Addr())
	})
	return addrs
}

// servingAddress is a node's own address as a /32: its slice's first, which
// the allocator never issues to a host.
func servingAddress(node wireguard.Entry) netip.Prefix {
	return netip.PrefixFrom(firstAddress(node.Overlay), 32)
}

// derpMap names the core's relay: one region, one node, on the coordination
// endpoint's own HTTPS identity.
func (a *App) derpMap() *tailcfg.DERPMap {
	port := a.cfg.DERP.Port
	if port == 0 {
		port = 443
	}
	node := &tailcfg.DERPNode{
		Name:     derpNodeName,
		RegionID: derpRegionID,
		HostName: a.cfg.DERP.HostName,
		// No STUN: NAT traversal is the client's outbound-initiated
		// session, not a discovery protocol.
		STUNPort: -1,
		DERPPort: port,
	}
	if a.cfg.DERP.IPv4 != "" {
		node.IPv4 = a.cfg.DERP.IPv4
	}
	if a.cfg.DERP.CertName != "" {
		node.CertName = a.cfg.DERP.CertName
	}
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			derpRegionID: {
				RegionID:   derpRegionID,
				RegionCode: derpRegionCode,
				RegionName: "CION core",
				Nodes:      []*tailcfg.DERPNode{node},
			},
		},
	}
}

// writeMapFrame writes one map response frame: a little-endian size prefix
// around the zstd encoding of the JSON, the client protocol's stream
// grammar — every frame compressed, for the client decodes every frame as
// zstd.
func writeMapFrame(w io.Writer, resp *tailcfg.MapResponse) error {
	raw, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	frame := zstdframe.AppendEncode(nil, raw)
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(frame)))
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// netmapsEqual reports whether two full maps name the same things — the
// resend decision, so an open stream carries changes and nothing else.
func netmapsEqual(a, b *tailcfg.MapResponse) bool {
	return mustJSON(a) == mustJSON(b)
}

// mustJSON marshals v, panicking on a value that cannot marshal.
func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshaling %T: %v", v, err))
	}
	return string(raw)
}
