package coordination

import (
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// The netmap's constants: the tailnet range the tunnel carries and nothing
// else — no default route is advertised, internet egress stays a service on
// the overlay — and the one DERP region the core serves.
const (
	// Tailnet is the overlay's host space, the range every slice is a
	// slice of.
	Tailnet = "100.64.0.0/10"

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

	// maxMapBody bounds one map request.
	maxMapBody = 1 << 20
)

// servedCapabilityVersion is the one capability version the service serves and
// advertises — the vendored client protocol's own current version, the pin of
// the standing compatibility commitment: the vendor's and mihomo's client
// lines are verified against it, and a vendored upgrade that moves it moves
// this with it or fails the pin's test.
const servedCapabilityVersion = tailcfg.CurrentCapabilityVersion

// handleMap answers one netmap request. Each host's map names exactly its
// node — the node's WireGuard public key, the host-facing endpoint from its
// directory entry, and allowed IPs covering the tailnet and nothing else —
// beside the host's own allocated address and the relay. No delta
// compression, no peer change machinery: the tailnet holds one peer per
// host, CION is non-scalable by design, and a full map is the smallest
// correct answer. The first map goes out at once; a streaming request's
// body stays open, keepalives holding it and a re-read registry resending
// the map when what it names changed.
func (a *App) handleMap(w http.ResponseWriter, r *http.Request,
	machine key.MachinePublic) {

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
	resp, err := a.netmap(req.NodeKey, machine, directory,
		req.DiscoKey, hostinfo)
	if err != nil {
		// A key the registry does not hold maps nothing: the client
		// retries, and the refusal names the register it must complete.
		http.Error(w, "no registration for the key", http.StatusForbidden)
		return
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
	if !req.Stream {
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
			updated, err := a.netmap(req.NodeKey, machine, directory,
				req.DiscoKey, hostinfo)
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

// netmap builds one host's full map from the registry. The peer carries no
// disco key: the node is a wireguard-only peer with a static endpoint, the
// model the client lines already serve for third-party exits. The peer's
// allowed IPs are the registry's whole occupied space — every allocated host
// /32 beside every node's own address, the slice's first, each an offered
// exit's serving address — covering the tailnet and nothing else, no default
// route anywhere, as single-IP Tailscale addresses rather than the covering
// /10, the form the client lines route unconditionally: a covering prefix is
// an advertised subnet route behind the client's own route-all preference,
// which no host of this network is asked to hold. The packet filter is a
// single rule admitting the member's traffic: membership is the tailnet's one
// policy, and no engine stands behind the rule to configure.
func (a *App) netmap(node key.NodePublic, machine key.MachinePublic,
	directory wireguard.Directory, reqDisco key.DiscoPublic,
	reqHostinfo tailcfg.HostinfoView) (*tailcfg.MapResponse, error) {

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
	var owner *wireguard.Entry
	for i := range directory.Nodes {
		if directory.Nodes[i].IA.Equal(self.IA) {
			owner = &directory.Nodes[i]
			break
		}
	}
	if owner == nil {
		return nil, fmt.Errorf("the owning node %s holds no directory entry", self.IA)
	}
	if !owner.HostEndpoint.IsValid() {
		return nil, fmt.Errorf("the owning node %s published no host endpoint", self.IA)
	}
	address := netip.PrefixFrom(self.Addr, 32)
	routed := routedAddresses(directory)
	now := time.Now()
	online := true
	if debugCfgControl {
		debugDiscoKey = key.NewDisco().Public()
	}
	peer := &tailcfg.Node{
		ID:                2,
		User:              registerUserID,
		Key:               nodePublicOf(owner.PublicKey),
		AllowedIPs:        routed,
		Addresses:         routed,
		Endpoints:         []netip.AddrPort{owner.HostEndpoint},
		HomeDERP:          derpRegionID,
		IsWireGuardOnly:   !debugCfgControl, // control experiment knob
		DiscoKey:          debugDiscoKey,
		MachineAuthorized: true,
		Online:            &online,
		LastSeen:          &now,
		Cap:               servedCapabilityVersion,
		Created:           now,
	}
	if a.cfg.RelayOnly {
		peer.Endpoints = nil
	}
	return &tailcfg.MapResponse{
		Node: &tailcfg.Node{
			ID:         1,
			User:       registerUserID,
			Key:        node,
			Machine:    machine,
			Addresses:  []netip.Prefix{address},
			AllowedIPs: []netip.Prefix{address},
			// The client's own claims, echoed the way a control answers:
			// its disco key from the request, its hostinfo beside them.
			DiscoKey:          reqDisco,
			Hostinfo:          reqHostinfo,
			MachineAuthorized: true,
			Cap:               servedCapabilityVersion,
			Created:           time.Now(),
		},
		Peers:   []*tailcfg.Node{peer},
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

// debugDiscoKey is the control experiment's stand-in disco key, used only
// when debugDiscoPeer is set.
var debugDiscoKey = key.DiscoPublic{}

// debugCfgControl runs the control experiment: serve the peer as a
// standard disco peer instead of a wireguard-only one.
var debugCfgControl bool

// SetDebugDiscoPeer runs the control experiment: serve the peer as a
// standard disco peer instead of a wireguard-only one.
func SetDebugDiscoPeer(v bool) { debugCfgControl = v }

// routedAddresses lists every routed address as a /32, sorted: the registry's
// whole occupied space — each allocated host beside each node's own, the
// slice's first address, the serving address every node's SOCKS offer answers
// on. Nothing new rides the directory entry: the node's address was always
// derivable from the slice the entry carries, and the allocator never issues
// it to a host, so the addition cannot collide with an allocation. One login
// serves every node, and the exit a flow uses is which tailnet address it is
// sent to.
func routedAddresses(directory wireguard.Directory) []netip.Prefix {
	addrs := make([]netip.Prefix, 0,
		len(directory.Hosts)+len(directory.Nodes))
	for _, host := range directory.Hosts {
		addrs = append(addrs, netip.PrefixFrom(host.Addr, 32))
	}
	for _, node := range directory.Nodes {
		addrs = append(addrs, netip.PrefixFrom(firstAddress(node.Overlay), 32))
	}
	slices.SortFunc(addrs, func(a, b netip.Prefix) int {
		return a.Addr().Compare(b.Addr())
	})
	return addrs
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
