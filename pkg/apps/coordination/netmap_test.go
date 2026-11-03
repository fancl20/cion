package coordination

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// The two-node registry the netmap tests map from: the home node, where the
// mapped host lands, and one other node, each under its own key with its own
// slice and host endpoint, a host on each, and the arrival every map is built
// at.
var (
	homeNode = wireguard.Entry{
		IA:           mustIA("1-ff00:0:1"),
		PublicKey:    dbtest.MustKey(0x11),
		Overlay:      netip.MustParsePrefix("100.64.1.0/24"),
		HostEndpoint: netip.MustParseAddrPort("198.51.100.10:51820"),
	}
	otherNode = wireguard.Entry{
		IA:           mustIA("1-ff00:0:2"),
		PublicKey:    dbtest.MustKey(0x12),
		Overlay:      netip.MustParsePrefix("100.64.8.0/24"),
		HostEndpoint: netip.MustParseAddrPort("198.51.100.11:51820"),
	}
	homeHost   = dbtest.MustKey(0x21)
	otherHost  = dbtest.MustKey(0x22)
	mapArrival = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
)

// twoNodeRegistry seeds the two-node registry.
func twoNodeRegistry(t *testing.T) *dbtest.MemStore {
	t.Helper()
	store := &dbtest.MemStore{}
	store.Seed(homeNode)
	store.Seed(otherNode)
	for _, host := range []wireguard.HostEntry{
		{PublicKey: homeHost, Addr: netip.MustParseAddr("100.64.1.2"), IA: homeNode.IA},
		{PublicKey: otherHost, Addr: netip.MustParseAddr("100.64.8.9"), IA: otherNode.IA},
	} {
		if err := store.PublishHost(context.Background(), host); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

// buildMap builds the home host's map from the store's registry at the
// arrival.
func buildMap(t *testing.T, a *App, store *dbtest.MemStore) *tailcfg.MapResponse {
	t.Helper()
	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.netmap(context.Background(), nodePublicOf(homeHost), machineZero(), directory,
		key.DiscoPublic{}, tailcfg.HostinfoView{}, mapArrival)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// wireJSON is v's wire form, indented so a mismatch diffs line by line.
func wireJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v, jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestNetmapNamesEveryNode checks the map the two-node registry builds for
// the home host: the host's own allocated address; two peers, in ID order —
// the home node under its key, ID, endpoint, and region, holding every
// host's address beside its own serving address and the exit routes, and
// the other node under its own key, holding its serving address alone and
// the exit routes, reached at the home node's endpoint — each with
// capability version 0, hostinfo, a name, and the resolvers, and stamped
// with the request's arrival; no peer for a node holding no slice; a single
// packet filter rule admitting the member's traffic; and the DERP map naming
// the core's region.
func TestNetmapNamesEveryNode(t *testing.T) {
	store := twoNodeRegistry(t)
	store.Seed(wireguard.Entry{IA: mustIA("1-ff00:0:3"), PublicKey: dbtest.MustKey(0x13)})
	a := testApp(t, Config{
		Store:     store,
		Resolvers: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
	})
	resp := buildMap(t, a, store)

	if resp.Node.Key != nodePublicOf(homeHost) {
		t.Errorf("the map's own key = %v, want the host's", resp.Node.Key)
	}
	want := "100.64.1.2/32"
	if len(resp.Node.Addresses) != 1 || resp.Node.Addresses[0].String() != want {
		t.Errorf("the map's addresses = %v, want the allocated %s", resp.Node.Addresses, want)
	}
	if !resp.Node.MachineAuthorized {
		t.Error("the map's own node is not machine-authorized")
	}
	if resp.Node.Cap != servedCapabilityVersion {
		t.Errorf("the map advertises capability %d, want the served %d",
			resp.Node.Cap, servedCapabilityVersion)
	}
	if resp.Node.StableID != stableID(homeHost) {
		t.Errorf("the map's own stable id = %q, want the host key's %q",
			resp.Node.StableID, stableID(homeHost))
	}
	if !resp.Node.Created.Equal(mapArrival) {
		t.Errorf("the map's own node was created %v, want the request's arrival %v",
			resp.Node.Created, mapArrival)
	}

	online := true
	resolvers := []*dnstype.Resolver{{Addr: "8.8.8.8"}, {Addr: "8.8.4.4"}}
	endpoints := []netip.AddrPort{homeNode.HostEndpoint}
	wantPeers := []*tailcfg.Node{{
		ID:       homeNodeID,
		StableID: "n111111111111",
		Name:     "1-ff00-0-1." + webpkitest.Domain + ".",
		User:     registerUserID,
		Key:      nodePublicOf(homeNode.PublicKey),
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.1/32"), // the home node's own
			netip.MustParsePrefix("100.64.1.2/32"), // its host
			netip.MustParsePrefix("100.64.8.9/32"), // the other node's host
		},
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.1/32"),
			netip.MustParsePrefix("100.64.1.2/32"),
			netip.MustParsePrefix("100.64.8.9/32"),
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
		Endpoints:            endpoints,
		HomeDERP:             derpRegionID,
		Hostinfo:             (&tailcfg.Hostinfo{Hostname: "1-ff00:0:1"}).View(),
		Created:              mapArrival,
		Cap:                  0,
		LastSeen:             &mapArrival,
		Online:               &online,
		MachineAuthorized:    true,
		IsWireGuardOnly:      true,
		ExitNodeDNSResolvers: resolvers,
	}, {
		ID:        0x0001_ff00_0000_0002,
		StableID:  "n121212121212",
		Name:      "1-ff00-0-2." + webpkitest.Domain + ".",
		User:      registerUserID,
		Key:       nodePublicOf(otherNode.PublicKey),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.8.1/32")},
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("100.64.8.1/32"),
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
		Endpoints:            endpoints,
		Hostinfo:             (&tailcfg.Hostinfo{Hostname: "1-ff00:0:2"}).View(),
		Created:              mapArrival,
		Cap:                  0,
		LastSeen:             &mapArrival,
		Online:               &online,
		MachineAuthorized:    true,
		IsWireGuardOnly:      true,
		ExitNodeDNSResolvers: resolvers,
	}}
	if diff := cmp.Diff(wireJSON(t, wantPeers), wireJSON(t, resp.Peers)); diff != "" {
		t.Errorf("the peers' wire form (-want +got):\n%s", diff)
	}

	// The packet filter is a single rule admitting the member's traffic.
	if len(resp.PacketFilter) != 1 {
		t.Fatalf("the packet filter holds %d rules, want the one", len(resp.PacketFilter))
	}
	rule := resp.PacketFilter[0]
	if len(rule.SrcIPs) != 1 || rule.SrcIPs[0] != Tailnet {
		t.Errorf("the filter's sources = %v, want the tailnet alone", rule.SrcIPs)
	}
	if len(rule.DstPorts) != 1 || rule.DstPorts[0].Ports != tailcfg.PortRangeAny {
		t.Errorf("the filter's ports = %v, want every port", rule.DstPorts)
	}

	// The DERP map names the core's region on its own identity.
	region, ok := resp.DERPMap.Regions[derpRegionID]
	if !ok || len(region.Nodes) != 1 {
		t.Fatalf("the DERP map = %+v, want one region, one node", resp.DERPMap.Regions)
	}
	relay := region.Nodes[0]
	if relay.HostName != webpkitest.Domain || relay.STUNPort != -1 {
		t.Errorf("the relay = %+v, want the core's identity and no STUN", relay)
	}
	if resp.DNSConfig != nil {
		t.Error("the map carries a DNS configuration, want none")
	}
}

// TestNetmapRelayOnlyStripsEndpoints checks the relay-only posture: no peer
// carries an endpoint, and the home node's keeps its region.
func TestNetmapRelayOnlyStripsEndpoints(t *testing.T) {
	store := twoNodeRegistry(t)
	a := testApp(t, Config{Store: store, RelayOnly: true})
	resp := buildMap(t, a, store)
	if len(resp.Peers) != 2 {
		t.Fatalf("the map holds %d peers, want both nodes", len(resp.Peers))
	}
	for _, peer := range resp.Peers {
		if len(peer.Endpoints) != 0 {
			t.Errorf("the peer %s carries the endpoints %v, want none", peer.Name, peer.Endpoints)
		}
	}
	if resp.Peers[0].HomeDERP != derpRegionID {
		t.Errorf("the home node's region = %d, want the core's %d",
			resp.Peers[0].HomeDERP, derpRegionID)
	}
}

// TestNetmapWithoutResolvers checks an empty resolver list: no peer names a
// resolver.
func TestNetmapWithoutResolvers(t *testing.T) {
	store := twoNodeRegistry(t)
	a := testApp(t, Config{Store: store})
	for _, peer := range buildMap(t, a, store).Peers {
		if peer.ExitNodeDNSResolvers != nil {
			t.Errorf("the peer %s names the resolvers %v, want none",
				peer.Name, peer.ExitNodeDNSResolvers)
		}
	}
}

// TestNetmapRequiresRegistration checks the map refuses keys the registry
// does not hold and nodes that published no host-facing endpoint.
func TestNetmapRequiresRegistration(t *testing.T) {
	store := &dbtest.MemStore{}
	a := testApp(t, Config{Store: store})
	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.netmap(context.Background(), nodePublicOf(dbtest.MustKey(1)), machineZero(), directory,
		key.DiscoPublic{}, tailcfg.HostinfoView{}, mapArrival); err == nil {
		t.Error("an unregistered key mapped, want refusal")
	}
	if err := store.PublishHost(context.Background(), registeredHost(dbtest.MustKey(1))); err != nil {
		t.Fatal(err)
	}
	directory, _ = store.List(context.Background())
	if _, err := a.netmap(context.Background(), nodePublicOf(dbtest.MustKey(1)), machineZero(), directory,
		key.DiscoPublic{}, tailcfg.HostinfoView{}, mapArrival); err == nil {
		t.Error("a host with no owning node entry mapped, want refusal")
	}
}

// TestNetmapBindsAndRefusesMachines checks the map's machine claim at the
// builder: a record holding no machine key binds the first machine to
// present it — the registry keeps the binding — and a machine the record
// does not name maps nothing.
func TestNetmapBindsAndRefusesMachines(t *testing.T) {
	store := &dbtest.MemStore{}
	nodeEntry := testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820")
	nodeEntry.PublicKey = dbtest.MustKey(0x11)
	store.Seed(nodeEntry)
	if err := store.PublishHost(context.Background(),
		registeredHost(dbtest.MustKey(0x22))); err != nil {
		t.Fatal(err)
	}
	a := testApp(t, Config{Store: store})

	// The first presentation binds: the record answers the machine and
	// keeps the binding.
	member := key.NewMachine()
	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.netmap(context.Background(), nodePublicOf(dbtest.MustKey(0x22)),
		member.Public(), directory, key.DiscoPublic{}, tailcfg.HostinfoView{}, mapArrival); err != nil {
		t.Fatalf("the first presentation mapped no answer: %v", err)
	}
	directory, err = store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Hosts) != 1 ||
		directory.Hosts[0].MachineKey != machineKeyOf(member.Public()) {
		t.Fatalf("the registry holds %+v, want the record bound to the first presenter",
			directory.Hosts)
	}

	// A machine the record does not name maps nothing.
	if _, err := a.netmap(context.Background(), nodePublicOf(dbtest.MustKey(0x22)),
		key.NewMachine().Public(), directory, key.DiscoPublic{}, tailcfg.HostinfoView{},
		mapArrival); err == nil {
		t.Error("a machine the record does not name mapped, want refusal")
	}
}

// TestNetmapResendFollowsNodes checks the map comparison's verdict over the
// rebuilds of one stream: an unchanged registry rebuilds an equal map, so
// the stream resends nothing; a node's arrival changes the map, so the
// standing resend ticker carries the new map — a full map still the
// smallest correct answer; and every node keeps its peer's ID and stable ID
// across the rebuilds, the arriving node's ID its ISD-AS's.
func TestNetmapResendFollowsNodes(t *testing.T) {
	store := twoNodeRegistry(t)
	a := testApp(t, Config{Store: store})
	before := buildMap(t, a, store)
	if !netmapsEqual(before, buildMap(t, a, store)) {
		t.Error("an unchanged registry rebuilt a different map, want no resend")
	}

	// A node's arrival flips the verdict: its peer joins the map.
	store.Seed(wireguard.Entry{
		IA:           mustIA("1-ff00:0:3"),
		PublicKey:    dbtest.MustKey(0x13),
		Overlay:      netip.MustParsePrefix("100.64.9.0/24"),
		HostEndpoint: netip.MustParseAddrPort("198.51.100.12:51820"),
	})
	after := buildMap(t, a, store)
	if netmapsEqual(before, after) {
		t.Error("a node's arrival left the map unchanged, want the resend to fire")
	}

	type identity struct {
		ID       tailcfg.NodeID
		StableID tailcfg.StableNodeID
	}
	identities := func(resp *tailcfg.MapResponse) map[string]identity {
		out := make(map[string]identity, len(resp.Peers))
		for _, peer := range resp.Peers {
			out[peer.Key.String()] = identity{peer.ID, peer.StableID}
		}
		return out
	}
	wantIDs := identities(before)
	wantIDs[nodePublicOf(dbtest.MustKey(0x13)).String()] = identity{0x0001_ff00_0000_0003, "n131313131313"}
	if diff := cmp.Diff(wantIDs, identities(after)); diff != "" {
		t.Errorf("the peers' identities after the arrival (-want +got):\n%s", diff)
	}
}
