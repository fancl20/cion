package coordination

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// TestNetmapHoldsOnePeer checks the map the registry builds for one host:
// the host's own allocated address, exactly its node as the peer — the
// node's key, the host-facing endpoint, allowed IPs covering the tailnet
// and nothing else, wireguard-only with no disco key — a single packet
// filter rule admitting the member's traffic, and the DERP map naming the
// core's region.
func TestNetmapHoldsOnePeer(t *testing.T) {
	store := &memStore{}
	nodeEntry := testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820")
	nodeEntry.PublicKey = testHostKey(0x11)
	if err := store.Publish(context.Background(), nodeEntry); err != nil {
		t.Fatal(err)
	}
	hostKey := testHostKey(0x22)
	host := registeredHost(hostKey)
	if err := store.PublishHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	a := testApp(t, Config{Store: store})

	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.netmap(nodePublicOf(hostKey), machineZero(), directory,
		key.DiscoPublic{}, tailcfg.HostinfoView{})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Key != nodePublicOf(hostKey) {
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

	if len(resp.Peers) != 1 {
		t.Fatalf("the map holds %d peers, want exactly the node", len(resp.Peers))
	}
	peer := resp.Peers[0]
	if peer.Key != nodePublicOf(nodeEntry.PublicKey) {
		t.Errorf("the peer key = %v, want the node's", peer.Key)
	}
	// The peer's allowed IPs are the registry's occupied space — the
	// allocated /32s beside the node's own address, the slice's first —
	// each a single-IP Tailscale address the client lines route
	// unconditionally, and no covering prefix, which the client would hold
	// behind its route-all preference.
	wantIPs := []netip.Prefix{
		netip.MustParsePrefix("100.64.1.1/32"),
		netip.MustParsePrefix("100.64.1.2/32"),
	}
	if !slices.Equal(peer.AllowedIPs, wantIPs) {
		t.Errorf("the peer's allowed IPs = %v, want %v", peer.AllowedIPs, wantIPs)
	}
	tailnet := netip.MustParsePrefix(Tailnet)
	for _, aip := range peer.AllowedIPs {
		if !tailnet.Contains(aip.Addr()) {
			t.Errorf("the allowed IP %s is outside the tailnet", aip)
		}
	}
	if len(peer.Endpoints) != 1 || peer.Endpoints[0] != nodeEntry.HostEndpoint {
		t.Errorf("the peer's endpoints = %v, want the host-facing %v",
			peer.Endpoints, nodeEntry.HostEndpoint)
	}
	if !peer.IsWireGuardOnly || !peer.DiscoKey.IsZero() {
		t.Error("the peer is not the wireguard-only, no-disco model")
	}
	if peer.HomeDERP != derpRegionID {
		t.Errorf("the peer's home DERP = %d, want the core's region %d",
			peer.HomeDERP, derpRegionID)
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
	if relay.HostName != TestDomain || relay.STUNPort != -1 {
		t.Errorf("the relay = %+v, want the core's identity and no STUN", relay)
	}
	if resp.DNSConfig != nil {
		t.Error("the map carries a DNS configuration, want none")
	}
}

// TestNetmapRequiresRegistration checks the map refuses keys the registry
// does not hold and nodes that published no host-facing endpoint.
func TestNetmapRequiresRegistration(t *testing.T) {
	store := &memStore{}
	a := testApp(t, Config{Store: store})
	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.netmap(nodePublicOf(testHostKey(1)), machineZero(), directory,
		key.DiscoPublic{}, tailcfg.HostinfoView{}); err == nil {
		t.Error("an unregistered key mapped, want refusal")
	}
	if err := store.PublishHost(context.Background(), registeredHost(testHostKey(1))); err != nil {
		t.Fatal(err)
	}
	directory, _ = store.List(context.Background())
	if _, err := a.netmap(nodePublicOf(testHostKey(1)), machineZero(), directory,
		key.DiscoPublic{}, tailcfg.HostinfoView{}); err == nil {
		t.Error("a host with no owning node entry mapped, want refusal")
	}
}

// TestNetmapCarriesEveryNodesAddress checks the map's growth (ADR-0012):
// every node entry contributes its slice's first address — the node's own,
// the SOCKS service's serving address — as one more /32 among the host
// /32s, sorted, and no covering prefix appears anywhere in the map.
func TestNetmapCarriesEveryNodesAddress(t *testing.T) {
	store := &memStore{}
	if err := store.Publish(context.Background(),
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820")); err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(context.Background(),
		testNode(mustIA("1-ff00:0:2"), "100.64.8.0/24", "198.51.100.11:51820")); err != nil {
		t.Fatal(err)
	}
	for _, host := range []wireguard.HostEntry{
		{PublicKey: testHostKey(0x21), Addr: netip.MustParseAddr("100.64.1.2"),
			IA: mustIA("1-ff00:0:1")},
		{PublicKey: testHostKey(0x22), Addr: netip.MustParseAddr("100.64.8.9"),
			IA: mustIA("1-ff00:0:2")},
	} {
		if err := store.PublishHost(context.Background(), host); err != nil {
			t.Fatal(err)
		}
	}
	a := testApp(t, Config{Store: store})

	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.netmap(nodePublicOf(testHostKey(0x21)), machineZero(),
		directory, key.DiscoPublic{}, tailcfg.HostinfoView{})
	if err != nil {
		t.Fatal(err)
	}
	peer := resp.Peers[0]
	want := []netip.Prefix{
		netip.MustParsePrefix("100.64.1.1/32"), // node 1's own
		netip.MustParsePrefix("100.64.1.2/32"), // its host
		netip.MustParsePrefix("100.64.8.1/32"), // node 2's own
		netip.MustParsePrefix("100.64.8.9/32"), // its host
	}
	if !slices.Equal(peer.AllowedIPs, want) || !slices.Equal(peer.Addresses, want) {
		t.Errorf("the peer's routed addresses = %v, want %v", peer.AllowedIPs, want)
	}
	for _, aip := range peer.AllowedIPs {
		if aip.Bits() != 32 {
			t.Errorf("the address %s is a covering prefix, want single-IP routes alone", aip)
		}
	}
}

// TestNetmapResendFollowsNodes checks the map comparison's verdict: a
// node's arrival or departure changes the map a connected host holds, so
// the standing resend ticker carries the new map — a full map still the
// smallest correct answer.
func TestNetmapResendFollowsNodes(t *testing.T) {
	store := &memStore{}
	owner := testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820")
	if err := store.Publish(context.Background(), owner); err != nil {
		t.Fatal(err)
	}
	host := registeredHost(testHostKey(0x31))
	if err := store.PublishHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	a := testApp(t, Config{Store: store})

	build := func() *tailcfg.MapResponse {
		directory, err := store.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		resp, err := a.netmap(nodePublicOf(testHostKey(0x31)), machineZero(),
			directory, key.DiscoPublic{}, tailcfg.HostinfoView{})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	before := build()

	// A node's arrival flips the verdict: its own address joins the map.
	if err := store.Publish(context.Background(),
		testNode(mustIA("1-ff00:0:2"), "100.64.2.0/24", "198.51.100.11:51820")); err != nil {
		t.Fatal(err)
	}
	after := build()
	if netmapsEqual(before, after) {
		t.Error("a node's arrival left the map unchanged, want the resend to fire")
	}
}
