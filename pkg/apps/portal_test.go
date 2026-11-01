package apps

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/portal"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/modules/membership"
)

// TestPortalRecordsNodes checks the console's view of the nodes: one per
// membership, in the listing's ISD-AS order, with its key and expiry — a
// node in no view the founder holds among them, and a node the views hold
// without a membership left out; the roles from the founder's ISD-AS and the
// TRC's cores; the tag each node's latest report earns — NAT when behind a
// NAT and unanswered, Degraded when unanswered alone, none for a node behind
// a NAT peers dial or a node without a report; and the WireGuard directory's
// slice, endpoint, and issued count beside each.
func TestPortalRecordsNodes(t *testing.T) {
	ctx := t.Context()
	founder, core := addr.MustParseIA("1-ff00:0:1"), addr.MustParseIA("1-ff00:0:2")
	node, cloud := addr.MustParseIA("1-ff00:0:3"), addr.MustParseIA("1-ff00:0:4")
	roamer, inside := addr.MustParseIA("1-ff00:0:5"), addr.MustParseIA("1-ff00:0:6")
	now := time.Now().UTC().Truncate(time.Second)
	reported := func(minutes int) time.Time { return now.Add(-time.Duration(minutes) * time.Minute) }
	memberships := []membership.Membership{
		{IA: founder, Key: []byte{0x01, 0x01}, Expires: now.Add(72 * time.Hour)},
		{IA: core, Key: []byte{0x02, 0x02}, Expires: now.Add(60 * time.Hour)},
		{IA: node, Key: []byte{0x03, 0x03}, Expires: now.Add(48 * time.Hour)},
		{IA: cloud, Key: []byte{0x04, 0x04}, Expires: now.Add(36 * time.Hour)},
		{IA: inside, Key: []byte{0x06, 0x06}},
	}
	registry := &dbtest.MemStore{}
	registry.Seed(wireguard.Entry{
		IA:           founder,
		Overlay:      netip.MustParsePrefix("100.64.0.0/24"),
		HostEndpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
	})
	for i, a := range []string{"100.64.0.2", "100.64.0.3"} {
		if err := registry.PublishHost(ctx, wireguard.HostEntry{
			PublicKey: dbtest.MustKey(byte(0x80 + i)),
			Addr:      netip.MustParseAddr(a),
			IA:        founder,
		}); err != nil {
			t.Fatal(err)
		}
	}
	b := bus.New()
	reach := func(r bus.Reach) []bus.Address { return []bus.Address{{Reach: r}} }
	b.Directory().Publish(bus.NewDirectory(nil,
		bus.NewScope(bus.DirectoryID{1},
			bus.DirectoryEntry{IA: core, Published: reported(1),
				Addresses: reach(bus.Reach{BehindNAT: true, RendezvousUnanswered: true})},
			bus.DirectoryEntry{IA: node, Published: reported(2),
				Addresses: reach(bus.Reach{RendezvousUnanswered: true})},
			bus.DirectoryEntry{IA: cloud, Published: reported(3),
				Addresses: reach(bus.Reach{BehindNAT: true})},
			bus.DirectoryEntry{IA: roamer, Published: reported(4)},
		),
		// A node another directory holds too is tagged by its latest entry.
		bus.NewScope(bus.DirectoryID{2},
			bus.DirectoryEntry{IA: node, Published: reported(9),
				Addresses: reach(bus.Reach{BehindNAT: true, RendezvousUnanswered: true})},
		),
	))
	r := &portalRecords{
		memberships: func(context.Context) ([]membership.Membership, error) {
			return memberships, nil
		},
		cores:         func(addr.ISD) ([]addr.IA, error) { return []addr.IA{founder, core}, nil },
		founder:       founder,
		nodeDirectory: b.Directory(),
		registry:      registry,
	}
	nodes, err := r.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []portal.Node{
		{
			IA:       founder,
			Key:      "0101",
			Expires:  now.Add(72 * time.Hour),
			Role:     portal.RoleFounder,
			Overlay:  netip.MustParsePrefix("100.64.0.0/24"),
			Endpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
			Issued:   2,
		},
		{
			IA: core, Key: "0202", Expires: now.Add(60 * time.Hour),
			Role: portal.RoleCore, Reach: portal.ReachNAT,
		},
		{
			IA: node, Key: "0303", Expires: now.Add(48 * time.Hour),
			Role: portal.RoleNormal, Reach: portal.ReachDegraded,
		},
		{IA: cloud, Key: "0404", Expires: now.Add(36 * time.Hour), Role: portal.RoleNormal},
		{IA: inside, Key: "0606", Role: portal.RoleNormal},
	}
	if diff := cmp.Diff(want, nodes,
		cmpopts.EquateComparable(netip.Prefix{}, netip.AddrPort{})); diff != "" {
		t.Errorf("the nodes mismatch (-want +got):\n%s", diff)
	}
}

// TestPortalRecordsRemoveNode checks that the console's removal of a node
// reaches the founder's removal with the node's ISD-AS.
func TestPortalRecordsRemoveNode(t *testing.T) {
	var removed []addr.IA
	r := &portalRecords{removeNode: func(_ context.Context, ia addr.IA) error {
		removed = append(removed, ia)
		return nil
	}}
	node := addr.MustParseIA("1-ff00:0:3")
	if err := r.RemoveNode(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]addr.IA{node}, removed); diff != "" {
		t.Errorf("the founder's removal was asked (-want +got):\n%s", diff)
	}
}

// TestPortalRecordsHosts checks the console's view of the hosts: the
// registry's entries sorted by address, each beside its node's host
// endpoint, with the claims their admission recorded and a legacy record's
// empty machine key; a release reaching the registry through the
// coordination application; and neither without it.
func TestPortalRecordsHosts(t *testing.T) {
	ctx := t.Context()
	owner := addr.MustParseIA("1-ff00:0:1")
	endpoint := netip.MustParseAddrPort("198.51.100.10:41641")
	registry := &dbtest.MemStore{}
	registry.Seed(wireguard.Entry{
		IA:           owner,
		Overlay:      netip.MustParsePrefix("100.64.0.0/24"),
		HostEndpoint: endpoint,
	})
	recorded := []wireguard.HostEntry{
		{
			PublicKey: dbtest.MustKey(0x82),
			Addr:      netip.MustParseAddr("100.64.0.3"),
			IA:        owner,
		},
		{
			PublicKey:  dbtest.MustKey(0x81),
			MachineKey: dbtest.MustKey(0x91),
			Addr:       netip.MustParseAddr("100.64.0.2"),
			IA:         owner,
			Note:       "portal auth key 0a1b2c3d",
			Hostname:   "laptop",
			OS:         "linux",
		},
	}
	for _, h := range recorded {
		if err := registry.PublishHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	coord, err := coordination.New(coordination.Config{
		Domain:     webpkitest.Domain,
		Store:      registry,
		StateDir:   t.TempDir(),
		MountHTTPS: http.NewServeMux().Handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coord.Close)
	r := &portalRecords{registry: registry, coord: coord}
	hosts, err := r.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []portal.Host{
		{
			Addr:       netip.MustParseAddr("100.64.0.2"),
			NodeKey:    strings.Repeat("81", 32),
			MachineKey: strings.Repeat("91", 32),
			Owner:      owner,
			Endpoint:   endpoint,
			Note:       "portal auth key 0a1b2c3d",
			Hostname:   "laptop",
			OS:         "linux",
		},
		{
			Addr:     netip.MustParseAddr("100.64.0.3"),
			NodeKey:  strings.Repeat("82", 32),
			Owner:    owner,
			Endpoint: endpoint,
		},
	}
	if diff := cmp.Diff(want, hosts,
		cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})); diff != "" {
		t.Errorf("the hosts mismatch (-want +got):\n%s", diff)
	}

	if err := r.RemoveHost(ctx, strings.Repeat("81", 32)); err != nil {
		t.Fatalf("releasing the laptop: %v", err)
	}
	directory, err := registry.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Hosts) != 1 || directory.Hosts[0].PublicKey != dbtest.MustKey(0x82) {
		t.Errorf("after the release the registry holds %+v, want the other host alone", directory.Hosts)
	}

	bare := &portalRecords{registry: registry}
	if _, err := bare.Hosts(ctx); !errors.Is(err, portal.ErrNoCoordination) {
		t.Errorf("hosts without coordination = %v, want ErrNoCoordination", err)
	}
	if err := bare.RemoveHost(ctx, strings.Repeat("82", 32)); !errors.Is(err, portal.ErrNoCoordination) {
		t.Errorf("a release without coordination = %v, want ErrNoCoordination", err)
	}
}
