package apps

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/portal"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// portalEntry is the portal application: the operator's passkey console,
// served beneath /admin/ on the founding core's HTTPS server. It pairs with
// the portal admission method, whose asks it decides and whose auth keys it
// mints, and it lists the network's records: the nodes from the issued
// chains, the hosts from the WireGuard registry and the coordination
// application, which it borrows where they load — a core serving no hosts
// still decides its nodes.
var portalEntry = Entry{
	Name:      "portal",
	CoreOnly:  true,
	Admission: "portal",
	New:       newPortal,
}

// newPortal adapts the environment into the console's configuration: the
// selected method's operator surface — the pairing has already made any
// other method a refused selection — and the records over the issued
// chains and whichever of the registry's owners loaded before it.
func newPortal(env *Environment, loaded []Loaded) (Application, error) {
	records := &portalRecords{
		chains:  env.IssuedChains,
		cores:   env.Engine.CoreASes,
		founder: env.IA,
	}
	if wg, ok := AppOf(loaded, "wireguard").(*wireguard.App); ok {
		records.registry = wg.Registry()
	}
	if coord, ok := AppOf(loaded, "coordination").(*coordination.App); ok {
		records.coord = coord
	}
	return portal.New(portal.Config{
		Domain:     env.Domain,
		Origin:     env.HTTPSOrigin,
		StateDir:   filepath.Join(env.StateRoot, "portal"),
		Operator:   env.Authorizer.(enrollauth.Operator),
		Records:    records,
		MountHTTPS: env.MountHTTPS,
	})
}

// portalRecords is the console's view of the founder's records: the chains
// it issued, the TRC's cores, the directory, and the coordination
// application's registry and presence.
type portalRecords struct {
	chains  func(context.Context) ([][]*x509.Certificate, error)
	cores   func(addr.ISD) ([]addr.IA, error)
	founder addr.IA
	// registry is the WireGuard application's directory; nil where it did
	// not load.
	registry wireguard.Registry
	// coord is the coordination application; nil where it did not load.
	coord *coordination.App
}

var _ portal.Records = (*portalRecords)(nil)

// Nodes lists every node holding a chain valid now, the newest chain per
// ISD-AS, beside the node's directory entry where the registry holds one.
func (r *portalRecords) Nodes(ctx context.Context) ([]portal.Node, error) {
	chains, err := r.chains(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the chains: %w", err)
	}
	newest := make(map[addr.IA][]*x509.Certificate)
	for _, chain := range chains {
		ia, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			return nil, fmt.Errorf("reading a stored chain's ISD-AS: %w", err)
		}
		if held, ok := newest[ia]; !ok || chain[0].NotAfter.After(held[0].NotAfter) {
			newest[ia] = chain
		}
	}
	cores, err := r.cores(r.founder.ISD())
	if err != nil {
		return nil, fmt.Errorf("reading the TRC's cores: %w", err)
	}
	var directory wireguard.Directory
	if r.registry != nil {
		if directory, err = r.registry.List(ctx); err != nil {
			return nil, fmt.Errorf("reading the directory: %w", err)
		}
	}
	nodes := make([]portal.Node, 0, len(newest))
	for ia, chain := range newest {
		node := portal.Node{
			IA:      ia,
			Key:     hex.EncodeToString(chain[0].SubjectKeyId),
			Expires: chain[0].NotAfter,
			Role:    portal.RoleNormal,
		}
		switch {
		case ia.Equal(r.founder):
			node.Role = portal.RoleFounder
		case slices.Contains(cores, ia):
			node.Role = portal.RoleCore
		}
		for _, entry := range directory.Nodes {
			if entry.IA.Equal(ia) {
				node.Overlay, node.Endpoint = entry.Overlay, entry.HostEndpoint
			}
		}
		for _, host := range directory.Hosts {
			if host.IA.Equal(ia) {
				node.Issued++
			}
		}
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(a, b portal.Node) int {
		return cmp.Compare(uint64(a.IA), uint64(b.IA))
	})
	return nodes, nil
}

// Hosts lists the registry's hosts, sorted by address, each beside the host
// endpoint of the node it connects to and the presence the coordination
// application observed — whose claims, the latest a client made, stand over
// the ones its admission recorded.
func (r *portalRecords) Hosts(ctx context.Context) ([]portal.Host, error) {
	if r.coord == nil {
		return nil, portal.ErrNoCoordination
	}
	directory, err := r.registry.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the registry: %w", err)
	}
	presence := r.coord.Presence()
	endpoints := make(map[addr.IA]netip.AddrPort, len(directory.Nodes))
	for _, entry := range directory.Nodes {
		endpoints[entry.IA] = entry.HostEndpoint
	}
	hosts := make([]portal.Host, 0, len(directory.Hosts))
	for _, h := range directory.Hosts {
		host := portal.Host{
			Addr:     h.Addr,
			NodeKey:  h.PublicKey.String(),
			Owner:    h.IA,
			Endpoint: endpoints[h.IA],
			Note:     h.Note,
			Hostname: h.Hostname,
			OS:       h.OS,
		}
		if h.MachineKey != (wireguard.PublicKey{}) {
			host.MachineKey = h.MachineKey.String()
		}
		if seen, ok := presence[h.PublicKey]; ok {
			host.Connected, host.LastSeen = seen.Connected, seen.LastSeen
			if seen.Hostname != "" {
				host.Hostname = seen.Hostname
			}
			if seen.OS != "" {
				host.OS = seen.OS
			}
		}
		hosts = append(hosts, host)
	}
	slices.SortFunc(hosts, func(a, b portal.Host) int { return a.Addr.Compare(b.Addr) })
	return hosts, nil
}

// RemoveHost releases the host through the coordination application, the
// registry's owner.
func (r *portalRecords) RemoveHost(ctx context.Context, nodeKey string) error {
	if r.coord == nil {
		return portal.ErrNoCoordination
	}
	key, err := wireguard.ParsePublicKey(nodeKey)
	if err != nil {
		return err
	}
	return r.coord.RemoveHost(ctx, key)
}
