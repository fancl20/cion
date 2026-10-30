package portal

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// ErrNoCoordination answers the host queries of a core that runs no
// coordination application: it holds no registry to read or prune.
var ErrNoCoordination = errors.New("the coordination application is not running")

// Role is a node's place in the trust fabric.
type Role string

const (
	// RoleFounder is the founding core, the issuer of every chain.
	RoleFounder Role = "founder"
	// RoleCore is a core the TRC names beside the founder.
	RoleCore Role = "core"
	// RoleNormal is every other enrolled node.
	RoleNormal Role = "normal"
)

// Reach is the observed tag of a node peers cannot dial; the zero value
// tags nothing.
type Reach string

const (
	// ReachNAT tags a node behind a NAT that peers cannot dial.
	ReachNAT Reach = "nat"
	// ReachDegraded tags a node peers cannot dial with no NAT in
	// front of it: a firewall or a network fault.
	ReachDegraded Reach = "degraded"
)

// Node is one node as the founder's records hold it: a node holding a chain
// valid now that the founder knows, or one the node directory's view holds.
type Node struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Key is the newest chain's subject key fingerprint, hex encoded — the
	// fingerprint the node's enrollment presented — empty while the founder
	// holds no chain of the node valid now.
	Key string
	// Reported is when the node signed the entry the node directory's view
	// holds of it, zero while the view holds none: the node is silent.
	Reported time.Time
	// Role is the node's place in the trust fabric.
	Role Role
	// Reach is the node's observed tag, the zero value while peers can dial
	// it or nothing was observed.
	Reach Reach
	// Overlay and Endpoint are the node's tailnet slice and host-facing
	// endpoint, zero while the directory holds no entry of the node.
	Overlay  netip.Prefix
	Endpoint netip.AddrPort
	// Issued counts the host addresses the node's slice has issued.
	Issued int
}

// Host is one Tailscale client the registry holds.
type Host struct {
	// Addr is the host's tailnet address.
	Addr netip.Addr
	// NodeKey is the host's node key, hex encoded: its registry identity.
	NodeKey string
	// MachineKey is the machine key the registration presented, hex
	// encoded; empty for a record from before the machine claim.
	MachineKey string
	// Owner is the node whose slice the address came from — the node the
	// host connects to — and Endpoint that node's host endpoint, zero while
	// the directory holds no entry of it.
	Owner    addr.IA
	Endpoint netip.AddrPort
	// Note is the approving plugin's note the registry recorded.
	Note string
	// Hostname and OS are the client's latest claims about itself.
	Hostname string
	OS       string
	// Connected reports an open map stream; LastSeen is the host's latest
	// sighting since the core started, zero when it has not mapped since.
	Connected bool
	LastSeen  time.Time
}

// Records is the network's records as the console reads them, and the one
// write the console makes: releasing a host's address. The application's
// entry adapts them from the chains the founder holds, the directory, and
// the coordination application.
type Records interface {
	// Nodes lists the nodes holding a chain valid now, the newest chain per
	// ISD-AS, beside the nodes the node directory's view holds.
	Nodes(ctx context.Context) ([]Node, error)
	// Hosts lists the registry's hosts with their presence, or answers
	// ErrNoCoordination.
	Hosts(ctx context.Context) ([]Host, error)
	// RemoveHost releases the host whose hex node key it names, or answers
	// ErrNoCoordination.
	RemoveHost(ctx context.Context, nodeKey string) error
}
