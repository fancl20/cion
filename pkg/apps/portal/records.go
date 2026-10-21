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
	RoleFounder Role = "founding core"
	// RoleCore is a core the TRC names beside the founder.
	RoleCore Role = "core"
	// RoleNode is every other enrolled node.
	RoleNode Role = "node"
)

// Node is one node holding a chain valid now, as the founder's records hold
// it.
type Node struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Key is the newest chain's subject key fingerprint, hex encoded — the
	// fingerprint the node's enrollment presented.
	Key string
	// Expires is the newest chain's expiry.
	Expires time.Time
	// Role is the node's place in the trust fabric.
	Role Role
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
	// Owner is the node whose slice the address came from.
	Owner addr.IA
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
// entry adapts them from the founder's issued chains, the directory, and
// the coordination application.
type Records interface {
	// Nodes lists the nodes holding a chain valid now, newest per ISD-AS.
	Nodes(ctx context.Context) ([]Node, error)
	// Hosts lists the registry's hosts with their presence, or answers
	// ErrNoCoordination.
	Hosts(ctx context.Context) ([]Host, error)
	// RemoveHost releases the host whose hex node key it names, or answers
	// ErrNoCoordination.
	RemoveHost(ctx context.Context, nodeKey string) error
}
