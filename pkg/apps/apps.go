// Package apps is the applications roof's root: the closed table of the
// node's resident applications, the seam they assemble through, and the
// environment their constructors adapt. Each entry carries its name, the
// registration of its own run arguments, its role bounds, the
// applications it requires beside it, and its constructor; the
// --applications run argument selects among the entries — unset to keep
// the inference the run arguments practice, empty to run the deliberate
// core, given to load exactly the names it lists. The application
// packages sit one beneath the roof and import the core and the
// libraries, never the assembly, the harness, the commands, or this root;
// the table imports them, and the assembly imports the table.
package apps

import (
	"context"
	"net/http"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// Application is the seam a resident application assembles through: Run
// launches its loops under the node's supervision, Close releases it in
// the node's reverse-order release walk, and HTTPSHandler is the surface
// the node's HTTPS server mounts — nil when the application mounts
// nothing there, its surfaces its own sockets instead. The concrete
// applications satisfy it without importing this package.
type Application interface {
	// Run serves the application until the context is canceled.
	Run(ctx context.Context) error
	// Close releases the application.
	Close()
	// HTTPSHandler is the handler the node's HTTPS server mounts, nil when
	// the application mounts nothing on it.
	HTTPSHandler() http.Handler
}

// Environment is the node's facts the entries' constructors adapt into
// their applications' own configurations: everything the assembly's
// phases produced that a resident consumes, built once when the
// applications assemble.
type Environment struct {
	// Arguments are the resident applications' own run arguments; each
	// constructor reads its own entry's block.
	Arguments Arguments
	// IA is the node's ISD-AS; Core marks the founding core's role.
	IA   addr.IA
	Core bool
	// StateRoot is the state directory's root; each application keeps its
	// own state beneath.
	StateRoot string
	// ControlHost is the control address, "host:port"; its host is the
	// underlay host the host-facing port binds.
	ControlHost string
	// Domain is the core's domain — the core's own when Core is set, the
	// network's core domain otherwise.
	Domain string
	// Engine provides the node's chain for the directory channel; Provider
	// resolves the paths the mesh datagrams ride.
	Engine   *trust.Engine
	Provider *scion.PathProvider
	// NewConn binds the node's sending conn on an ephemeral port: the
	// socket the application's own services ride.
	NewConn func() (*scion.Conn, error)
	// InterfaceDown is the node's shared negative cache of SCMP
	// interface-down signals.
	InterfaceDown *scion.InterfaceDownCache
	// RegisterSvc and UnregisterSvc register and retire one of the
	// application's sockets as a SCION service in this AS, on the serving
	// data plane generation and on every one to come.
	RegisterSvc   func(svc addr.SVC, port uint16) error
	UnregisterSvc func(svc addr.SVC, port uint16) error
	// Authorizer gates the coordination application's registrations — nil
	// is open admission.
	Authorizer enrollauth.AdmissionAuthorizer
	// CoreRoute resolves the route to the core the joiner's directory
	// fetch rides; the core needs none, serving the directory itself.
	CoreRoute func() *scion.Addr
	// Relay carries the relay derivation's inputs: the production form
	// derives from the domain, and the harness's placement — its loopback
	// address and pinned certificate — stands in for the domain and the
	// WebPKI. The zero value derives everything from Domain.
	Relay RelayPlacement
	// DirectoryPacing overrides the directory's publish and fetch cadence;
	// zero keeps the production constants.
	DirectoryPacing time.Duration
}

// RelayPlacement is the harness's stand-in for the production relay
// derivation: the relay's URL as the presences dial it and the
// advertisements carry, the address that dials it without DNS, the pinned
// certificate's name, and the relay-only posture that forces the relay
// leg in the netmap.
type RelayPlacement struct {
	URL       string
	IPv4      string
	CertName  string
	RelayOnly bool
}

// Arguments holds the resident applications' own run arguments, one block
// per entry: the commands register the blocks from the table, and each
// constructor adapts its own. The zero value refuses every
// argument-gated application.
type Arguments struct {
	// Wireguard is the WireGuard application's block.
	Wireguard WireguardArguments
}

// WireguardArguments is the WireGuard application's own run arguments.
type WireguardArguments struct {
	// HostPort is the shared host-facing UDP port every host dials. It
	// alone decides whether the node serves hosts: zero runs no WireGuard
	// or SOCKS application.
	HostPort uint16
}
