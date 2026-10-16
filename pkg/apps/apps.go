// Package apps is the applications roof's root: the closed table of the
// node's resident applications, the seam they assemble through, and the
// environment their constructors adapt. Each entry carries its name, the
// registration of its own run arguments, its role bounds, the
// applications it requires beside it, and its constructor; the
// --applications run argument selects among the entries — unset to keep
// the inference the run arguments practice, empty to run the deliberate
// core, given to load exactly the names it lists. The application
// packages sit one beneath the roof and import the core, the libraries,
// and the siblings their entries require — never the assembly, the
// harness, the commands, or this root; the table imports them, and the
// assembly imports the table.
package apps

import (
	"context"
	"net/http"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/apps/voting"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// Application is the seam a resident application assembles through: Run
// launches its loops under the node's supervision, Close releases it in
// the node's reverse-order release walk, and HTTPSHandler is the surface
// the node's HTTPS server mounts — nil when the application mounts
// nothing there, its surfaces its own sockets instead. The concrete
// applications satisfy it without importing this package.
type Application interface {
	// Run runs the application's loops until the context is canceled,
	// each in its own goroutine with a panic absorbed and logged, and
	// returns once every goroutine it started has returned. It may close
	// what nothing borrows to end a loop; what a borrower uses stays for
	// Close.
	Run(ctx context.Context) error
	// Close releases what the constructor bound, once Run has returned, or
	// alone when Run never ran — a failed boot releases applications whose
	// Run never started. A second call releases nothing again.
	Close()
	// HTTPSHandler is the handler the node's HTTPS server mounts at its
	// root, nil when the application mounts nothing on it; at most one
	// loaded application contributes one.
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
	// Domain is the core's WebPKI identity — the founding core's own when
	// Core is set, the network's core identity otherwise.
	Domain string
	// Engine provides the node's chain for the directory channel; Paths
	// resolves the paths the mesh datagrams ride.
	Engine *trust.Engine
	Paths  Paths
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
	// Authorizer is the selected admission policy the applications ask —
	// open where none loads. The coordination application's registrations
	// ask its verdict.
	Authorizer enrollauth.AdmissionAuthorizer
	// TRCDecision is the control plane's decision on the TRC updates the
	// cores submit: the founder's own gates, the pin of what verifies as
	// submitted, and the sensitive vote it casts on its admission policy's
	// allow. Nil on every node but the founding core, the one role the
	// voting application loads on; the application refuses to load
	// without it.
	TRCDecision voting.Decider
	// MountControlEndpoint mounts one of the application's handlers on the
	// node's control endpoint, behind the peer-identity middleware, beside
	// the drafts' services.
	MountControlEndpoint func(pattern string, handler http.Handler)
	// CoreRoute resolves the route to the founding core the directory's
	// publish and fetch ride on every other node; the founding core needs
	// none, serving the directory itself.
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

// Paths is the node's path resolution as the residents call it: the composed
// candidates to a destination, and a path from local state alone.
type Paths interface {
	Enumerate(ctx context.Context, dst addr.IA) ([]scion.Candidate, error)
	LocalPath(dst addr.IA) (*spath.Decoded, error)
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
