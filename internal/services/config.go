package services

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/enrollauth"
)

// Default run arguments: a restart needs none of them (ADR-0008).
const (
	// DefaultState is the state directory's default.
	DefaultState = "/var/lib/cion"
	// DefaultInternal is the internal address's default.
	DefaultInternal = "127.0.0.1:30042"
	// DefaultControl is the control address's default; its host carries the
	// control service, rendezvous, and directory sockets.
	DefaultControl = "127.0.0.1:30044"
)

// NodeConfig is the node's run arguments — everything the retiring
// configuration file carried, as arguments with defaults: identity, links,
// and the forwarding key come from the state directory, where the first
// start generates them (ADR-0008).
type NodeConfig struct {
	// Core marks the founding core: TRC genesis, issuer, self-enrollment. It
	// takes no neighbor.
	Core bool
	// Domain is the core's domain — the core's own when Core is set (with
	// AcmeEmail optional and the certificate files as the offline fallback),
	// the network's core domain otherwise: the WebPKI identity of the
	// enrollment and TRC fetch.
	Domain    string
	AcmeEmail string
	CertFile  string
	KeyFile   string
	// Neighbors are existing nodes' rendezvous underlay addresses; the first
	// start of a non-core requires at least one, later starts seed
	// additional entries, idempotent by remote address. They select the
	// measured topology provider, which loads by default.
	Neighbors []string
	// LinkSet points at the file provider's link-set (ADR 0009): neighbor
	// ISD-ASes with the links' two underlay addresses, reconciled into the
	// store as the operator's vouch. It refuses to combine with --neighbor,
	// and it never carries identity, keys, or bind addresses — those stay
	// run arguments and state.
	LinkSet string
	// State is the state directory; Internal and Control are the bind
	// addresses.
	State    string
	Internal string
	Control  string
	// EnrollAuth selects the enrollment authorizer that gates first
	// issuance (ADR-0010), "method=spec": "cidrs" with a comma-separated
	// prefix list, "telegram" with <chat>:<token>. Empty is open enrollment
	// — the zero-conf default — and the argument refuses to load without
	// --core, the only node that issues chains.
	EnrollAuth string
	// TelegramAPI overrides the Telegram Bot API's base URL for the
	// telegram method of EnrollAuth; empty uses the public one. The
	// integration tests point it at their local double.
	TelegramAPI string
	// BehindNAT publishes the node's reachability class as private: joinable
	// by no one, candidate for no one's floor.
	BehindNAT bool
	// Slice is the node's slice of the tailnet range, 100.64.0.0/10, e.g.
	// "100.64.1.0/24" (proposal 0024): the space the coordination service
	// allocates the node's hosts from, the slice's first address the
	// node's own — the SOCKS service's serving address. Empty runs no
	// WireGuard or SOCKS application.
	Slice string
	// HostPort is the shared host-facing UDP port every host dials;
	// required with Slice.
	HostPort uint16
	// Coordination overrides the coordination endpoint's placement for the
	// integration harness (proposal 0022): the loopback address its core
	// serves on and the relay every node's presence dials, standing in for
	// the production derivation from the core's domain. Nil serves the
	// endpoint on the core's control host at the default port.
	Coordination *CoordinationOptions
	// RootCAs anchors the WebPKI verification of the core's domain
	// certificate; nil uses the system roots. The integration tests inject
	// their CA with it.
	RootCAs *x509.CertPool

	// Pacing shortens the loops' periods; zero values keep the production
	// constants. The daemon never sets it — the integration tests do.
	Pacing NodePacing
}

// CoordinationOptions is the coordination endpoint's harness placement.
type CoordinationOptions struct {
	// Addr is the HTTPS address the core serves the coordination endpoint
	// on, "host:port".
	Addr string
	// DERP overrides the relay the netmap advertises and the nodes'
	// presences dial.
	DERP DERPOptions
	// RelayOnly strips the peer's endpoint from every netmap the endpoint
	// serves — the harness's stand-in for a network where UDP to the node
	// cannot pass, forcing the relay leg.
	RelayOnly bool
}

// DERPOptions names a relay: the pieces of the DERP map's grammar the
// harness needs beside the production derivation from the core's domain.
type DERPOptions struct {
	// URL is the relay's HTTPS address as the node's presence dials it.
	URL string
	// IPv4 dials the relay by address instead of DNS.
	IPv4 string
	// Port overrides the relay's HTTPS port in the netmap's advertisement.
	Port int
	// CertName pins the relay's certificate ("sha256-raw:<hex>" among the
	// forms).
	CertName string
}

// NodePacing carries the test pacing of the node's loops.
type NodePacing struct {
	Propagation     time.Duration // beacon origination and propagation
	Registration    time.Duration // segment registration
	Enrollment      time.Duration // enrollment retry
	Selection       time.Duration // selection evaluation window
	CandidateWindow time.Duration // unproven candidate lifetime
	Directory       time.Duration // directory publish and fetch
	RendezvousRate  time.Duration // admission rate caps (rendezvous, link, and enrollment doors)
	LinkSetPoll     time.Duration // the file provider's link-set poll
	BFD             time.Duration // BFD transmission interval
}

// Validate applies the role-aware argument checks: the domain is always
// required; the core takes no neighbor.
func (c NodeConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("--domain is required: the core's own on --core, the network's core domain otherwise")
	}
	if c.Core && len(c.Neighbors) > 0 {
		return fmt.Errorf("the founding core takes no --neighbor: nodes join it")
	}
	if c.LinkSet != "" && len(c.Neighbors) > 0 {
		return fmt.Errorf("--link-set refuses --neighbor: " +
			"one topology provider per process, the static and the measured")
	}
	if c.State == "" || c.Internal == "" || c.Control == "" {
		return fmt.Errorf("--state, --internal, and --control are required")
	}
	for _, s := range c.Neighbors {
		if _, err := netip.ParseAddrPort(s); err != nil {
			return fmt.Errorf("parsing --neighbor %q: %w", s, err)
		}
	}
	if c.EnrollAuth != "" {
		// A silently inert gate is the misleading configuration the
		// role-aware checks exist to refuse: only the core issues chains,
		// so only the core's gate means anything.
		if !c.Core {
			return fmt.Errorf("--enroll-auth requires --core: " +
				"the core is the only node that issues chains")
		}
		if _, _, err := enrollauth.Load(c.EnrollAuth,
			enrollauth.LoadOptions{State: c.State}); err != nil {
			return fmt.Errorf("parsing --enroll-auth: %w", err)
		}
	}
	if c.Slice != "" {
		// The slice's grammar is the one the retired configuration file
		// narrowed (proposal 0022): a prefix the tailnet range contains.
		subnet, err := netip.ParsePrefix(c.Slice)
		if err != nil {
			return fmt.Errorf("parsing --slice %q: %w", c.Slice, err)
		}
		if !subnet.Addr().Is4() ||
			!wireguard.Tailnet.Contains(subnet.Addr()) ||
			subnet.Bits() < wireguard.Tailnet.Bits() {
			return fmt.Errorf("--slice %s is not a slice of the tailnet range %s",
				subnet, wireguard.Tailnet)
		}
		if c.HostPort == 0 {
			return fmt.Errorf("--host-port is required with --slice: " +
				"the shared host-facing port every host dials")
		}
	}
	if c.HostPort != 0 && c.Slice == "" {
		return fmt.Errorf("--host-port requires --slice: " +
			"the port serves the applications the slice names")
	}
	return nil
}

// controlBind returns the "host:port" address for the control endpoint: the
// control address's host with the given port.
func controlBind(control string, port uint16) (string, error) {
	ap, err := dataplane.ResolveAddrPort(control)
	if err != nil {
		return "", fmt.Errorf("parsing control address: %w", err)
	}
	return netip.AddrPortFrom(ap.Addr(), port).String(), nil
}

// parseControlHost returns the control address's host.
func parseControlHost(control string) (netip.Addr, error) {
	ap, err := dataplane.ResolveAddrPort(control)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing control address: %w", err)
	}
	return ap.Addr(), nil
}

// parseInternalHost returns the local host address derived from the internal
// address.
func parseInternalHost(internal string) (addr.Host, error) {
	ap, err := dataplane.ResolveAddrPort(internal)
	if err != nil {
		return addr.Host{}, fmt.Errorf("parsing internal address: %w", err)
	}
	return addr.HostIP(ap.Addr()), nil
}
