package services

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
)

// Default run arguments: a restart needs none of them.
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
// configuration file carried, as arguments with defaults: identity, links, and
// the forwarding key come from the state directory, where the first start
// generates them.
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
	// LinkSet points at the file provider's link-set: neighbor ISD-ASes with the
	// links' two underlay addresses, reconciled into the store as the operator's
	// vouch. It refuses to combine with --neighbor, and it never carries
	// identity, keys, or bind addresses — those stay run arguments and state.
	LinkSet string
	// State is the state directory; Internal and Control are the bind
	// addresses.
	State    string
	Internal string
	Control  string
	// EnrollAuth selects the enrollment authorizer that gates first issuance,
	// "method=spec": "cidrs" with a comma-separated prefix list, "telegram" with
	// <chat>:<token>. Empty is open enrollment — the zero-conf default — and the
	// argument refuses to load off the core, the only node that issues chains.
	EnrollAuth string
	// TelegramAPI overrides the Telegram Bot API's base URL for the
	// telegram method of EnrollAuth; empty uses the public one. The
	// integration tests point it at their local double.
	TelegramAPI string
	// HostPort is the shared host-facing UDP port every host dials. It alone
	// decides whether the node serves hosts: zero runs no WireGuard or SOCKS
	// application, and the directory assigns the slice their addresses come
	// from.
	HostPort uint16
	// Coordination overrides the coordination endpoint's placement for the
	// integration harness: the loopback address its core serves on and the relay
	// every node's presence dials, standing in for the production derivation from
	// the core's domain. Nil serves the endpoint on the core's control host at
	// the default port.
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
		if c.Core {
			return fmt.Errorf("--domain is required: the core's own, " +
				"the WebPKI identity of its certificate")
		}
		return fmt.Errorf("--domain is required: the network's core domain, " +
			"the WebPKI identity of the enrollment and TRC fetch")
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
			return fmt.Errorf("--enroll-auth requires the core role: " +
				"the core is the only node that issues chains")
		}
		if _, _, err := loadEnrollAuth(c.EnrollAuth, c.TelegramAPI, c.State); err != nil {
			return fmt.Errorf("parsing --enroll-auth: %w", err)
		}
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
