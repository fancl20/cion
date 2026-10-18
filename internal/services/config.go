package services

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/netip"
	"time"

	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
	measured "github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// Default run arguments: a restart needs none of them.
const (
	// DefaultState is the state directory's default.
	DefaultState = "/var/lib/cion"
	// DefaultInternal is the internal address's default: the loopback at the
	// underlay block's bottom, the port that binds the node alone — a peer
	// cannot observe the internal link's number.
	DefaultInternal = "127.0.0.1:30044"
	// DefaultControl is the control address's default; its host carries the
	// control endpoint, the rendezvous acceptor, and the coordination
	// listener, each at the port the underlay block's ladder fixes.
	DefaultControl = "127.0.0.1:30042"
)

// NodeConfig is the node's run arguments — everything the retiring
// configuration file carried, as arguments with defaults: identity, links, and
// the forwarding key come from the state directory, where the first start
// generates them.
type NodeConfig struct {
	// Core marks the core role: founding without a neighbor — TRC genesis,
	// issuer, self-enrollment — and joining with one, as an authoritative
	// core the founder onboards by sensitive TRC update.
	Core bool
	// Domain is the core's WebPKI identity — the founding core's own when
	// Core is set without a neighbor (with AcmeEmail optional and the
	// certificate files as the offline fallback), the network's core
	// identity otherwise.
	Domain    string
	AcmeEmail string
	CertFile  string
	KeyFile   string
	// Neighbors are existing nodes' rendezvous underlay addresses; the first
	// start of a non-core requires at least one, later starts seed
	// additional entries, idempotent by remote address. They select the
	// measured topology provider, which loads by default. On the core role
	// they decide the tier: a core with a neighbor joins the neighbor's ISD
	// as an authoritative core instead of founding its own.
	Neighbors []string
	// LinkSet points at the file provider's link-set: neighbor ISD-ASes with the
	// links' two underlay addresses, reconciled into the store as the operator's
	// vouch. It refuses to combine with --topology.neighbor, and it never carries
	// identity, keys, or bind addresses — those stay run arguments and state.
	LinkSet string
	// State is the state directory; Internal and Control are the bind
	// addresses.
	State    string
	Internal string
	Control  string
	// EnrollAuth selects the enrollment authorizer that gates first issuance,
	// host registration, and the founding core's sensitive vote on a core's
	// TRC submission, "method=spec": "cidrs" with a comma-separated prefix
	// list, "telegram" with <chat>:<token>. Empty is open enrollment and
	// registration — the zero-conf default — with the vote denied, and the
	// argument refuses to load off the founding core, the only node that
	// issues chains.
	EnrollAuth string
	// TelegramAPI overrides the Telegram Bot API's base URL for the
	// telegram method of EnrollAuth; empty uses the public one. The
	// integration tests point it at their local double.
	TelegramAPI string
	// Applications selects the resident applications by name: nil keeps the
	// inference — an application loads when its role bounds hold, its
	// requirements load, and its required arguments are present; the empty
	// list runs the deliberate core, no application at all; a given list
	// loads exactly the named, in table order whatever order the list
	// spells. resolve refuses every miscombination with the fix named.
	Applications []string
	// AppArguments carries the resident applications' own run arguments,
	// one block per entry; the commands register them from the
	// applications table.
	AppArguments apps.Arguments
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
	Propagation       time.Duration // beacon origination and propagation
	Registration      time.Duration // segment registration
	Enrollment        time.Duration // enrollment retry; the rotation watch's retry and inspection
	EnrollmentInspect time.Duration // enrollment inspection of a valid chain
	Selection         time.Duration // selection evaluation window
	CandidateWindow   time.Duration // unproven candidate lifetime
	Directory         time.Duration // directory publish, its retry, and fetch
	RendezvousRate    time.Duration // admission rate caps (rendezvous, link, and enrollment doors)
	LinkSetPoll       time.Duration // the file provider's link-set poll
	BFD               time.Duration // BFD transmission interval
	RotationThreshold time.Duration // remaining validity below which the rotation watch rolls
}

// resolvedConfig is the run arguments resolved once at boot: the NodeConfig
// beside what every phase reads from it, derived and checked a single time.
type resolvedConfig struct {
	NodeConfig
	// role is the node's tier: the founding core for the core flag without
	// a neighbor, the authoritative core with one, the normal node without
	// the flag. The state directory plays no part, so a restart keeps its
	// tier by spelling the same arguments.
	role trust.ASType
	// controlAddr and internalAddr are the control and internal addresses.
	// A host name in either resolves here, so every conn and generation
	// binds the one answer.
	controlAddr  netip.AddrPort
	internalAddr netip.AddrPort
	// enrollAuth gates the trust service's first issuance, the coordination
	// application's registrations, and the TRC decision's sensitive vote;
	// nil leaves the first two open and denies the vote. enrollRun runs the
	// selected method's own loops — the Telegram authorizer's poll — nil
	// when the method has none.
	enrollAuth enrollauth.AdmissionAuthorizer
	enrollRun  func(context.Context)
	// apps is the selected resident applications, in table order.
	apps []apps.Entry
}

// resolve applies the role-aware argument checks and resolves the run
// arguments once: the domain is always required, the role derives from the
// core flag and the neighbors, and the gate and the core-bound applications
// load on the founding core alone. The authorizer is built and the
// applications selected here, so a malformed spec or a miscombination fails
// the boot before any assembly runs.
func (c NodeConfig) resolve() (resolvedConfig, error) {
	r := resolvedConfig{NodeConfig: c}
	if c.Core {
		r.role = trust.ASTypeCore
		if len(c.Neighbors) > 0 {
			r.role = trust.ASTypeAuthoritative
		}
	}
	founding := r.role == trust.ASTypeCore
	if c.Domain == "" {
		if founding {
			return resolvedConfig{}, fmt.Errorf("--trust.domain is required: the founding " +
				"core's own, the WebPKI identity of its certificate")
		}
		return resolvedConfig{}, fmt.Errorf("--trust.domain is required: the network's core " +
			"identity")
	}
	if c.LinkSet != "" && len(c.Neighbors) > 0 {
		return resolvedConfig{}, fmt.Errorf("--topology.link-set refuses --topology.neighbor: " +
			"one topology provider per process, the static and the measured")
	}
	if c.State == "" || c.Internal == "" || c.Control == "" {
		return resolvedConfig{}, fmt.Errorf("--state, --internal, and --control are required")
	}
	for _, s := range c.Neighbors {
		if _, err := measured.ParseRendezvousAddr(s); err != nil {
			return resolvedConfig{}, fmt.Errorf("parsing --topology.neighbor %q: %w", s, err)
		}
	}
	var err error
	if r.controlAddr, err = underlay.ResolveAddrPortDefault(
		c.Control, scionrpc.EndpointPort); err != nil {
		return resolvedConfig{}, fmt.Errorf("parsing control address: %w", err)
	}
	if r.internalAddr, err = underlay.ResolveAddrPortDefault(
		c.Internal, netip.MustParseAddrPort(DefaultInternal).Port()); err != nil {
		return resolvedConfig{}, fmt.Errorf("parsing internal address: %w", err)
	}
	if c.EnrollAuth != "" {
		// A silently inert gate is the misleading configuration the
		// role-aware checks exist to refuse: only the founding core issues
		// chains, so only the founding core's gate means anything.
		if !founding {
			return resolvedConfig{}, fmt.Errorf("--trust.enroll-auth requires the founding core: " +
				"the founding core is the only node that issues chains")
		}
		r.enrollAuth, r.enrollRun, err = loadEnrollAuth(c.EnrollAuth, c.TelegramAPI, c.State)
		if err != nil {
			return resolvedConfig{}, fmt.Errorf("parsing --trust.enroll-auth: %w", err)
		}
	}
	if r.apps, err = apps.Select(c.Applications, founding, c.AppArguments); err != nil {
		return resolvedConfig{}, err
	}
	return r, nil
}
