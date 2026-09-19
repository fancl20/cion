package services

import (
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/addr"

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
	// WireguardConfig points at the WireGuard application's own file (host
	// membership, subnets, exits); empty runs none.
	WireguardConfig string
	// RootCAs anchors the WebPKI verification of the core's domain
	// certificate; nil uses the system roots. The integration tests inject
	// their CA with it.
	RootCAs *x509.CertPool

	// Pacing shortens the loops' periods; zero values keep the production
	// constants. The daemon never sets it — the integration tests do.
	Pacing NodePacing
}

// NodePacing carries the test pacing of the node's loops.
type NodePacing struct {
	Propagation     time.Duration // beacon origination and propagation
	Registration    time.Duration // segment registration
	Enrollment      time.Duration // enrollment retry
	Selection       time.Duration // selection evaluation window
	CandidateWindow time.Duration // unproven candidate lifetime
	Directory       time.Duration // directory publish and fetch
	RendezvousRate  time.Duration // admission rate caps
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
		if _, _, err := enrollauth.Load(c.EnrollAuth, enrollauth.LoadOptions{}); err != nil {
			return fmt.Errorf("parsing --enroll-auth: %w", err)
		}
	}
	return nil
}

// ConfigWireguard is the WireGuard application's configuration file. See
// proposal 0006; the section moved out of the retiring node file (ADR-0008).
type ConfigWireguard struct {
	// Subnet is the node's overlay subnet, e.g. "10.64.1.0/24". Host
	// addresses are assigned within it by the peer configuration.
	Subnet string `json:"subnet"`
	// ListenPort is the shared host-facing UDP port every host dials.
	ListenPort uint16 `json:"listenPort"`
	// Egress marks an internet exit: the node runs the netstack egress only
	// when set.
	Egress bool `json:"egress"`
	// Exits lists the offered exit ISD-ASes, e.g. ["20-ff00:0:3"]; one host
	// device serves each.
	Exits []string `json:"exits"`
	// Peers lists the host public keys — the operator's membership list —
	// with an overlay address and an exit each.
	Peers []ConfigWireguardPeer `json:"peers"`
}

// ConfigWireguardPeer is one host's entry in the application's configuration.
type ConfigWireguardPeer struct {
	// PublicKey is the host's 32-byte WireGuard public key, hexadecimal.
	PublicKey string `json:"publicKey"`
	// Address is the host's overlay address inside the subnet.
	Address string `json:"address"`
	// Exit is the exit ISD-AS the host sends through.
	Exit string `json:"exit"`
}

// LoadWireguardConfig reads the WireGuard application's configuration from
// the JSON file at the given path; an empty path runs no application.
// Unknown fields are refused rather than silently ignored, so a file still
// naming a retired field stops here.
func LoadWireguardConfig(path string) (*ConfigWireguard, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the wireguard configuration: %w", err)
	}
	cfg := &ConfigWireguard{}
	if err := json.Unmarshal(raw, cfg, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parsing the wireguard configuration: %w", err)
	}
	return cfg, nil
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
