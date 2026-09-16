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
)

// Default run arguments: a restart needs none of them (ADR-0006).
const (
	// DefaultState is the state directory's default.
	DefaultState = "/var/lib/cion"
	// DefaultInternal is the internal address's default.
	DefaultInternal = "127.0.0.1:30042"
	// DefaultControl is the control address's default.
	DefaultControl = "127.0.0.1:30043"
)

// NodeConfig is the node's run arguments — everything the retiring
// configuration file carried, as arguments with defaults: identity, links,
// and the forwarding key come from the state directory, where the first
// start generates them (ADR-0006).
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
	// additional entries, idempotent by remote address.
	Neighbors []string
	// State is the state directory; Internal and Control are the bind
	// addresses.
	State    string
	Internal string
	Control  string
	// AllowIA optionally restricts enrollment on the core and link admission
	// everywhere; open when unset.
	AllowIA []string
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
	Discovery       time.Duration // greeting interval
	Propagation     time.Duration // beacon origination and propagation
	Registration    time.Duration // segment registration
	Enrollment      time.Duration // enrollment retry
	Selection       time.Duration // selection evaluation window
	CandidateWindow time.Duration // unproven candidate lifetime
	Directory       time.Duration // directory publish and fetch
	RendezvousRate  time.Duration // admission rate caps
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
	if c.State == "" || c.Internal == "" || c.Control == "" {
		return fmt.Errorf("--state, --internal, and --control are required")
	}
	for _, s := range c.Neighbors {
		if _, err := netip.ParseAddrPort(s); err != nil {
			return fmt.Errorf("parsing --neighbor %q: %w", s, err)
		}
	}
	for _, s := range c.AllowIA {
		if _, err := addr.ParseIA(s); err != nil {
			return fmt.Errorf("parsing --allow-ia %q: %w", s, err)
		}
	}
	return nil
}

// ConfigWireguard is the WireGuard application's configuration file. See
// proposal 0006; the section moved out of the retiring node file (ADR-0006).
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

// parseAllowIA parses the admission allowlist into a set.
func parseAllowIA(ias []string) (map[addr.IA]bool, error) {
	if len(ias) == 0 {
		return nil, nil
	}
	allow := make(map[addr.IA]bool, len(ias))
	for _, s := range ias {
		ia, err := addr.ParseIA(s)
		if err != nil {
			return nil, fmt.Errorf("parsing allowlisted ISD-AS %q: %w", s, err)
		}
		allow[ia] = true
	}
	return allow, nil
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
