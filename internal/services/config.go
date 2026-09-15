package services

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/trust"
)

// Config is the configuration of a CION node. See configs/sample.json.
type Config struct {
	// IA is the ISD-AS identifier of this node, e.g. "20-ff00:0:1". The ISD
	// should come from the private range 16-63.
	IA string `json:"ia"`
	// ASType is the tiered role of the node: core, authoritative, or normal.
	ASType string `json:"asType"`
	// State is the directory for the node's state: key material and the
	// trust database.
	State string `json:"state"`
	// Internal is the UDP address the router listens on for traffic from
	// hosts in the local AS, e.g. "127.0.0.1:30041".
	Internal string `json:"internal"`
	// Control is the UDP address the control service listens on and
	// advertises to neighbors, e.g. "127.0.0.1:30043".
	Control string `json:"control"`
	// Key is the hex-encoded secret key used for hop field MAC computation.
	Key string `json:"key"`
	// Interfaces are the external links to neighboring ASes.
	Interfaces []ConfigInterface `json:"interfaces"`
	// Domain is the DNS domain this core serves its control endpoint for
	// (core only). It is a TLS identity, never resolved.
	Domain string `json:"domain"`
	// CertFile and KeyFile are the TLS certificate for the control endpoint
	// (core only, optional). Without them the certificate is managed via
	// ACME, which needs publicly reachable TCP ports 80 and 443.
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	// CoreDomain is the DNS domain of the core this node enrolls with
	// (non-core only).
	CoreDomain string `json:"coreDomain"`
	// AllowIAS optionally restricts enrollment to the listed ISD-ASes; the
	// core rejects and logs requests from any other ISD-AS (core only).
	AllowIAS []string `json:"allowIAS"`
	// Gateway configures the WireGuard gateway application (proposal 0006);
	// a node without the section runs no gateway.
	Gateway *ConfigGateway `json:"gateway"`
}

// ConfigGateway is the gateway application's configuration section. See
// proposal 0006.
type ConfigGateway struct {
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
	Peers []ConfigGatewayPeer `json:"peers"`
}

// ConfigGatewayPeer is one host's entry in the gateway configuration.
type ConfigGatewayPeer struct {
	// PublicKey is the host's 32-byte WireGuard public key, hexadecimal.
	PublicKey string `json:"publicKey"`
	// Address is the host's overlay address inside the subnet.
	Address string `json:"address"`
	// Exit is the exit ISD-AS the host sends through.
	Exit string `json:"exit"`
}

type ConfigInterface struct {
	// ID is the SCION interface ID of this link.
	ID uint16 `json:"id"`
	// Local is the UDP address to send and receive on, e.g. "192.0.2.1:50000".
	Local string `json:"local"`
	// Remote is the UDP address of the neighbor router, e.g. "192.0.2.2:50000".
	Remote string `json:"remote"`
	// NeighborIA is the ISD-AS of the neighbor, e.g. "20-ff00:0:2".
	NeighborIA string `json:"neighborIA"`
}

// LoadConfig reads and validates the node configuration from the JSON file
// at the given path.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("missing --config flag")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.IA == "" || cfg.Internal == "" {
		return nil, fmt.Errorf("config must set ia and internal")
	}
	if cfg.ASType == "" || cfg.State == "" {
		return nil, fmt.Errorf("config must set asType and state")
	}
	return cfg, nil
}

// parseIdentity returns the node's decoded self: what every assembly phase
// needs from the configuration.
func parseIdentity(cfg *Config) (identity, error) {
	ia, err := addr.ParseIA(cfg.IA)
	if err != nil {
		return identity{}, fmt.Errorf("parsing IA: %w", err)
	}
	asType, err := trust.ParseASType(cfg.ASType)
	if err != nil {
		return identity{}, err
	}
	key, err := decodeKey(cfg.Key)
	if err != nil {
		return identity{}, err
	}
	localHost, err := parseInternalHost(cfg.Internal)
	if err != nil {
		return identity{}, err
	}
	return identity{ia: ia, asType: asType, key: key, localHost: localHost}, nil
}

// decodeKey decodes the hex-encoded forwarding key.
func decodeKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}
	return key, nil
}

// parseAllowIAS parses the enrollment allowlist into a set.
func parseAllowIAS(ias []string) (map[addr.IA]bool, error) {
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

// parseInternalHost returns the local host address derived from the internal
// address.
func parseInternalHost(internal string) (addr.Host, error) {
	ap, err := dataplane.ResolveAddrPort(internal)
	if err != nil {
		return addr.Host{}, fmt.Errorf("parsing internal address: %w", err)
	}
	return addr.HostIP(ap.Addr()), nil
}
