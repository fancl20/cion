package services

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// nodeConfig builds a minimal valid run-argument set for the validation and
// parsing tests.
func nodeConfig() NodeConfig {
	return NodeConfig{
		Core:     true,
		Domain:   webpkitest.Domain,
		State:    "/var/lib/cion",
		Internal: DefaultInternal,
		Control:  DefaultControl,
	}
}

// TestNodeConfigResolve checks the role-aware argument checks: the domain
// is always required, the joining core takes its neighbor, and the
// addresses resolve — the default control address the bare wildcard, its
// port derived from the endpoint's.
func TestNodeConfigResolve(t *testing.T) {
	rc, err := nodeConfig().resolve()
	if err != nil {
		t.Fatalf("resolving the minimal core: %v", err)
	}
	if want := (netip.AddrPortFrom(netip.MustParseAddr(DefaultControl), 30042)); rc.controlAddr != want {
		t.Errorf("the control address = %v, want the wildcard at the endpoint's port %v",
			rc.controlAddr, want)
	}
	if want := netip.MustParseAddrPort(DefaultInternal); rc.internalAddr != want {
		t.Errorf("the internal address = %v, want %v", rc.internalAddr, want)
	}

	cfg := nodeConfig()
	cfg.Core = false
	cfg.Neighbors = []string{"192.0.2.7:30043"}
	if _, err := cfg.resolve(); err != nil {
		t.Fatalf("resolving a joiner: %v", err)
	}

	// A bare host names the argument's default port: the control and
	// internal addresses their defaults, a neighbor the fixed rendezvous
	// port.
	bare := nodeConfig()
	bare.Core = false
	bare.Control = "192.0.2.7"
	bare.Internal = "192.0.2.7"
	bare.Neighbors = []string{"192.0.2.9"}
	rc, err = bare.resolve()
	if err != nil {
		t.Fatalf("resolving bare hosts: %v", err)
	}
	if want := netip.MustParseAddrPort("192.0.2.7:30042"); rc.controlAddr != want {
		t.Errorf("the bare control address = %v, want %v", rc.controlAddr, want)
	}
	if want := netip.MustParseAddrPort("192.0.2.7:30044"); rc.internalAddr != want {
		t.Errorf("the bare internal address = %v, want %v", rc.internalAddr, want)
	}

	// A founding address identity stands on its own: the control host's
	// address or another one, the public face a NAT forwards; a joiner names
	// the network's identity whatever its grammar, and no control host of its
	// own is asked.
	ownAddress := nodeConfig()
	ownAddress.Domain = "127.0.0.1"
	if _, err := ownAddress.resolve(); err != nil {
		t.Fatalf("resolving the control host's own address as the identity: %v", err)
	}
	nattedAddress := nodeConfig()
	nattedAddress.Domain = "192.0.2.9"
	if _, err := nattedAddress.resolve(); err != nil {
		t.Fatalf("resolving an address identity beyond the control host: %v", err)
	}
	joinerAddress := nodeConfig()
	joinerAddress.Core = false
	joinerAddress.Neighbors = []string{"192.0.2.7:30043"}
	joinerAddress.Domain = "198.51.100.2"
	if _, err := joinerAddress.resolve(); err != nil {
		t.Fatalf("resolving a joiner's address identity: %v", err)
	}

	// The core role with a neighbor joins: the founding refusal is gone.
	joining := nodeConfig()
	joining.Neighbors = []string{"192.0.2.7:30043"}
	if _, err := joining.resolve(); err != nil {
		t.Fatalf("resolving a joining core: %v", err)
	}

	// Every method of the selector parses.
	for _, spec := range []string{
		"cidrs=192.0.2.0/24,198.51.100.0/24",
		"telegram=-1002147483647:7481532:AAFtoken",
		"portal",
	} {
		cfg := nodeConfig()
		cfg.State = t.TempDir()
		cfg.EnrollAuth = spec
		if _, err := cfg.resolve(); err != nil {
			t.Errorf("resolving %q: %v", spec, err)
		}
	}

	bad := map[string]func(*NodeConfig){
		"missing domain":      func(c *NodeConfig) { c.Domain = "" },
		"missing state":       func(c *NodeConfig) { c.State = "" },
		"bad neighbor":        func(c *NodeConfig) { c.Core = false; c.Neighbors = []string{"nope"} },
		"missing internal":    func(c *NodeConfig) { c.Internal = "" },
		"unparsable internal": func(c *NodeConfig) { c.Internal = "192.0.2.1:99999" },
		"unparsable control":  func(c *NodeConfig) { c.Control = "192.0.2.1:99999" },
		"enroll-auth without the founding core": func(c *NodeConfig) {
			c.Neighbors = []string{"192.0.2.7:30043"}
			c.EnrollAuth = "cidrs=192.0.2.0/24"
		},
		"unknown enroll-auth method": func(c *NodeConfig) {
			c.EnrollAuth = "carrier-pigeon=coop"
		},
		"enroll-auth without method": func(c *NodeConfig) {
			c.EnrollAuth = "192.0.2.0/24"
		},
		"empty prefix list": func(c *NodeConfig) {
			c.EnrollAuth = "cidrs="
		},
		"unparsable prefix": func(c *NodeConfig) {
			c.EnrollAuth = "cidrs=192.0.2.0/24,nope"
		},
		"unparsable chat": func(c *NodeConfig) {
			c.EnrollAuth = "telegram=chat:7481532:AAFtoken"
		},
		"chat without token": func(c *NodeConfig) {
			c.EnrollAuth = "telegram=-1002147483647:"
		},
		"portal with a spec": func(c *NodeConfig) {
			c.EnrollAuth = "portal=/admin"
		},
		"link-set plus neighbor": func(c *NodeConfig) {
			c.Core = false
			c.LinkSet = "/tmp/link-set.json"
			c.Neighbors = []string{"192.0.2.7:30043"}
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := nodeConfig()
			mutate(&cfg)
			if _, err := cfg.resolve(); err == nil {
				t.Error("the malformed run arguments were accepted")
			}
		})
	}
}

// TestHTTPSOrigin checks the HTTPS server's origin: the domain over HTTPS,
// the harness placement's port joining it unless it is HTTPS's own.
func TestHTTPSOrigin(t *testing.T) {
	for _, tc := range []struct {
		placement *CoordinationOptions
		want      string
	}{
		{nil, "https://" + webpkitest.Domain},
		{&CoordinationOptions{}, "https://" + webpkitest.Domain},
		{&CoordinationOptions{Addr: "127.0.0.1:443"}, "https://" + webpkitest.Domain},
		{&CoordinationOptions{Addr: "127.0.0.1:8443"}, "https://" + webpkitest.Domain + ":8443"},
	} {
		cfg := nodeConfig()
		cfg.Coordination = tc.placement
		if got := cfg.httpsOrigin(); got != tc.want {
			t.Errorf("the origin under the placement %+v = %q, want %q", tc.placement, got, tc.want)
		}
	}
}

// TestNodeConfigResolveApplications checks the applications list's
// regimes and refusals where every role-aware check reads them, at
// resolve and before any assembly runs.
func TestNodeConfigResolveApplications(t *testing.T) {
	// The inference and the deliberate core need no list at all: an unset
	// list with refused arguments loads nothing, an empty one states it.
	if _, err := nodeConfig().resolve(); err != nil {
		t.Fatalf("an unset list with the port refused: %v", err)
	}
	deliberate := nodeConfig()
	deliberate.Applications = []string{}
	if _, err := deliberate.resolve(); err != nil {
		t.Fatalf("the deliberate core: %v", err)
	}
	serving := nodeConfig()
	serving.AppArguments.Wireguard.HostPort = apps.DefaultHostPort
	if _, err := serving.resolve(); err != nil {
		t.Fatalf("the inference with the port given: %v", err)
	}

	refusals := map[string]struct {
		mutate func(*NodeConfig)
		want   string
	}{
		"an unknown name": {
			func(c *NodeConfig) { c.Applications = []string{"middlebox"} },
			"the residents are wireguard, coordination, socks",
		},
		"coordination off the core": {
			func(c *NodeConfig) {
				c.Core = false
				c.Applications = []string{"coordination", "wireguard"}
				c.AppArguments.Wireguard.HostPort = apps.DefaultHostPort
			},
			"coordination, which requires the founding core",
		},
		"voting on a joining core": {
			func(c *NodeConfig) {
				c.Neighbors = []string{"192.0.2.7:30043"}
				c.Applications = []string{"voting"}
			},
			"voting, which requires the founding core",
		},
		"socks without wireguard": {
			func(c *NodeConfig) { c.Applications = []string{"socks"} },
			"requires wireguard beside it",
		},
		"coordination without wireguard": {
			func(c *NodeConfig) { c.Applications = []string{"coordination"} },
			"requires wireguard beside it",
		},
		"wireguard beside the refused port": {
			func(c *NodeConfig) { c.Applications = []string{"wireguard"} },
			"--wireguard.host-port is zero",
		},
		"the portal method without its console": {
			func(c *NodeConfig) {
				c.EnrollAuth = "portal"
				c.Applications = []string{"voting"}
			},
			"--trust.enroll-auth=portal pairs with the portal application",
		},
		"the console without its method": {
			func(c *NodeConfig) { c.Applications = []string{"portal"} },
			"portal, which pairs with --trust.enroll-auth=portal",
		},
	}
	for name, tc := range refusals {
		t.Run(name, func(t *testing.T) {
			cfg := nodeConfig()
			tc.mutate(&cfg)
			_, err := cfg.resolve()
			if err == nil {
				t.Fatal("the miscombination was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal = %q, want it to carry %q", err, tc.want)
			}
		})
	}
}

// TestNodeConfigResolveRole checks the role derives from the pair the run
// arguments spell: the core flag without a neighbor founds, with one it
// joins as an authoritative core, and without the flag the node is a
// normal one.
func TestNodeConfigResolveRole(t *testing.T) {
	neighbor := []string{"192.0.2.7:30043"}
	for _, tc := range []struct {
		name      string
		core      bool
		neighbors []string
		want      trust.ASType
	}{
		{"the core flag without a neighbor", true, nil, trust.ASTypeCore},
		{"the core flag with a neighbor", true, neighbor, trust.ASTypeAuthoritative},
		{"a neighbor without the core flag", false, neighbor, trust.ASTypeNormal},
	} {
		cfg := nodeConfig()
		cfg.Core, cfg.Neighbors = tc.core, tc.neighbors
		rc, err := cfg.resolve()
		if err != nil {
			t.Fatalf("resolving %s: %v", tc.name, err)
		}
		if rc.role != tc.want {
			t.Errorf("%s resolves %v, want %v", tc.name, rc.role, tc.want)
		}
	}
}

// TestLoadIdentityRestart checks a restart on the same arguments: the
// identity the first start persisted loads unchanged, and the role resolves
// as it did.
func TestLoadIdentityRestart(t *testing.T) {
	cfg := nodeConfig()
	cfg.State = t.TempDir()
	cfg.Neighbors = []string{"192.0.2.7:30043"}
	rc, err := cfg.resolve()
	if err != nil {
		t.Fatal(err)
	}
	first, created, err := loadIdentity(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("the first start found an identity, want a draw")
	}
	if err := trust.PersistIA(cfg.State, first.ia); err != nil {
		t.Fatal(err)
	}

	rc, err = cfg.resolve()
	if err != nil {
		t.Fatal(err)
	}
	restart, created, err := loadIdentity(rc)
	if err != nil {
		t.Fatal(err)
	}
	if created || !restart.ia.Equal(first.ia) {
		t.Errorf("the restart loaded %v (created %v), want the persisted %v",
			restart.ia, created, first.ia)
	}
	if rc.role != trust.ASTypeAuthoritative {
		t.Errorf("the restart resolves %v, want the authoritative core", rc.role)
	}
}
