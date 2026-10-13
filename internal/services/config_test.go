package services

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
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
// addresses resolve.
func TestNodeConfigResolve(t *testing.T) {
	rc, err := nodeConfig().resolve()
	if err != nil {
		t.Fatalf("resolving the minimal core: %v", err)
	}
	if want := netip.MustParseAddrPort(DefaultControl); rc.controlAddr != want {
		t.Errorf("the control address = %v, want %v", rc.controlAddr, want)
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

	// The core role with a neighbor joins: the founding refusal is gone.
	joining := nodeConfig()
	joining.Neighbors = []string{"192.0.2.7:30043"}
	if _, err := joining.resolve(); err != nil {
		t.Fatalf("resolving a joining core: %v", err)
	}

	// Both methods of the selector parse.
	for _, spec := range []string{
		"cidrs=192.0.2.0/24,198.51.100.0/24",
		"telegram=-1002147483647:7481532:AAFtoken",
	} {
		cfg := nodeConfig()
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
		"unparsable internal": func(c *NodeConfig) { c.Internal = "127.0.0.1" },
		"unparsable control":  func(c *NodeConfig) { c.Control = "nope" },
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
