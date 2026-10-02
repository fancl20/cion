package services

import (
	"strings"
	"testing"

	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/trust"
)

// nodeConfig builds a minimal valid run-argument set for the validation and
// parsing tests.
func nodeConfig() NodeConfig {
	return NodeConfig{
		Core:     true,
		Domain:   "core.example.org",
		State:    "/var/lib/cion",
		Internal: DefaultInternal,
		Control:  DefaultControl,
	}
}

// TestNodeConfigValidate checks the role-aware argument validation: the
// domain is always required, the joining core takes its neighbor, and the
// addresses parse.
func TestNodeConfigValidate(t *testing.T) {
	if err := nodeConfig().Validate(); err != nil {
		t.Fatalf("validating the minimal core: %v", err)
	}

	cfg := nodeConfig()
	cfg.Core = false
	cfg.Neighbors = []string{"192.0.2.7:30043"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validating a joiner: %v", err)
	}

	// The core role with a neighbor joins: the founding refusal is gone.
	joining := nodeConfig()
	joining.Neighbors = []string{"192.0.2.7:30043"}
	if err := joining.Validate(); err != nil {
		t.Fatalf("validating a joining core: %v", err)
	}

	// Both methods of the selector parse.
	for _, spec := range []string{
		"cidrs=192.0.2.0/24,198.51.100.0/24",
		"telegram=-1002147483647:7481532:AAFtoken",
	} {
		cfg := nodeConfig()
		cfg.EnrollAuth = spec
		if err := cfg.Validate(); err != nil {
			t.Errorf("validating %q: %v", spec, err)
		}
	}

	bad := map[string]func(*NodeConfig){
		"missing domain":   func(c *NodeConfig) { c.Domain = "" },
		"missing state":    func(c *NodeConfig) { c.State = "" },
		"bad neighbor":     func(c *NodeConfig) { c.Core = false; c.Neighbors = []string{"nope"} },
		"missing internal": func(c *NodeConfig) { c.Internal = "" },
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
			if err := cfg.Validate(); err == nil {
				t.Error("the malformed run arguments were accepted")
			}
		})
	}
}

// TestNodeConfigValidateApplications checks the applications list's
// regimes and refusals where every role-aware check reads them, at
// Validate and before any assembly runs.
func TestNodeConfigValidateApplications(t *testing.T) {
	// The inference and the deliberate core need no list at all: an unset
	// list with refused arguments loads nothing, an empty one states it.
	if err := nodeConfig().Validate(); err != nil {
		t.Fatalf("an unset list with the port refused: %v", err)
	}
	deliberate := nodeConfig()
	deliberate.Applications = []string{}
	if err := deliberate.Validate(); err != nil {
		t.Fatalf("the deliberate core: %v", err)
	}
	serving := nodeConfig()
	serving.AppArguments.Wireguard.HostPort = apps.DefaultHostPort
	if err := serving.Validate(); err != nil {
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
			"coordination, which requires the core role",
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
			err := cfg.Validate()
			if err == nil {
				t.Fatal("the miscombination was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal = %q, want it to carry %q", err, tc.want)
			}
		})
	}
}

// TestLoadIdentityDerivesTier checks the tier derives from the pair the run
// arguments spell: the core flag without a neighbor founds, with one it joins
// as an authoritative core, the flag alone leaves the normal node, and a
// restart derives the same tier from the same arguments.
func TestLoadIdentityDerivesTier(t *testing.T) {
	cfg := func(mutate func(*NodeConfig)) NodeConfig {
		c := NodeConfig{
			Domain:   "core.example.org",
			State:    t.TempDir(),
			Internal: DefaultInternal,
			Control:  DefaultControl,
		}
		mutate(&c)
		return c
	}

	founding := cfg(func(c *NodeConfig) { c.Core = true })
	ident, created, err := loadIdentity(founding)
	if err != nil {
		t.Fatal(err)
	}
	if !created || ident.asType != trust.ASTypeCore {
		t.Errorf("the core without a neighbor = %v (created %v), want a founding first start",
			ident.asType, created)
	}

	joining := cfg(func(c *NodeConfig) {
		c.Core = true
		c.Neighbors = []string{"192.0.2.7:30043"}
	})
	ident, created, err = loadIdentity(joining)
	if err != nil {
		t.Fatal(err)
	}
	if !created || ident.asType != trust.ASTypeAuthoritative {
		t.Errorf("the core with a neighbor = %v (created %v), want an authoritative first start",
			ident.asType, created)
	}
	if err := trust.PersistIA(joining.State, ident.ia); err != nil {
		t.Fatal(err)
	}
	// The restart of the same arguments derives the same tier, the persisted
	// identity untouched by it.
	ident, created, err = loadIdentity(joining)
	if err != nil {
		t.Fatal(err)
	}
	if created || ident.asType != trust.ASTypeAuthoritative {
		t.Errorf("the authoritative restart = %v (created %v), want the same tier unpersisted",
			ident.asType, created)
	}

	local := cfg(func(c *NodeConfig) {
		c.Neighbors = []string{"192.0.2.7:30043"}
	})
	ident, _, err = loadIdentity(local)
	if err != nil {
		t.Fatal(err)
	}
	if ident.asType != trust.ASTypeNormal {
		t.Errorf("the node without the core flag = %v, want the normal tier", ident.asType)
	}
}
