package services

import (
	"testing"
)

// nodeConfig builds a minimal valid run-argument set for the validation and
// parsing tests.
func nodeConfig() NodeConfig {
	return NodeConfig{
		Core:     true,
		Domain:   "core.example.org",
		State:    "/var/lib/cion",
		Internal: "127.0.0.1:30042",
		Control:  "127.0.0.1:30043",
	}
}

// TestNodeConfigValidate checks the role-aware argument validation: the
// domain is always required, the core takes no neighbor, and the addresses
// parse.
func TestNodeConfigValidate(t *testing.T) {
	if err := nodeConfig().Validate(); err != nil {
		t.Fatalf("validating the minimal core: %v", err)
	}

	cfg := nodeConfig()
	cfg.Core = false
	cfg.Neighbors = []string{"192.0.2.7:30045"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validating a joiner: %v", err)
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
		"missing domain":     func(c *NodeConfig) { c.Domain = "" },
		"missing state":      func(c *NodeConfig) { c.State = "" },
		"core with neighbor": func(c *NodeConfig) { c.Neighbors = []string{"192.0.2.7:30045"} },
		"bad neighbor":       func(c *NodeConfig) { c.Core = false; c.Neighbors = []string{"nope"} },
		"missing internal":   func(c *NodeConfig) { c.Internal = "" },
		"enroll-auth without core": func(c *NodeConfig) {
			c.Core = false
			c.Neighbors = []string{"192.0.2.7:30045"}
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
			c.Neighbors = []string{"192.0.2.7:30045"}
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
