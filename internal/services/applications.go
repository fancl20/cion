package services

import (
	"fmt"
	"net/http"

	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/scion"
)

// setupApplications resolves the applications the run arguments select
// and constructs the loaded in table order — the WireGuard application
// first, its borrowers after — the environment built once from the node's
// phases and the loaded set growing as the constructors return, so each
// borrower finds the owner's exported surface beside it. Validate already
// refused the miscombinations; whatever loads here was named or implied.
func (n *node) setupApplications() error {
	selected, err := apps.Select(n.cfg.Applications, n.cfg.Core, n.cfg.AppArguments)
	if err != nil {
		return err
	}
	env := n.appEnvironment()
	for _, e := range selected {
		app, err := e.New(env, n.apps)
		if err != nil {
			return fmt.Errorf("assembling the %s application: %w", e.Name, err)
		}
		n.apps = append(n.apps, apps.Loaded{Name: e.Name, App: app})
	}
	return nil
}

// appEnvironment builds the node's facts the entries' constructors adapt:
// the identity and role, the state root, the control host, the domain,
// the trust engine and path provider, the sending conn and the
// interface-down cache, the service-socket registration, the admission
// authorizer, the core route the joiner's directory fetch rides, the
// relay derivation's inputs with the harness's placement among them, the
// directory pacing, the control plane's TRC decision the voting application
// hands its submissions to, and the control-endpoint mounting behind the
// peer-identity middleware.
func (n *node) appEnvironment() *apps.Environment {
	env := &apps.Environment{
		Arguments:       n.cfg.AppArguments,
		IA:              n.ident.ia,
		Core:            n.cfg.Core,
		StateRoot:       n.cfg.State,
		ControlHost:     n.cfg.Control,
		Domain:          n.cfg.Domain,
		Engine:          n.engine,
		Provider:        n.pathProvider,
		NewConn:         func() (*scion.Conn, error) { return n.scionConn(0) },
		InterfaceDown:   n.ifDown,
		RegisterSvc:     n.registerSvc,
		UnregisterSvc:   n.unregisterSvc,
		Authorizer:      n.enrollAuth,
		CoreRoute:       n.coreRoute,
		DirectoryPacing: n.cfg.Pacing.Directory,
		MountControlEndpoint: func(pattern string, handler http.Handler) error {
			if n.services == nil {
				return fmt.Errorf("the control endpoint is not assembled")
			}
			n.services.Mounts = append(n.services.Mounts, controlplane.Mount{
				Pattern: pattern, Handler: handler,
			})
			return nil
		},
	}
	// The typed-nil guard: a nil decider must read as no decision wired,
	// not as a decision that would panic under the application's nil check.
	if n.decider != nil {
		env.TRCDecision = n.decider
	}

	if o := n.cfg.Coordination; o != nil {
		env.Relay = apps.RelayPlacement{
			URL:       o.DERP.URL,
			IPv4:      o.DERP.IPv4,
			CertName:  o.DERP.CertName,
			RelayOnly: o.RelayOnly,
		}
	}
	return env
}
