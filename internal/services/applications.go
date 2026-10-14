package services

import (
	"fmt"
	"net/http"

	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
)

// setupApplications constructs the applications resolve selected, in table
// order — the WireGuard application first, its borrowers after — the
// environment built once from the node's phases and the loaded set growing
// as the constructors return, so each borrower finds the owner's exported
// surface beside it. Each registers its release as it loads, so the group
// releases the borrowers before the machinery they borrow.
func (n *node) setupApplications() error {
	env := n.appEnvironment()
	for _, e := range n.cfg.apps {
		app, err := e.New(env, n.apps)
		if err != nil {
			return fmt.Errorf("assembling the %s application: %w", e.Name, err)
		}
		n.group.Own(e.Name+" application", func() error {
			app.Close()
			return nil
		})
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
// peer-identity middleware. The environment's core flag marks the founding
// tier alone: a joining core runs the applications a local node runs, its
// WireGuard application publishing to and fetching from the founder's
// directory.
func (n *node) appEnvironment() *apps.Environment {
	env := &apps.Environment{
		Arguments:       n.cfg.AppArguments,
		IA:              n.ident.ia,
		Core:            n.cfg.role == trust.ASTypeCore,
		StateRoot:       n.cfg.State,
		ControlHost:     n.cfg.controlAddr.String(),
		Domain:          n.cfg.Domain,
		Engine:          n.engine,
		Paths:           n.pathProvider,
		NewConn:         func() (*scion.Conn, error) { return n.scionConn(0) },
		InterfaceDown:   n.ifDown,
		RegisterSvc:     n.registerSvc,
		UnregisterSvc:   n.unregisterSvc,
		Authorizer:      n.cfg.enrollAuth,
		TRCDecision:     n.trcDecision,
		CoreRoute:       n.coreRoute,
		DirectoryPacing: n.cfg.Pacing.Directory,
		MountControlEndpoint: func(pattern string, handler http.Handler) {
			n.services.Mounts = append(n.services.Mounts, scionrpc.Mount{
				Pattern: pattern, Handler: handler,
			})
		},
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
