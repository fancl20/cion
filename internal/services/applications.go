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

// appEnvironment builds the node's facts the entries' constructors adapt: the
// identity and role, the state root, the control host, the domain and the
// HTTPS server's origin, the trust engine and path provider, the
// memberships, the sending conn, the node's bus, the service-socket
// registration, the admission authorizer, the founder route the joiner's
// directory fetch rides, the relay derivation's inputs with the harness's
// placement among them, the directory pacing, the control plane's TRC
// decision the voting application hands its submissions to, the
// control-endpoint mounting behind the peer-identity middleware, and the
// HTTPS server's mounting. The environment's core flag marks the founding
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
		HTTPSOrigin:     n.cfg.httpsOrigin(),
		Engine:          n.engine,
		Paths:           n.pathProvider,
		Memberships:     n.members.List,
		NewConn:         func() (*scion.Conn, error) { return n.scionConn(0) },
		Bus:             n.bus,
		RegisterSvc:     n.registerSvc,
		UnregisterSvc:   n.unregisterSvc,
		Authorizer:      n.cfg.enrollAuth,
		TRCDecision:     n.trcDecision,
		RemoveNode:      n.removeNode,
		FounderRoute:    n.founderRoute,
		DirectoryPacing: n.cfg.Pacing.Directory,
		MountControlEndpoint: func(pattern string, handler http.Handler) {
			n.services.Mounts = append(n.services.Mounts, scionrpc.Mount{
				Pattern: pattern, Handler: handler,
			})
		},
		MountHTTPS: n.mountHTTPS,
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
