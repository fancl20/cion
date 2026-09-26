package services

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/trust"
)

// setupCoordination assembles the coordination application (ADR-0011,
// proposal 0022) on the core beside the WireGuard application, when the
// node's arguments name a wireguard configuration — the core alone holds
// the directory store whose shape implies the service. The application
// owns no listener: it hands the node's assembly its HTTP surface — the
// key fetch, the noise upgrade, the relay — which assembleHTTPS mounts on
// the node's HTTPS server over the core's WebPKI identity (proposal 0023).
func (n *node) setupCoordination() error {
	if n.ident.asType != trust.ASTypeCore || n.wireguard == nil {
		return nil
	}
	registry := n.wireguard.Registry()
	if registry == nil {
		return errors.New("the core's wireguard application holds no store to coordinate")
	}
	coordCfg := coordination.Config{
		Domain:     n.cfg.Domain,
		Store:      registry,
		Authorizer: n.enrollAuth,
		DERP:       n.relayAdvertisement(),
		StateDir:   filepath.Join(n.cfg.State, "coordination"),
	}
	if o := n.cfg.Coordination; o != nil {
		coordCfg.RelayOnly = o.RelayOnly
	}
	app, err := coordination.New(coordCfg)
	if err != nil {
		return fmt.Errorf("assembling the coordination application: %w", err)
	}
	n.coordination = app
	return nil
}

// relayAdvertisement names the relay the netmap carries: the core's
// coordination endpoint on its own identity, the one region every host's
// map holds. The production derivation is the core's domain at the HTTPS
// port; the harness's placement overrides it.
func (n *node) relayAdvertisement() coordination.DERPConfig {
	derp := coordination.DERPConfig{HostName: n.cfg.Domain}
	if o := n.cfg.Coordination; o != nil && o.DERP.URL != "" {
		parsed, err := url.Parse(o.DERP.URL)
		if err != nil {
			return derp
		}
		derp.HostName = parsed.Hostname()
		if port, err := strconv.Atoi(parsed.Port()); err == nil {
			derp.Port = port
		}
		derp.IPv4 = o.DERP.IPv4
		derp.CertName = o.DERP.CertName
	}
	return derp
}
