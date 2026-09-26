package services

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/trust"
)

// setupCoordination assembles the coordination application (ADR-0011,
// proposal 0022) on the core beside the WireGuard application, when the
// node's arguments name a wireguard configuration — the core alone holds
// the directory store whose shape implies the service. The application
// rides the core's WebPKI identity — the certificate machinery the
// endpoint's channel already holds, cloned for its own protocols — and
// answers the ACME TLS-ALPN challenge on the port it serves, so the
// dedicated challenge listener a coordination-serving core once needed
// retires with it standing on 443.
func (n *node) setupCoordination() error {
	if n.ident.asType != trust.ASTypeCore || n.wireguard == nil {
		return nil
	}
	registry := n.wireguard.Registry()
	if registry == nil {
		return errors.New("the core's wireguard application holds no store to coordinate")
	}
	addr := ""
	if n.cfg.Coordination != nil {
		addr = n.cfg.Coordination.Addr
	}
	if addr == "" {
		listenHost, err := dataplane.ResolveAddrPort(n.cfg.Control)
		if err != nil {
			return fmt.Errorf("parsing the control address: %w", err)
		}
		// The endpoint serves on the core's own host at the HTTPS port.
		if !listenHost.Addr().IsValid() || listenHost.Addr().IsUnspecified() {
			return errors.New("the coordination endpoint needs a specific host: " +
				"a wildcard control address would publish an endpoint no host could dial")
		}
		addr = net.JoinHostPort(listenHost.Addr().String(), coordination.DefaultPort)
	}
	coordCfg := coordination.Config{
		Domain:     n.cfg.Domain,
		Addr:       addr,
		TLS:        n.certMgr.TLSConfig(),
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
