package services

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/webpki"
)

// assembleHTTPS binds the node's HTTPS server: the one server that holds
// internet HTTPS's port, presents the core's WebPKI identity, and answers the
// ACME TLS-ALPN challenge beside whatever protocols the mounted apps speak.
// The identity is every core's already; here, after the applications assemble,
// the node knows the handlers it carries and binds the address it names. The
// ACME-managed identity binds for the challenge alone when no app contributes
// handlers, and a static-file identity on a core whose apps mount nothing
// leaves the port unbound, as the tree behaves today. The listener is held
// here, before start launches the serving loop and the certificate
// maintenance, so a first issuance's probe finds the port answered by
// structure rather than by retry.
func (n *node) assembleHTTPS() error {
	if n.certMgr == nil {
		// A non-core holds no WebPKI identity to serve.
		return nil
	}
	mux := http.NewServeMux()
	mounted := false
	if n.coordination != nil {
		mux.Handle("/", n.coordination.Handler())
		mounted = true
	}
	if !mounted && !n.certMgr.ACMEManaged() {
		// Static files with nothing to serve bind nothing — the offline
		// deployment's shape, as it is today.
		return nil
	}
	addr, err := n.httpsBindAddr()
	if err != nil {
		return err
	}
	ln, err := n.certMgr.ListenHTTPS(addr)
	if err != nil {
		return err
	}
	n.httpsLn = ln
	n.httpsHandler = mux
	return nil
}

// httpsBindAddr names the address the HTTPS server binds: the integration
// harness's placement when it names one — its loopback bind standing in
// for the core's domain — else the core's control host at the HTTPS port.
// A wildcard control address refuses the boot: the published endpoint
// would name an address no host could dial.
func (n *node) httpsBindAddr() (string, error) {
	if o := n.cfg.Coordination; o != nil && o.Addr != "" {
		return o.Addr, nil
	}
	listenHost, err := dataplane.ResolveAddrPort(n.cfg.Control)
	if err != nil {
		return "", fmt.Errorf("parsing the control address: %w", err)
	}
	if listenHost.Addr().IsUnspecified() {
		return "", errors.New("the coordination endpoint needs a specific host: " +
			"a wildcard control address would publish an endpoint no host could dial")
	}
	return net.JoinHostPort(listenHost.Addr().String(), webpki.HTTPSPort), nil
}
