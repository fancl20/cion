package services

import (
	"fmt"
	"net"
	"net/http"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki"
)

// httpsMount is one handler an application mounted on the node's HTTPS
// server: the pattern it answers and the handler.
type httpsMount struct {
	pattern string
	handler http.Handler
}

// mountHTTPS records one application handler for the node's HTTPS server,
// the environment's MountHTTPS; assembleHTTPS mounts what was recorded.
func (n *node) mountHTTPS(pattern string, handler http.Handler) {
	n.httpsMounts = append(n.httpsMounts, httpsMount{pattern: pattern, handler: handler})
}

// assembleHTTPS binds the node's HTTPS server: the one server that holds
// internet HTTPS's port, presents the core's WebPKI identity, and answers the
// ACME TLS-ALPN challenge beside whatever protocols the mounted apps speak.
// The identity is every core's already; here, after the applications
// assemble, the node knows the handlers they mounted and binds the address
// it names. Each handler answers its own pattern, so a pattern mounted twice
// refuses the boot. The ACME-managed identity binds for the challenge alone
// when nothing mounts, and a static-file identity on a core that mounts
// nothing leaves the port unbound. The listener is held here, before start
// launches the serving loop and the certificate maintenance, so a first
// issuance's probe finds the port answered by structure rather than by
// retry.
func (n *node) assembleHTTPS() error {
	if n.cfg.role != trust.ASTypeCore {
		// Only the founding core holds a WebPKI identity to serve.
		return nil
	}
	mux := http.NewServeMux()
	mounted := make(map[string]bool, len(n.httpsMounts))
	for _, m := range n.httpsMounts {
		if mounted[m.pattern] {
			return fmt.Errorf("two applications mount %s on the node's HTTPS server", m.pattern)
		}
		mounted[m.pattern] = true
		mux.Handle(m.pattern, m.handler)
	}
	if len(mounted) == 0 && !n.certMgr.ACMEManaged() {
		// Static files with nothing to serve bind nothing — the offline
		// deployment's shape.
		return nil
	}
	addr := n.httpsBindAddr()
	ln, err := n.certMgr.ListenHTTPS(addr, n.sockets)
	if err != nil {
		return err
	}
	n.group.Own("https listener", ln.Close)
	n.httpsLn = ln
	n.httpsHandler = mux
	return nil
}

// httpsBindAddr names the address the HTTPS server binds: the integration
// harness's placement when it names one — its loopback bind standing in
// for the core's domain — else the core's control host at the HTTPS port,
// the wildcard binding every interface of its family: the published
// coordination endpoint names the identity, not the bind host, and the
// CA's challenges want the port held on every interface.
func (n *node) httpsBindAddr() string {
	if o := n.cfg.Coordination; o != nil && o.Addr != "" {
		return o.Addr
	}
	return net.JoinHostPort(n.cfg.controlAddr.Addr().String(), webpki.HTTPSPort)
}
