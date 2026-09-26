package coordination

import (
	"log/slog"
	"net/http"

	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// derpServer is the relay fallback the client protocol expects: a DERP
// server on the coordination endpoint's own HTTPS identity, the paths a
// public endpoint cannot reach directly. One region, one node, the core's
// — named in every netmap it serves.
type derpServer struct {
	server *derpserver.Server
}

// newDERPServer stands the relay on its persisted node key — the key the
// relay's clients are addressed by, stable across restarts.
func newDERPServer(nodeKey key.NodePrivate) derpServer {
	return derpServer{server: derpserver.New(nodeKey, logger.Logf(func(
		format string, args ...any) {

		slog.Info("DERP server: "+format, args...)
	}))}
}

// handler serves the relay's HTTP surface, mounted at /derp.
func (s derpServer) handler() http.Handler { return derpserver.Handler(s.server) }

// close shuts the relay down with its connected clients.
func (s derpServer) close() error { return s.server.Close() }
