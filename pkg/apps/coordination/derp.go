package coordination

import (
	"bufio"
	"log/slog"
	"net"
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

// relayHandler serves the relay's surface with each client's connection
// registered among the application's open connections from the relay's
// hijack until the relay finishes serving it — the relay serves a client
// for as long as its connection lasts, and accepts one even once closed —
// so Close ends the relay's clients as it ends the conversations.
func (a *App) relayHandler() http.Handler {
	relay := a.derp.handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			// The relay refuses a writer it cannot hijack on its own.
			relay.ServeHTTP(w, r)
			return
		}
		rw := &relayWriter{ResponseWriter: w, hijacker: hijacker, app: a}
		relay.ServeHTTP(rw, r)
		if rw.conn != nil {
			a.convMtx.Lock()
			delete(a.relays, rw.conn)
			a.convMtx.Unlock()
		}
	})
}

// relayWriter hands the relay its client's connection registered under the
// conversations' mutex; once Close has run, the hijacked connection closes
// at once instead, and the relay's serving of it fails.
type relayWriter struct {
	http.ResponseWriter
	hijacker http.Hijacker
	app      *App
	// conn is the registered connection, nil until the hijack registers
	// one.
	conn net.Conn
}

func (w *relayWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := w.hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.app.convMtx.Lock()
	defer w.app.convMtx.Unlock()
	if w.app.closed {
		_ = conn.Close()
		return conn, brw, nil
	}
	w.app.relays[conn] = struct{}{}
	w.conn = conn
	return conn, brw, nil
}
