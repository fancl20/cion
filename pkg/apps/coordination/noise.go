package coordination

import (
	"encoding/json/v2"
	"log/slog"
	"net/http"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// maxConversations bounds the noise conversations the application serves:
// past the bound the upgrade refuses before the handshake begins — one
// conversation per client; CION is non-scalable by design.
const maxConversations = 128

// handleNoise answers the client protocol's upgrade: the /ts2021 request
// completes the noise handshake — the server's machine key against the
// client's — and the hijacked connection becomes an HTTP/2 session carrying
// the machine endpoints, registration and the netmap, inside the noise
// envelope. The conversation holds one of a bounded set: past the bound the
// upgrade refuses before the handshake begins.
func (a *App) handleNoise(w http.ResponseWriter, r *http.Request) {
	if a.conversations.Add(1) > maxConversations {
		a.conversations.Add(-1)
		http.Error(w, "the coordination endpoint holds its conversations",
			http.StatusServiceUnavailable)
		return
	}
	conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, a.machineKey, nil)
	if err != nil {
		a.conversations.Add(-1)
		slog.Warn("Coordination noise handshake", "remote", r.RemoteAddr, "err", err)
		return
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.conversations.Add(-1)
		defer func() { _ = conn.Close() }()
		(&http2.Server{}).ServeConn(conn,
			&http2.ServeConnOpts{Handler: &machineHandler{app: a, machine: conn.Peer()}})
	}()
}

// machineHandler serves one noise conversation's machine endpoints, the
// handshake-authenticated machine key beside them: the one fact the
// endpoints need that HTTP itself cannot name.
type machineHandler struct {
	app     *App
	machine key.MachinePublic
}

func (h *machineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/machine/register":
		h.app.handleRegister(w, r, h.machine)
	case "/machine/map":
		h.app.handleMap(w, r, h.machine)
	default:
		http.NotFound(w, r)
	}
}

// handleKey answers the client protocol's first exchange: the noise
// machine key over plain TLS, the one fact a client cannot begin the
// handshake without.
func (a *App) handleKey(w http.ResponseWriter, r *http.Request) {
	raw, err := json.Marshal(tailcfg.OverTLSPublicKeyResponse{
		PublicKey: a.machineKey.Public(),
	})
	if err != nil {
		http.Error(w, "encoding the key", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
