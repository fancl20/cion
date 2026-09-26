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

// handleNoise answers the client protocol's upgrade: the /ts2021 request
// completes the noise handshake — the server's machine key against the
// client's — and the hijacked connection becomes an HTTP/2 session carrying
// the machine endpoints, registration and the netmap, inside the noise
// envelope.
func (a *App) handleNoise(w http.ResponseWriter, r *http.Request) {
	conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, a.machineKey, nil)
	if err != nil {
		slog.Warn("Coordination noise handshake", "remote", r.RemoteAddr, "err", err)
		return
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
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
