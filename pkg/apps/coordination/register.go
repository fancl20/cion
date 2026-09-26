package coordination

import (
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/netip"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/controlplane"
)

// maxRegisterBody bounds one registration request: the hostinfo a client
// carries is small, and the request needs no more room than that.
const maxRegisterBody = 1 << 20

// registerUser is the one user every admitted host belongs to: the tailnet
// holds no user management — admission is the tailnet's one policy — and
// the client's own machinery wants a profile to carry, not a directory of
// people.
var (
	registerUserID  tailcfg.UserID  = 1
	registerLoginID tailcfg.LoginID = 1
	registerLogin                   = "host"
	registerDisplay                 = "CION host"
)

// handleRegister answers one registration: a joiner presents its keys — the
// machine key the noise channel authenticated and the node key the data
// plane will use — and, when it carries one, a credential. A key the
// registry already holds answers from the record, admission being durable;
// a new key asks the seam, and approve allocates and records while deny and
// pending leave the request refused and unanswered — the client's own
// polling carries the wait, the registration retry loop the protocol's
// clients already run.
func (a *App) handleRegister(w http.ResponseWriter, r *http.Request,
	machine key.MachinePublic) {

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRegisterBody))
	if err != nil {
		http.Error(w, "reading the registration", http.StatusBadRequest)
		return
	}
	var req tailcfg.RegisterRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "malformed registration", http.StatusBadRequest)
		return
	}
	if req.NodeKey.IsZero() {
		http.Error(w, "registration carries no node key", http.StatusBadRequest)
		return
	}
	source, _ := netip.ParseAddrPort(r.RemoteAddr)
	nodeKey := nodeKeyOf(req.NodeKey)
	credential := ""
	if req.Auth != nil {
		credential = req.Auth.AuthKey
	}
	directory, err := a.cfg.Store.List(r.Context())
	if err != nil {
		http.Error(w, "the registry is unavailable",
			http.StatusInternalServerError)
		slog.Error("Coordination reading the registry", "err", err)
		return
	}

	// The registry's own record answers a key it holds: a re-registering
	// host changes nothing, and the seam is never re-asked.
	for _, host := range directory.Hosts {
		if host.PublicKey == nodeKey {
			writeRegisterResponse(w, req.NodeKey)
			return
		}
	}

	facts := controlplane.AdmissionFacts{
		Boundary: controlplane.BoundaryRegistration,
		Keys: []string{
			machine.String(),
			req.NodeKey.String(),
		},
		Source:     source,
		Credential: credential,
	}
	var answer controlplane.AdmissionAnswer
	if a.cfg.Authorizer == nil {
		// No authorizer selected keeps registration open — the zero-conf
		// default.
		answer.Admission = controlplane.AdmissionAllow
	} else {
		answer = a.cfg.Authorizer.Authorize(r.Context(), facts)
	}
	switch answer.Admission {
	case controlplane.AdmissionAllow:
		// Approve allocates the next free address in the owning node's
		// slice and records the one registry entry: the key, the address,
		// the owning node, and the approving plugin's note.
		host, err := allocate(nodeKey, directory)
		if err != nil {
			http.Error(w, "no address to allocate", http.StatusServiceUnavailable)
			slog.Warn("Coordination allocating a host address",
				"node_key", req.NodeKey.ShortString(), "err", err)
			return
		}
		host.Note = answer.Note
		if err := a.cfg.Store.PublishHost(r.Context(), host); err != nil {
			http.Error(w, "recording the registration",
				http.StatusInternalServerError)
			slog.Error("Coordination recording a host", "err", err)
			return
		}
		slog.Info("Coordination admitted a host",
			"node_key", req.NodeKey.ShortString(),
			"addr", host.Addr, "node", host.IA, "note", host.Note)
		writeRegisterResponse(w, req.NodeKey)
	case controlplane.AdmissionPending:
		// Pending leaves the request refused-and-retried: the client's own
		// polling carries the wait, exactly as enrollment's retry does.
		http.Error(w, "registration pending a decision", http.StatusServiceUnavailable)
		slog.Info("Coordination registration pending",
			"machine", machine.ShortString(),
			"node_key", req.NodeKey.ShortString(), "source", source)
	default:
		http.Error(w, "registration denied", http.StatusForbidden)
		slog.Warn("Coordination denied a registration",
			"machine", machine.ShortString(),
			"node_key", req.NodeKey.ShortString(), "source", source)
	}
}

// writeRegisterResponse completes the login on the spot: no AuthURL, the
// machine authorized — the entire configuration arrives with the netmap the
// client asks for next.
func writeRegisterResponse(w http.ResponseWriter, node key.NodePublic) {
	resp := tailcfg.RegisterResponse{
		User: tailcfg.User{
			ID:          registerUserID,
			DisplayName: registerDisplay,
		},
		Login: tailcfg.Login{
			ID:          registerLoginID,
			LoginName:   registerLogin,
			DisplayName: registerDisplay,
		},
		MachineAuthorized: true,
	}
	w.Header().Set("Content-Type", "application/json")
	raw, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "encoding the response", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(raw)
}

// nodeKeyOf converts the protocol's node key to the registry's.
func nodeKeyOf(k key.NodePublic) wireguard.PublicKey {
	var out wireguard.PublicKey
	copy(out[:], k.AppendTo(nil))
	return out
}

// nodePublicOf converts the registry's key to the protocol's.
func nodePublicOf(k wireguard.PublicKey) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(k[:]))
}
