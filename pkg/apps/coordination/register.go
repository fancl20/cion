package coordination

import (
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

const (
	// maxRegisterBody bounds one registration request: the hostinfo a client
	// carries is small, and the request needs no more room than that.
	maxRegisterBody = 1 << 20

	// admissionMinInterval is the registration door's rate cap: the least
	// pause between the seam's asks, per source and overall — the trust
	// door's own interval the shape, the security model's named control.
	admissionMinInterval = time.Second
)

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
// registry already holds answers from the record, admission being durable,
// and the record names the machine: the machine that earned the key answers,
// any other meets the refusal the denied registration carries. A new key
// asks the seam — past the door's rate caps — and approve allocates in the
// node the answer names and records, while deny and pending leave the
// request refused and unanswered — the client's own polling carries the
// wait, the registration retry loop the protocol's clients already run.
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
	hostname, osName := claimsOf(req.Hostinfo.View())

	// The admission transaction: one lock holds the read, the idempotency
	// check, the seam's ask, the allocation, and the record — the renewal
	// transaction's own shape — so overlapping admissions read in order, each
	// allocation seeing every record the last one wrote, and a key racing
	// itself meets the idempotent answer.
	a.admissionMtx.Lock()
	defer a.admissionMtx.Unlock()

	directory, err := a.cfg.Store.List(r.Context())
	if err != nil {
		http.Error(w, "the registry is unavailable",
			http.StatusInternalServerError)
		slog.Error("Coordination reading the registry", "err", err)
		return
	}

	// The registry's own record answers a key it holds: a re-registering
	// host changes nothing and the seam is never re-asked — the answer
	// passes the door's caps uncapped, and the binding makes it a refusal
	// when the asker is not the machine the record names.
	for i := range directory.Hosts {
		host := &directory.Hosts[i]
		if host.PublicKey != nodeKey {
			continue
		}
		bound, err := a.bindMachine(r.Context(), host, machine)
		if err != nil {
			http.Error(w, "recording the registration",
				http.StatusInternalServerError)
			slog.Error("Coordination binding a host", "err", err)
			return
		}
		if !bound {
			http.Error(w, "registration denied", http.StatusForbidden)
			slog.Warn("Coordination refused a registration from a machine the record does not name",
				"machine", machine.ShortString(),
				"node_key", req.NodeKey.ShortString(), "source", source)
			return
		}
		writeRegisterResponse(w, req.NodeKey)
		return
	}

	// The door's rate caps, ahead of the seam's ask: one admission per
	// interval per source address — an internet source's port is ephemeral —
	// beside the door's own overall pace against many slow sources, so a
	// flood of fresh keys tries auth keys no faster than the caps and writes
	// no record. The refusal rides the pending refusal's own path and
	// status, for the vendored client answers the rate's own status — 429 —
	// by failing a headless host's login outright instead of retrying it.
	if !a.bySource.Admit(source.Addr()) || !a.overall.Allow() {
		http.Error(w, "registration exceeds the admission rate",
			http.StatusServiceUnavailable)
		return
	}

	facts := enrollauth.AdmissionFacts{
		Boundary: enrollauth.BoundaryRegistration,
		Keys: []string{
			machine.String(),
			req.NodeKey.String(),
		},
		Source:     source,
		Credential: credential,
	}
	var answer enrollauth.AdmissionAnswer
	if a.cfg.Authorizer != nil {
		// No authorizer selected admits no host: the zero answer denies.
		answer = a.cfg.Authorizer.Authorize(r.Context(), facts)
	}
	switch answer.Admission {
	case enrollauth.AdmissionAllow:
		// Approve allocates the next free address in the slice of the node
		// the answer names — the founding core where it names none — and
		// records the one registry entry: the key, the machine, the address,
		// the owning node, the approving plugin's note, and the client's
		// claims about itself.
		node := answer.Node
		if node.IsZero() {
			node = a.cfg.IA
		}
		host, err := allocate(nodeKey, directory, node)
		if err != nil {
			http.Error(w, "no address to allocate", http.StatusServiceUnavailable)
			slog.Warn("Coordination allocating a host address",
				"node_key", req.NodeKey.ShortString(), "node", node, "err", err)
			return
		}
		host.Note = answer.Note
		host.MachineKey = machineKeyOf(machine)
		host.Hostname, host.OS = hostname, osName
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
	case enrollauth.AdmissionPending:
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

// bindMachine settles the record's machine claim before it answers: the
// record names the machine its node key belongs to, and the channel's
// authenticated machine is what the claim checks. A record from before the
// claim — one holding no machine key — binds the first machine to present
// it, one write on the answer path, the honest migration for a record that
// never held the fact; a record naming another machine does not answer. It
// reports whether the record answers the machine, and errors only on the
// store's write. The caller holds the admission lock, for the binding
// writes the record.
func (a *App) bindMachine(ctx context.Context, host *wireguard.HostEntry,
	machine key.MachinePublic) (bool, error) {

	presented := machineKeyOf(machine)
	if host.MachineKey == presented {
		return true, nil
	}
	if host.MachineKey != (wireguard.PublicKey{}) {
		return false, nil
	}
	host.MachineKey = presented
	if err := a.cfg.Store.PublishHost(ctx, *host); err != nil {
		return false, err
	}
	slog.Info("Coordination bound a record to its first presenting machine",
		"node_key", nodePublicOf(host.PublicKey).ShortString(),
		"machine", machine.ShortString())
	return true, nil
}

// bindOnMap settles the record's machine claim on the map path, which holds
// no lock of its own: a record naming a machine answers that machine alone,
// and a record from before the claim binds under the admission lock, read
// again first, so a release that landed since the map read the registry is
// never undone by the binding's write.
func (a *App) bindOnMap(ctx context.Context, host *wireguard.HostEntry,
	machine key.MachinePublic) (bool, error) {

	if presented := machineKeyOf(machine); host.MachineKey == presented {
		return true, nil
	}
	if host.MachineKey != (wireguard.PublicKey{}) {
		return false, nil
	}
	a.admissionMtx.Lock()
	defer a.admissionMtx.Unlock()
	directory, err := a.cfg.Store.List(ctx)
	if err != nil {
		return false, err
	}
	for i := range directory.Hosts {
		if directory.Hosts[i].PublicKey == host.PublicKey {
			return a.bindMachine(ctx, &directory.Hosts[i], machine)
		}
	}
	return false, nil
}

// RemoveHost releases the host the node key names: its registry entry is
// deleted under the admission lock — no admission and no binding
// interleaves with the delete — and its address returns to the allocator.
// An open map stream for the key closes at its next re-read, as for any
// vanished registration, and each node drops the peer at its next
// directory fetch. A key the registry does not hold releases nothing and
// succeeds.
func (a *App) RemoveHost(ctx context.Context, nodeKey wireguard.PublicKey) error {
	a.admissionMtx.Lock()
	defer a.admissionMtx.Unlock()
	if err := a.cfg.Store.DeleteHost(ctx, nodeKey); err != nil {
		return err
	}
	a.forget(nodeKey)
	slog.Info("Coordination released a host",
		"node_key", nodePublicOf(nodeKey).ShortString())
	return nil
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

// machineKeyOf converts the protocol's machine key to the registry's.
func machineKeyOf(k key.MachinePublic) wireguard.PublicKey {
	var out wireguard.PublicKey
	copy(out[:], k.UntypedBytes()) // nolint - the registry's key type
	return out
}

// nodePublicOf converts the registry's key to the protocol's.
func nodePublicOf(k wireguard.PublicKey) key.NodePublic {
	return key.NodePublicFromRaw32(mem.B(k[:]))
}
