package portal

import (
	_ "embed"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// The page, embedded: one document, its script, and its style, served from
// the console's own origin alone.
var (
	//go:embed index.html
	indexHTML []byte
	//go:embed portal.js
	portalJS []byte
	//go:embed portal.css
	portalCSS []byte
)

// The surface's bounds and names: a request body's cap, the caps of the
// names an operator types, and the cookies the sessions and the ceremonies
// ride — __Host- prefixed, so a browser sends them to this origin alone.
const (
	maxBody        = 64 << 10
	nameCap        = 64
	descriptionCap = 128
	sessionCookie  = "__Host-cion-session"
	ceremonyCookie = "__Host-cion-ceremony"
)

// contentSecurityPolicy confines the page to the console's own origin and
// refuses every frame.
const contentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'"

// routes builds the surface: the page at its views' paths and the JSON API
// beneath /admin/api/, the API behind the cross-origin check and every
// response carrying the security headers.
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	for _, view := range []string{"{$}", "nodes", "hosts", "keys", "settings", "setup"} {
		mux.HandleFunc("GET /admin/"+view, asset(indexHTML, "text/html; charset=utf-8"))
	}
	mux.HandleFunc("GET /admin/portal.js", asset(portalJS, "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /admin/portal.css", asset(portalCSS, "text/css; charset=utf-8"))

	api := http.NewServeMux()
	api.HandleFunc("GET /admin/api/session", a.handleSession)
	api.HandleFunc("POST /admin/api/setup/begin", a.limited("setup/begin", a.handleSetupBegin))
	api.HandleFunc("POST /admin/api/setup/finish", a.limited("setup/finish", a.handleSetupFinish))
	api.HandleFunc("POST /admin/api/login/begin", a.limited("login/begin", a.handleLoginBegin))
	api.HandleFunc("POST /admin/api/login/finish", a.limited("login/finish", a.handleLoginFinish))
	api.HandleFunc("POST /admin/api/logout", a.signedIn(a.handleLogout))
	api.HandleFunc("GET /admin/api/nodes", a.signedIn(a.handleNodes))
	api.HandleFunc("GET /admin/api/hosts", a.signedIn(a.handleHosts))
	api.HandleFunc("DELETE /admin/api/hosts/{key}", a.signedIn(a.handleRemoveHost))
	api.HandleFunc("POST /admin/api/asks/{id}/approve", a.signedIn(a.handleDecide(true)))
	api.HandleFunc("POST /admin/api/asks/{id}/reject", a.signedIn(a.handleDecide(false)))
	api.HandleFunc("GET /admin/api/keys", a.signedIn(a.handleKeys))
	api.HandleFunc("POST /admin/api/keys", a.signedIn(a.handleMintKey))
	api.HandleFunc("DELETE /admin/api/keys/{id}", a.signedIn(a.handleRevokeKey))
	api.HandleFunc("GET /admin/api/passkeys", a.signedIn(a.handlePasskeys))
	api.HandleFunc("POST /admin/api/passkeys/begin", a.signedIn(a.handleAddBegin))
	api.HandleFunc("POST /admin/api/passkeys/finish", a.signedIn(a.handleAddFinish))
	api.HandleFunc("DELETE /admin/api/passkeys/{id}", a.signedIn(a.handleDeletePasskey))
	mux.Handle("/admin/api/", http.NewCrossOriginProtection().Handler(api))
	return securityHeaders(mux)
}

// securityHeaders sets the headers every response carries: the content
// policy, no sniffing, no referrer, and no caching of what the console
// shows.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// asset serves one embedded file.
func asset(body []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}
}

// limited paces an unauthenticated door: one request per interval per
// route and source address.
func (a *App) limited(route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source, _ := netip.ParseAddrPort(r.RemoteAddr)
		if !a.limit.Admit(limitKey{route: route, source: source.Addr()}) {
			writeError(w, http.StatusTooManyRequests, "too many requests; try again in a second")
			return
		}
		next(w, r)
	}
}

// signedIn admits a request carrying a standing session.
func (a *App) signedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.sessionValid(cookieOf(r, sessionCookie)) {
			writeError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		next(w, r)
	}
}

// handleSession answers whether the request is signed in, whether setup is
// open, and the console's domain.
func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		SignedIn bool   `json:"signedIn"`
		Setup    bool   `json:"setup"`
		Domain   string `json:"domain"`
	}{
		SignedIn: a.sessionValid(cookieOf(r, sessionCookie)),
		Setup:    a.SetupLink() != "",
		Domain:   a.domain,
	})
}

// handleSetupBegin opens the first passkey's registration for the setup
// token's holder.
func (a *App) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	creation, id, err := a.beginSetup(req.Token, passkeyName(req.Name))
	if err != nil {
		writeFailure(w, err)
		return
	}
	setCookie(w, ceremonyCookie, id, ceremonyLifetime)
	writeJSON(w, http.StatusOK, creation)
}

// handleSetupFinish completes the first passkey's registration and signs
// the operator in.
func (a *App) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	a.finishRegistering(w, r, ceremonySetup)
}

// handleLoginBegin opens a login.
func (a *App) handleLoginBegin(w http.ResponseWriter, _ *http.Request) {
	assertion, id, err := a.beginLogin()
	if err != nil {
		writeFailure(w, err)
		return
	}
	setCookie(w, ceremonyCookie, id, ceremonyLifetime)
	writeJSON(w, http.StatusOK, assertion)
}

// handleLoginFinish completes a login and opens the session.
func (a *App) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	response, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed assertion")
		return
	}
	id := cookieOf(r, ceremonyCookie)
	clearCookie(w, ceremonyCookie)
	token, err := a.finishLogin(id, response)
	if err != nil {
		writeFailure(w, err)
		return
	}
	setCookie(w, sessionCookie, token, sessionLifetime)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout closes the request's session.
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.endSession(cookieOf(r, sessionCookie))
	clearCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

// nodeView is one node as the API answers it.
type nodeView struct {
	IA       string    `json:"ia"`
	Key      string    `json:"key"`
	Expires  time.Time `json:"expires"`
	Role     Role      `json:"role"`
	Overlay  string    `json:"overlay,omitempty"`
	Endpoint string    `json:"endpoint,omitempty"`
	Issued   int       `json:"issued"`
	Capacity int       `json:"capacity"`
}

// handleNodes lists the nodes beside the node and vote asks.
func (a *App) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.records.Nodes(r.Context())
	if err != nil {
		slog.Error("Listing the nodes for the portal", "err", err)
		writeError(w, http.StatusInternalServerError, "the records are unavailable")
		return
	}
	views := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		v := nodeView{
			IA:       n.IA.String(),
			Key:      n.Key,
			Expires:  n.Expires,
			Role:     n.Role,
			Issued:   n.Issued,
			Capacity: capacityOf(n.Overlay),
		}
		if n.Overlay.IsValid() {
			v.Overlay = n.Overlay.String()
		}
		if n.Endpoint.IsValid() {
			v.Endpoint = n.Endpoint.String()
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, struct {
		Nodes []nodeView `json:"nodes"`
		Asks  []askView  `json:"asks"`
	}{views, askViews(a.operator.Asks(enrollauth.BoundaryEnrollment, enrollauth.BoundaryVoting))})
}

// capacityOf counts a slice's allocatable host addresses: every address but
// the network's, the node's own first, and the broadcast; zero without a
// slice.
func capacityOf(overlay netip.Prefix) int {
	if !overlay.IsValid() || overlay.Bits() > 30 {
		return 0
	}
	return 1<<(32-overlay.Bits()) - 3
}

// hostView is one host as the API answers it.
type hostView struct {
	Addr       string    `json:"addr"`
	NodeKey    string    `json:"nodeKey"`
	MachineKey string    `json:"machineKey,omitempty"`
	Owner      string    `json:"owner"`
	Note       string    `json:"note,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	OS         string    `json:"os,omitempty"`
	Connected  bool      `json:"connected"`
	LastSeen   time.Time `json:"lastSeen,omitzero"`
}

// handleHosts lists the hosts beside the registration asks; a core running
// no coordination application answers none available.
func (a *App) handleHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.records.Hosts(r.Context())
	available := !errors.Is(err, ErrNoCoordination)
	if err != nil && available {
		slog.Error("Listing the hosts for the portal", "err", err)
		writeError(w, http.StatusInternalServerError, "the records are unavailable")
		return
	}
	views := make([]hostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, hostView{
			Addr:       h.Addr.String(),
			NodeKey:    h.NodeKey,
			MachineKey: h.MachineKey,
			Owner:      h.Owner.String(),
			Note:       h.Note,
			Hostname:   h.Hostname,
			OS:         h.OS,
			Connected:  h.Connected,
			LastSeen:   h.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, struct {
		Available bool       `json:"available"`
		Hosts     []hostView `json:"hosts"`
		Asks      []askView  `json:"asks"`
	}{available, views, askViews(a.operator.Asks(enrollauth.BoundaryRegistration))})
}

// handleRemoveHost releases the host the path's node key names.
func (a *App) handleRemoveHost(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if raw, err := hex.DecodeString(key); err != nil || len(raw) != 32 {
		writeError(w, http.StatusBadRequest, "malformed node key")
		return
	}
	err := a.records.RemoveHost(r.Context(), key)
	switch {
	case errors.Is(err, ErrNoCoordination):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		slog.Error("Releasing a host from the portal", "node_key", key, "err", err)
		writeError(w, http.StatusInternalServerError, "the release failed")
		return
	}
	slog.Info("The portal released a host", "node_key", key)
	w.WriteHeader(http.StatusNoContent)
}

// askView is one ask as the API answers it.
type askView struct {
	ID         string    `json:"id"`
	Boundary   string    `json:"boundary"`
	Claim      string    `json:"claim,omitempty"`
	Keys       []string  `json:"keys"`
	Label      string    `json:"label,omitempty"`
	Source     string    `json:"source,omitempty"`
	Credential bool      `json:"credential"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Attempts   int       `json:"attempts"`
	State      string    `json:"state"`
	Until      time.Time `json:"until,omitzero"`
}

// askViews renders the method's asks as the API answers them.
func askViews(asks []enrollauth.Ask) []askView {
	views := make([]askView, 0, len(asks))
	for _, ask := range asks {
		v := askView{
			ID:         ask.ID,
			Boundary:   boundaryName(ask.Boundary),
			Keys:       ask.Keys,
			Label:      ask.Label,
			Credential: ask.Credential,
			FirstSeen:  ask.FirstSeen,
			LastSeen:   ask.LastSeen,
			Attempts:   ask.Attempts,
			State:      stateName(ask.Verdict),
			Until:      ask.Until,
		}
		if !ask.Claim.IsZero() {
			v.Claim = ask.Claim.String()
		}
		if ask.Source.IsValid() {
			v.Source = ask.Source.String()
		}
		views = append(views, v)
	}
	return views
}

func boundaryName(b enrollauth.Boundary) string {
	switch b {
	case enrollauth.BoundaryRegistration:
		return "registration"
	case enrollauth.BoundaryVoting:
		return "voting"
	default:
		return "enrollment"
	}
}

func stateName(v enrollauth.AdmissionVerdict) string {
	switch v {
	case enrollauth.AdmissionAllow:
		return "approved"
	case enrollauth.AdmissionDeny:
		return "rejected"
	default:
		return "pending"
	}
}

// handleDecide approves or rejects the ask the path names.
func (a *App) handleDecide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.operator.Decide(r.PathValue("id"), approve) {
			writeError(w, http.StatusNotFound, "no standing ask has that id")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// keyView is one auth key as the API answers it.
type keyView struct {
	ID          string              `json:"id"`
	Description string              `json:"description,omitempty"`
	Reusable    bool                `json:"reusable"`
	Created     time.Time           `json:"created"`
	Expires     time.Time           `json:"expires"`
	Uses        int                 `json:"uses"`
	State       enrollauth.KeyState `json:"state"`
}

// handleKeys lists the auth keys, newest first.
func (a *App) handleKeys(w http.ResponseWriter, _ *http.Request) {
	keys := a.operator.Keys()
	views := make([]keyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, keyView(k))
	}
	writeJSON(w, http.StatusOK, struct {
		Keys []keyView `json:"keys"`
	}{views})
}

// handleMintKey mints an auth key; the response carries the key, the one
// time it leaves the core.
func (a *App) handleMintKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Description string `json:"description"`
		Reusable    bool   `json:"reusable"`
		Days        int    `json:"days"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Days < enrollauth.MinKeyDays || req.Days > enrollauth.MaxKeyDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"an auth key expires between %d and %d days after its minting",
			enrollauth.MinKeyDays, enrollauth.MaxKeyDays))
		return
	}
	key, record, err := a.operator.MintKey(enrollauth.KeyRequest{
		Description: clean(req.Description, descriptionCap),
		Reusable:    req.Reusable,
		Days:        req.Days,
	})
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}{record.ID, key})
}

// handleRevokeKey retires the auth key the path names.
func (a *App) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	found, err := a.operator.RevokeKey(r.PathValue("id"))
	switch {
	case err != nil:
		writeFailure(w, err)
	case !found:
		writeError(w, http.StatusNotFound, "no auth key has that id")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handlePasskeys lists the passkeys.
func (a *App) handlePasskeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Passkeys []passkeyView `json:"passkeys"`
	}{a.listPasskeys()})
}

// handleAddBegin opens a further passkey's registration.
func (a *App) handleAddBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	creation, id, err := a.beginAdd(passkeyName(req.Name))
	if err != nil {
		writeFailure(w, err)
		return
	}
	setCookie(w, ceremonyCookie, id, ceremonyLifetime)
	writeJSON(w, http.StatusOK, creation)
}

// handleAddFinish completes a further passkey's registration.
func (a *App) handleAddFinish(w http.ResponseWriter, r *http.Request) {
	a.finishRegistering(w, r, ceremonyAdd)
}

// handleDeletePasskey deletes the passkey the path names.
func (a *App) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	if err := a.deletePasskey(r.PathValue("id")); err != nil {
		writeFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// finishRegistering completes a registration the request's ceremony
// opened; a setup's completion signs the operator in.
func (a *App) finishRegistering(w http.ResponseWriter, r *http.Request, kind ceremonyKind) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	response, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed credential")
		return
	}
	id := cookieOf(r, ceremonyCookie)
	clearCookie(w, ceremonyCookie)
	if err := a.finishRegistration(kind, id, response); err != nil {
		writeFailure(w, err)
		return
	}
	if kind == ceremonySetup {
		a.mtx.Lock()
		token := a.openSessionLocked(time.Now())
		a.mtx.Unlock()
		setCookie(w, sessionCookie, token, sessionLifetime)
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeFailure answers a ceremony's or a record's failure with its status;
// a verification's detail stays in the log.
func writeFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSetupToken):
		writeError(w, http.StatusForbidden, errSetupToken.Error())
	case errors.Is(err, errSetupClosed), errors.Is(err, errNoPasskey),
		errors.Is(err, errLastPasskey):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errNoCeremony):
		writeError(w, http.StatusBadRequest, errNoCeremony.Error())
	case errors.Is(err, errVerification):
		slog.Info("A portal ceremony failed verification", "err", err)
		writeError(w, http.StatusBadRequest, errVerification.Error())
	case errors.Is(err, errUnknownPasskey):
		writeError(w, http.StatusNotFound, errUnknownPasskey.Error())
	default:
		slog.Error("The portal failed a request", "err", err)
		writeError(w, http.StatusInternalServerError, "the console failed the request")
	}
}

// readJSON decodes the request's capped body into v, answering a malformed
// one itself.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, ok := readBody(w, r)
	if !ok {
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return false
	}
	return true
}

// readBody reads the request's body up to the cap, answering an oversized
// or broken one itself.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable request body")
		return nil, false
	}
	return body, true
}

// writeJSON answers v as JSON with the status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		slog.Error("Encoding a portal response", "err", err)
		http.Error(w, "encoding the response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// writeError answers a refusal as the API's error document.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{message})
}

// cookieOf reads the named cookie's value, empty when the request carries
// none.
func cookieOf(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// setCookie sets a console cookie: secure, script-proof, same-site only.
func setCookie(w http.ResponseWriter, name, value string, lifetime time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(lifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearCookie expires a console cookie.
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// passkeyName is the name a passkey is listed by: the operator's, cleaned
// and capped, or a default.
func passkeyName(s string) string {
	if name := clean(s, nameCap); name != "" {
		return name
	}
	return "Passkey"
}

// clean strips control characters and surrounding space from text an
// operator typed and cuts it to the cap on a rune boundary.
func clean(s string, limit int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "")))
	if len(s) <= limit {
		return s
	}
	cut := limit
	for !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
