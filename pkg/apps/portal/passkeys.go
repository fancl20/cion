package portal

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/fancl20/cion/pkg/libs/statefile"
)

// The console's credentials and their ceremonies: the passkeys persist in
// the state directory, while the ceremonies and the sessions live in
// memory, each table bounded — the oldest entry leaving past the bound.
const (
	passkeysFile     = "passkeys.json"
	ceremonyLifetime = 5 * time.Minute
	sessionLifetime  = 12 * time.Hour
	maxCeremonies    = 64
	maxSessions      = 64
	userHandleBytes  = 64
	tokenBytes       = 32
)

// The ceremonies' refusals; the API maps each to its status.
var (
	errSetupClosed    = errors.New("setup is closed: a passkey is registered")
	errSetupToken     = errors.New("the setup token does not match")
	errNoCeremony     = errors.New("no ceremony is in progress; begin again")
	errNoPasskey      = errors.New("no passkey is registered; set one up first")
	errLastPasskey    = errors.New("the last passkey cannot be deleted")
	errUnknownPasskey = errors.New("no passkey has that id")
	errVerification   = errors.New("the authenticator's response did not verify")
	errUnknownUser    = errors.New("the passkey names no operator of this console")
)

// passkeyRecord is the state file: the operator's user handle beside each
// credential registered for it.
type passkeyRecord struct {
	UserHandle  []byte              `json:"userHandle"`
	Credentials []*storedCredential `json:"credentials"`
}

// storedCredential is one passkey: the library's credential beside the name
// the operator gave it and when it was registered and last used.
type storedCredential struct {
	Name       string              `json:"name"`
	Created    time.Time           `json:"created"`
	LastUsed   time.Time           `json:"lastUsed,omitzero"`
	Credential webauthn.Credential `json:"credential"`
}

// operator is the console's one user as the library sees it: the handle
// minted with the first passkey and every credential registered since.
type operator struct {
	handle []byte
	creds  []webauthn.Credential
}

func (o operator) WebAuthnID() []byte                         { return o.handle }
func (o operator) WebAuthnName() string                       { return "operator" }
func (o operator) WebAuthnDisplayName() string                { return "CION operator" }
func (o operator) WebAuthnCredentials() []webauthn.Credential { return o.creds }

// ceremonyKind is what a ceremony registers or proves.
type ceremonyKind int

const (
	// ceremonySetup registers the first passkey, for the setup token's
	// holder.
	ceremonySetup ceremonyKind = iota
	// ceremonyAdd registers a further passkey, for a signed-in operator.
	ceremonyAdd
	// ceremonyLogin proves a registered passkey.
	ceremonyLogin
)

// ceremony is one ceremony in flight: the library's session data, the name
// a registration gives its passkey, and the moment it stops standing.
type ceremony struct {
	kind    ceremonyKind
	session webauthn.SessionData
	name    string
	expires time.Time
}

// operatorLocked snapshots the operator for the library; the caller holds
// the mutex.
func (a *App) operatorLocked() operator {
	creds := make([]webauthn.Credential, 0, len(a.passkeys.Credentials))
	for _, c := range a.passkeys.Credentials {
		creds = append(creds, c.Credential)
	}
	return operator{handle: a.passkeys.UserHandle, creds: creds}
}

// beginSetup opens the first passkey's registration for the holder of the
// setup token.
func (a *App) beginSetup(token, name string) (*protocol.CredentialCreation, string, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.setupToken == "" {
		return nil, "", errSetupClosed
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.setupToken)) != 1 {
		return nil, "", errSetupToken
	}
	if a.passkeys.UserHandle == nil {
		a.passkeys.UserHandle = randomBytes(userHandleBytes)
	}
	return a.beginRegistrationLocked(ceremonySetup, name)
}

// beginAdd opens a further passkey's registration.
func (a *App) beginAdd(name string) (*protocol.CredentialCreation, string, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.beginRegistrationLocked(ceremonyAdd, name)
}

// beginRegistrationLocked opens a registration: a discoverable credential,
// user verification required, no attestation asked, and the registered
// credentials excluded.
func (a *App) beginRegistrationLocked(kind ceremonyKind, name string) (
	*protocol.CredentialCreation, string, error) {

	user := a.operatorLocked()
	creation, session, err := a.rp.BeginRegistration(user,
		// One selection option: it replaces whatever selection an option
		// before it set.
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()),
	)
	if err != nil {
		return nil, "", fmt.Errorf("beginning a registration: %w", err)
	}
	return creation, a.openCeremonyLocked(kind, *session, name), nil
}

// finishRegistration completes a registration the ceremony opened: the
// response verified, the passkey recorded and persisted. The first one
// closes setup, its token discarded.
func (a *App) finishRegistration(kind ceremonyKind, ceremonyID string,
	response *protocol.ParsedCredentialCreationData) error {

	now := time.Now()
	a.mtx.Lock()
	defer a.mtx.Unlock()
	c := a.takeCeremonyLocked(ceremonyID, kind, now)
	if c == nil {
		return errNoCeremony
	}
	if kind == ceremonySetup && a.setupToken == "" {
		return errSetupClosed
	}
	cred, err := a.rp.CreateCredential(a.operatorLocked(), c.session, response)
	if err != nil {
		return fmt.Errorf("%w: %w", errVerification, err)
	}
	a.passkeys.Credentials = append(a.passkeys.Credentials, &storedCredential{
		Name:       c.name,
		Created:    now,
		Credential: *cred,
	})
	if err := a.persistPasskeysLocked(); err != nil {
		a.passkeys.Credentials = a.passkeys.Credentials[:len(a.passkeys.Credentials)-1]
		return err
	}
	if kind == ceremonySetup {
		a.setupToken = ""
		slog.Info("The portal registered the operator's first passkey; setup is closed")
	}
	return nil
}

// beginLogin opens a login: any registered passkey may answer, with user
// verification required.
func (a *App) beginLogin() (*protocol.CredentialAssertion, string, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if len(a.passkeys.Credentials) == 0 {
		return nil, "", errNoPasskey
	}
	assertion, session, err := a.rp.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", fmt.Errorf("beginning a login: %w", err)
	}
	return assertion, a.openCeremonyLocked(ceremonyLogin, *session, ""), nil
}

// finishLogin completes a login the ceremony opened and answers a fresh
// session: the response verified against the operator's credentials, a
// credential the library flags as cloned refused, and the used credential's
// counter and last use recorded. A failed write keeps the login.
func (a *App) finishLogin(ceremonyID string,
	response *protocol.ParsedCredentialAssertionData) (string, error) {

	now := time.Now()
	a.mtx.Lock()
	defer a.mtx.Unlock()
	c := a.takeCeremonyLocked(ceremonyID, ceremonyLogin, now)
	if c == nil {
		return "", errNoCeremony
	}
	_, cred, err := a.rp.ValidatePasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, a.passkeys.UserHandle) {
			return nil, errUnknownUser
		}
		return a.operatorLocked(), nil
	}, c.session, response)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errVerification, err)
	}
	if cred.Authenticator.CloneWarning {
		return "", fmt.Errorf("%w: the authenticator's counter went back", errVerification)
	}
	for _, stored := range a.passkeys.Credentials {
		if bytes.Equal(stored.Credential.ID, cred.ID) {
			stored.Credential = *cred
			stored.LastUsed = now
		}
	}
	if err := a.persistPasskeysLocked(); err != nil {
		slog.Warn("Persisting the portal's passkeys", "err", err)
	}
	return a.openSessionLocked(now), nil
}

// passkeyView is one passkey as the API answers it.
type passkeyView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed,omitzero"`
}

// listPasskeys snapshots the passkeys in registration order.
func (a *App) listPasskeys() []passkeyView {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	views := make([]passkeyView, 0, len(a.passkeys.Credentials))
	for _, c := range a.passkeys.Credentials {
		views = append(views, passkeyView{
			ID:       base64.RawURLEncoding.EncodeToString(c.Credential.ID),
			Name:     c.Name,
			Created:  c.Created,
			LastUsed: c.LastUsed,
		})
	}
	return views
}

// deletePasskey removes the passkey the ID names; the last one stays, so
// the console always holds a way in.
func (a *App) deletePasskey(id string) error {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return errUnknownPasskey
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	i := slices.IndexFunc(a.passkeys.Credentials, func(c *storedCredential) bool {
		return bytes.Equal(c.Credential.ID, raw)
	})
	if i < 0 {
		return errUnknownPasskey
	}
	if len(a.passkeys.Credentials) == 1 {
		return errLastPasskey
	}
	kept := slices.Delete(slices.Clone(a.passkeys.Credentials), i, i+1)
	held := a.passkeys.Credentials
	a.passkeys.Credentials = kept
	if err := a.persistPasskeysLocked(); err != nil {
		a.passkeys.Credentials = held
		return err
	}
	return nil
}

// openCeremonyLocked records a ceremony in flight under a fresh ID.
func (a *App) openCeremonyLocked(kind ceremonyKind, session webauthn.SessionData,
	name string) string {

	if len(a.ceremonies) >= maxCeremonies {
		dropSoonest(a.ceremonies, func(c *ceremony) time.Time { return c.expires })
	}
	id := randomHex(tokenBytes)
	a.ceremonies[id] = &ceremony{
		kind:    kind,
		session: session,
		name:    name,
		expires: time.Now().Add(ceremonyLifetime),
	}
	return id
}

// takeCeremonyLocked removes the ceremony the ID names and answers it when
// it is of the kind and still stands: a ceremony completes once.
func (a *App) takeCeremonyLocked(id string, kind ceremonyKind, now time.Time) *ceremony {
	c := a.ceremonies[id]
	delete(a.ceremonies, id)
	if c == nil || c.kind != kind || !now.Before(c.expires) {
		return nil
	}
	return c
}

// openSessionLocked opens a session and answers its token.
func (a *App) openSessionLocked(now time.Time) string {
	if len(a.sessions) >= maxSessions {
		dropSoonest(a.sessions, func(expires time.Time) time.Time { return expires })
	}
	token := randomHex(tokenBytes)
	a.sessions[token] = now.Add(sessionLifetime)
	return token
}

// sessionValid reports whether the token names a session still standing.
func (a *App) sessionValid(token string) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	expires, ok := a.sessions[token]
	return ok && time.Now().Before(expires)
}

// endSession closes the session the token names.
func (a *App) endSession(token string) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	delete(a.sessions, token)
}

// sweepSessionsLocked drops the ceremonies and sessions that stopped
// standing.
func (a *App) sweepSessionsLocked(now time.Time) {
	for id, c := range a.ceremonies {
		if !now.Before(c.expires) {
			delete(a.ceremonies, id)
		}
	}
	for token, expires := range a.sessions {
		if !now.Before(expires) {
			delete(a.sessions, token)
		}
	}
}

// dropSoonest removes the entry whose moment comes first.
func dropSoonest[V any](m map[string]V, moment func(V) time.Time) {
	var first string
	var at time.Time
	for k, v := range m {
		if t := moment(v); first == "" || t.Before(at) {
			first, at = k, t
		}
	}
	delete(m, first)
}

// loadPasskeys reads the persisted passkeys; a missing file is a console
// with none, whose setup is open.
func (a *App) loadPasskeys() error {
	raw, err := os.ReadFile(a.passkeysPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the passkeys: %w", err)
	}
	if err := json.Unmarshal(raw, &a.passkeys); err != nil {
		return fmt.Errorf("parsing the passkeys: %w", err)
	}
	return nil
}

// persistPasskeysLocked writes the passkeys back whole; the caller holds
// the mutex.
func (a *App) persistPasskeysLocked() error {
	raw, err := json.Marshal(a.passkeys)
	if err != nil {
		return err
	}
	if err := statefile.Write(a.passkeysPath(), raw); err != nil {
		return fmt.Errorf("writing the passkeys: %w", err)
	}
	return nil
}

func (a *App) passkeysPath() string {
	return filepath.Join(a.stateDir, passkeysFile)
}
