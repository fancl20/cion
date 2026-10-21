// Package portal is the operator's console: the resident application the
// founding core serves beneath /admin/ on its HTTPS server, paired with
// the portal admission method it decides for. Its one user — the
// operator, signed in with a passkey — approves or rejects the method's
// asks, mints the method's auth keys, reads the network's records through
// the Records its entry adapts — the nodes holding a chain, the hosts
// holding an address — and releases hosts.
//
// The ceremonies and the sessions live in memory; the passkeys persist in
// the application's state directory. A console with no passkey mints a
// one-time setup token in memory, and Run logs the link that carries it;
// the first registration consumes it, and a restart mints a fresh one.
package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/ratelimit"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// sweepInterval paces Run's sweep of the ceremonies and sessions that
// stopped standing.
const sweepInterval = time.Minute

// Config configures the application.
type Config struct {
	// Domain is the relying party: the core's WebPKI identity, a DNS name —
	// a passkey binds to a domain.
	Domain string
	// Origin is the console's origin: "https://" and the domain, with the
	// HTTPS server's port when it is not 443.
	Origin string
	// StateDir persists the application's passkeys.
	StateDir string
	// Operator is the admission method the console decides for: its asks,
	// its decisions, and its auth keys.
	Operator enrollauth.Operator
	// Records is the network's records the console lists, and the release
	// it asks.
	Records Records
	// MountHTTPS mounts the console's surface on the node's HTTPS server.
	MountHTTPS func(pattern string, handler http.Handler)
}

// App is the console. Its zero value is not usable; New builds it.
type App struct {
	domain   string
	origin   string
	stateDir string
	operator enrollauth.Operator
	records  Records
	rp       *webauthn.WebAuthn
	// limit paces the unauthenticated ceremonies' requests, one per
	// interval per source address and route.
	limit *ratelimit.Keyed[limitKey]

	// mtx guards everything below, shared by the API's handlers and Run.
	mtx        sync.Mutex
	passkeys   passkeyRecord
	setupToken string
	ceremonies map[string]*ceremony
	sessions   map[string]time.Time
}

// limitKey names one rate-limited door: the route asked and the source
// asking.
type limitKey struct {
	route  string
	source netip.Addr
}

// New builds the console — the relying party for the domain and origin,
// the persisted passkeys, and, with no passkey registered, the setup token
// — and mounts its surface beneath /admin/. A domain that is an address
// refuses, for a passkey binds to a DNS name.
func New(cfg Config) (*App, error) {
	if _, err := netip.ParseAddr(cfg.Domain); err == nil {
		return nil, fmt.Errorf("the portal needs a DNS name identity, not the address %s: "+
			"a passkey binds to a domain", cfg.Domain)
	}
	timeout := webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    ceremonyLifetime,
		TimeoutUVD: ceremonyLifetime,
	}
	rp, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.Domain,
		RPDisplayName: "CION",
		RPOrigins:     []string{cfg.Origin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        timeout,
			Registration: timeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configuring the relying party: %w", err)
	}
	a := &App{
		domain:     cfg.Domain,
		origin:     cfg.Origin,
		stateDir:   cfg.StateDir,
		operator:   cfg.Operator,
		records:    cfg.Records,
		rp:         rp,
		limit:      ratelimit.NewKeyed[limitKey](time.Second),
		ceremonies: make(map[string]*ceremony),
		sessions:   make(map[string]time.Time),
	}
	if err := a.loadPasskeys(); err != nil {
		return nil, err
	}
	if len(a.passkeys.Credentials) == 0 {
		a.setupToken = randomHex(tokenBytes)
	}
	cfg.MountHTTPS("/admin/", a.routes())
	return a, nil
}

// SetupLink is the link that carries the setup token while no passkey is
// registered, the token in its fragment so no request line carries it; the
// empty string once setup closed.
func (a *App) SetupLink() string {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.setupToken == "" {
		return ""
	}
	return a.origin + "/admin/setup#" + a.setupToken
}

// Run logs the setup link while setup is open, then sweeps the ceremonies
// and sessions that stopped standing until the context ends.
func (a *App) Run(ctx context.Context) error {
	if link := a.SetupLink(); link != "" {
		slog.Warn("The portal has no passkey; open the setup link to register the operator's first",
			"url", link)
	}
	for loops.Sleep(ctx, sweepInterval) {
		a.sweep(time.Now())
	}
	return nil
}

// Close releases nothing: the console serves on the node's HTTPS server
// and binds nothing of its own.
func (a *App) Close() {}

// sweep drops the ceremonies and sessions that stopped standing.
func (a *App) sweep(now time.Time) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.sweepSessionsLocked(now)
}

// randomBytes returns n bytes from crypto/rand, whose Read never fails —
// the runtime crashes the program instead.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// randomHex returns n random bytes, hex encoded.
func randomHex(n int) string {
	return hex.EncodeToString(randomBytes(n))
}
