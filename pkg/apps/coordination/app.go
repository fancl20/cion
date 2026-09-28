package coordination

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// Store is the registry the coordination application works on: the core's
// directory store, read for node entries and written with host entries. The
// store stays the WireGuard application's — this application borrows the
// view beside it, never the file.
type Store interface {
	List(ctx context.Context) (wireguard.Directory, error)
	PublishHost(ctx context.Context, entry wireguard.HostEntry) error
}

// DERPConfig names the relay a netmap advertises: the core's own HTTPS
// identity, one region, the one fallback path a client expects.
type DERPConfig struct {
	// HostName is the DERP node's hostname — the core's domain by default,
	// and the name the certificate answers for.
	HostName string
	// IPv4 optionally dials the relay by address instead of DNS — the
	// integration harness's stand-in for resolution.
	IPv4 string
	// Port overrides the DERP HTTPS port 443; zero is 443.
	Port int
	// CertName optionally pins the certificate the relay presents, in the
	// DERP map's grammar ("sha256-raw:<hex>" among them) — the harness's
	// stand-in for the WebPKI.
	CertName string
}

// Config configures the coordination application.
type Config struct {
	// Domain is the core's domain: the name the certificate answers for
	// and the tailnet's own.
	Domain string
	// Store is the registry: node entries read for the netmap and
	// allocation, host entries written at admission.
	Store Store
	// Authorizer gates registrations — the same seam the trust service
	// asks at first issuance, asked here with the registration boundary's
	// facts. Nil is open admission, the zero-conf default.
	Authorizer enrollauth.AdmissionAuthorizer
	// DERP names the relay the netmap advertises beside the coordination
	// endpoint's own identity.
	DERP DERPConfig
	// StateDir persists the application's own keys: the noise machine key
	// and the DERP server's node key.
	StateDir string

	// MapResend overrides, for tests, how often an open map stream re-reads
	// the registry — the bound on how long a peer change hides from a
	// connected host. Zero means the package constant.
	MapResend time.Duration

	// RelayOnly strips the peer's endpoint from every netmap: the
	// integration harness's stand-in for a network where UDP to the node
	// cannot pass, forcing the relay leg.
	RelayOnly bool
}

// App is the coordination application (ADR-0011): the noise channel of the
// client protocol carrying registration behind the admission seam, the
// netmap holding one peer, and the DERP relay fallback — its three surfaces
// handed to the node's assembly, which serves them over the core's WebPKI
// identity on the HTTPS port it owns (proposal 0023). Minimal by decision:
// no ACL engine, no naming, no user management, no key expiry, no
// credential minting, no listener of its own.
type App struct {
	cfg        Config
	machineKey key.MachinePrivate

	derp derpServer
	// handler is the mounted surface: the three paths of the client
	// protocol, one handler.
	handler http.Handler

	// wg waits for the served noise conversations, so Close waits for what
	// the mounting began.
	wg sync.WaitGroup
}

// New assembles the application: keys load or create in its own state, the
// DERP server stands on its node key, and the HTTP surface builds — the
// /ts2021 upgrade into the noise channel, the /derp relay, and the /key
// fetch over plain TLS beside them. Handler hands the surface to its
// mounter.
func New(cfg Config) (*App, error) {
	if cfg.Domain == "" {
		return nil, errors.New("no domain configured")
	}
	if cfg.Store == nil {
		return nil, errors.New("no registry store configured")
	}
	if cfg.DERP.HostName == "" {
		cfg.DERP.HostName = cfg.Domain
	}
	machineKey, err := LoadOrCreateMachineKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	derpKey, err := LoadOrCreateDERPKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg:        cfg,
		machineKey: machineKey,
		derp:       newDERPServer(derpKey),
	}
	mux := http.NewServeMux()
	mux.Handle("/ts2021", http.HandlerFunc(a.handleNoise))
	mux.Handle("/derp", a.derp.handler())
	// The client's first exchange is the key fetch over plain TLS: the
	// noise machine key it must know before the handshake can begin.
	mux.HandleFunc("/key", a.handleKey)
	a.handler = mux
	return a, nil
}

// Handler returns the application's HTTP surface — the /key fetch, the
// /ts2021 upgrade into the noise channel, and the /derp relay — for the
// assembly's mux to mount. The serving server, the listener, and the TLS
// identity are the assembly's; the keys, the state, and the conversations
// stay the application's.
func (a *App) Handler() http.Handler { return a.handler }

// Close retires the application: the served noise conversations and the
// relay with its connected clients.
func (a *App) Close() error {
	a.wg.Wait()
	return a.derp.close()
}
