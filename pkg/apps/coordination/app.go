package coordination

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/libs/ratelimit"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// Store is the registry the coordination application works on: the core's
// directory store, read for node entries, written with host entries, and
// pruned of the hosts the console releases. The store stays the WireGuard
// application's — this application borrows the view beside it, never the
// file.
type Store interface {
	List(ctx context.Context) (wireguard.Directory, error)
	PublishHost(ctx context.Context, entry wireguard.HostEntry) error
	DeleteHost(ctx context.Context, key wireguard.PublicKey) error
}

// DERPConfig names the relay a netmap advertises: the core's own HTTPS
// identity, one region, the one fallback path a client expects.
type DERPConfig struct {
	// HostName is the DERP node's hostname — the core's identity by
	// default, the name the certificate answers for; an address answers
	// the resolver and the verification both.
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
	// Domain is the core's identity: the name the certificate answers for
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
	// MountHTTPS mounts one of the application's surfaces on the node's
	// HTTPS server; the server, its listener, and its TLS identity are the
	// assembly's.
	MountHTTPS func(pattern string, handler http.Handler)

	// MapResend overrides, for tests, how often an open map stream re-reads
	// the registry — the bound on how long a peer change hides from a
	// connected host. Zero means the package constant.
	MapResend time.Duration

	// RelayOnly strips the peer's endpoint from every netmap: the
	// integration harness's stand-in for a network where UDP to the node
	// cannot pass, forcing the relay leg.
	RelayOnly bool
}

// App is the coordination application: the noise channel of the client
// protocol carrying registration behind the admission seam, the netmap holding
// one peer, and the DERP relay fallback — its three surfaces handed to the
// node's assembly, which serves them over the core's WebPKI identity on the
// HTTPS port it owns. Minimal by decision: no ACL engine, no naming, no user
// management, no key expiry, no credential minting, no listener of its own.
type App struct {
	cfg        Config
	machineKey key.MachinePrivate

	derp derpServer

	// admissionMtx serializes the admission transaction — the registry read,
	// the idempotency check, the seam's ask, the allocation, and the record
	// hold it together, whatever the seam's latency — so concurrent
	// admissions read in order and allocate distinct addresses, and a key
	// racing itself converges on its record. A release and the map path's
	// binding of a record from before the machine claim hold it too, so
	// neither interleaves with an admission or undoes the other. A Telegram
	// prompt's send holds a later registration behind it for as long as its
	// timeout; registration is rare enough that the queue is the honest
	// price of one key, one address.
	admissionMtx sync.Mutex
	// bySource and overall pace the seam's asks — one admission per interval
	// per source address beside one per interval at the door — the bounds
	// the security model's caps name.
	bySource *ratelimit.Keyed[netip.Addr]
	overall  *rate.Limiter
	// mapStreams is the bounded set an open map stream holds one of: past
	// the bound the map answers one full map and closes the stream.
	mapStreams chan struct{}
	// conversations counts the served noise conversations: past the bound
	// the upgrade refuses before the handshake begins.
	conversations atomic.Int64

	// presenceMtx guards presence: what the map handler last observed of
	// each registered host, keyed by its node key.
	presenceMtx sync.Mutex
	presence    map[wireguard.PublicKey]*sighting

	// convMtx guards the open conversations, the relay's client
	// connections, and the closed flag. A conversation or a relay client
	// otherwise ends only when its client leaves, so Close closes the open
	// ones' connections, and once it has marked the application closed no
	// conversation starts and a relay client's connection closes at once.
	convMtx sync.Mutex
	convs   map[*conversationConn]struct{}
	relays  map[net.Conn]struct{}
	closed  bool
	// wg waits for the served noise conversations, so Close returns once
	// the server has closed each one's connection.
	wg sync.WaitGroup
}

// New assembles the application: keys load or create in its own state, the
// DERP server stands on its node key, and the three surfaces mount through
// the configuration's MountHTTPS — the /ts2021 upgrade into the noise
// channel, the /derp relay, and the /key fetch over plain TLS beside them.
func New(cfg Config) (*App, error) {
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
		bySource:   ratelimit.NewKeyed[netip.Addr](admissionMinInterval),
		overall:    rate.NewLimiter(rate.Every(admissionMinInterval), 1),
		mapStreams: make(chan struct{}, maxMapStreams),
		presence:   make(map[wireguard.PublicKey]*sighting),
		convs:      make(map[*conversationConn]struct{}),
		relays:     make(map[net.Conn]struct{}),
	}
	cfg.MountHTTPS("/ts2021", http.HandlerFunc(a.handleNoise))
	cfg.MountHTTPS("/derp", a.relayHandler())
	// The client's first exchange is the key fetch over plain TLS: the
	// noise machine key it must know before the handshake can begin.
	cfg.MountHTTPS("/key", http.HandlerFunc(a.handleKey))
	return a, nil
}

// Run is the application's place in the node's start walk: every surface
// it serves is mounted on the node's HTTPS server, so the loop holds the
// context and ends with it.
func (a *App) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Close retires the application: the served noise conversations and the
// relay with its connected clients. It marks the application closed, so no
// conversation starts after it and a relay client's connection closes at
// once, and closes each open conversation's connection and each relay
// client's, for their clients may never leave; it returns once the server
// has finished with each conversation and the relay with each client. A
// second call releases nothing.
func (a *App) Close() {
	a.convMtx.Lock()
	a.closed = true
	for conv := range a.convs {
		conv.abort()
	}
	for conn := range a.relays {
		_ = conn.Close()
	}
	a.convMtx.Unlock()
	a.wg.Wait()
	_ = a.derp.close()
}
