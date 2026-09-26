package coordination

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/controlplane"
)

// DefaultPort is the coordination endpoint's port: the one port internet
// HTTPS means, beside which the ACME TLS-ALPN challenge is answered — the
// dedicated challenge listener a coordination-serving core once needed
// retires with this server standing on 443.
const DefaultPort = "443"

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
	// Addr is the HTTPS listen address, "host:port"; the port defaults to
	// DefaultPort when Addr names none.
	Addr string
	// TLS presents the WebPKI certificate — certmagic's machinery behind
	// --domain, the same GetCertificate the SCION endpoint's channel rides,
	// consumed here where hosts can reach it: hosts are plain internet
	// clients. Its GetCertificate also answers the TLS-ALPN challenge on
	// this listener.
	TLS *tls.Config
	// Store is the registry: node entries read for the netmap and
	// allocation, host entries written at admission.
	Store Store
	// Authorizer gates registrations — the same seam the trust service
	// asks at first issuance, asked here with the registration boundary's
	// facts. Nil is open admission, the zero-conf default.
	Authorizer controlplane.AdmissionAuthorizer
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

// App is the coordination application (ADR-0011): an internet-facing HTTPS
// server on the core's domain presenting the WebPKI certificate, the noise
// channel of the client protocol inside it carrying registration behind the
// admission seam and the netmap holding one peer, and the DERP relay
// fallback beside them. Minimal by decision: no ACL engine, no naming, no
// user management, no key expiry, no credential minting.
type App struct {
	cfg        Config
	machineKey key.MachinePrivate

	derp  derpServer
	https *http.Server

	// wg waits for the served noise conversations, so Close waits for what
	// Run began.
	wg sync.WaitGroup
}

// New assembles the application: keys load or create in its own state, the
// DERP server stands on its node key, and the two HTTP surfaces mount — the
// /ts2021 upgrade into the noise channel, the /derp relay. Run serves.
func New(cfg Config) (*App, error) {
	if cfg.Domain == "" {
		return nil, errors.New("no domain configured")
	}
	if cfg.TLS == nil {
		return nil, errors.New("no TLS configuration for the coordination endpoint")
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
	// The outer server speaks HTTP/1.1 — the client protocol's upgrade and
	// the relay's both ride it — and answers the ACME TLS-ALPN challenge
	// beside, through the shared certificate machinery.
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.NextProtos = []string{"http/1.1", acmez.ACMETLS1Protocol}
	a.https = &http.Server{
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
	}
	return a, nil
}

// Run serves the coordination endpoint until the context is canceled — the
// core's one host-facing surface, beside the WireGuard application.
func (a *App) Run(ctx context.Context) error {
	listener, err := a.listen()
	if err != nil {
		return err
	}
	return a.serve(ctx, listener)
}

// listen binds the coordination endpoint's HTTPS port.
func (a *App) listen() (net.Listener, error) {
	addr := a.cfg.Addr
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		addr = net.JoinHostPort(addr, DefaultPort)
	}
	listener, err := tls.Listen("tcp", addr, a.https.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("binding the coordination endpoint: %w", err)
	}
	return listener, nil
}

// serve answers the endpoint until the context is canceled.
func (a *App) serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	slog.Info("Serving the coordination application",
		"domain", a.cfg.Domain, "addr", listener.Addr().String())
	err := a.https.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		return err
	}
	return nil
}

// Close retires the application: the HTTPS server and its conversations,
// the relay with its connected clients.
func (a *App) Close() error {
	_ = a.https.Close()
	a.wg.Wait()
	return a.derp.close()
}
