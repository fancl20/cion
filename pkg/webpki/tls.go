package webpki

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
)

// HTTPSPort is the node's HTTPS port — internet HTTPS's one port, where the
// ACME TLS-ALPN challenge is answered beside whatever protocols the mounted
// apps speak.
const HTTPSPort = "443"

// readHeaderTimeout bounds one request's header read — the only
// server-level bound the HTTPS surface carries.
const readHeaderTimeout = 30 * time.Second

// TLSCertConfig describes how the endpoint's TLS certificate is obtained:
// explicit certificate files, or a certificate for the domain managed via
// ACME (certmagic) as the default.
type TLSCertConfig struct {
	// Domain is the DNS domain of the certificate. It is a TLS identity,
	// never resolved: the SCION link is the locator.
	Domain string
	// Email is the ACME account email; empty lets the ACME server ask for
	// one interactively or proceed without.
	Email string
	// CertFile and KeyFile point at the certificate and key in PEM format;
	// when set, they take precedence over ACME. This is the fallback for
	// offline deployments.
	CertFile string
	KeyFile  string
	// Storage is the directory for ACME state, e.g. account keys and
	// obtained certificates. Empty defaults to certmagic's data directory.
	Storage string
}

// CertManager is the prepared certificate identity: a TLS configuration
// whose GetCertificate presents the certificate — the one configuration
// every serving surface of the core's domain clones for its own protocol
// set — and, under ACME, the maintenance that keeps the certificate
// current.
type CertManager struct {
	tlsCfg *tls.Config
	// magic maintains the certificate under ACME; nil for static files.
	magic *certmagic.Config
	// domain is the maintained name; empty for static files.
	domain string
}

// PrepareTLSCert prepares the certificate identity without binding the
// HTTPS port: with certificate files configured it loads them once;
// otherwise certmagic's ACME machinery stands ready, its HTTP-01 challenge
// answered on the dedicated port 80, and the maintenance runs under
// Manage. Every core takes this half and serves it on the node's HTTPS
// server — ListenHTTPS and ServeHTTPS below — where the TLS-ALPN-01
// challenge is answered beside the mounted apps' own protocols (proposal
// 0023).
func PrepareTLSCert(ctx context.Context, cfg TLSCertConfig) (*CertManager, error) {
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		return &CertManager{tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS13,
		}}, nil
	}
	if cfg.Domain == "" {
		return nil, errors.New("TLSCertConfig needs a domain or certificate files")
	}

	var storage certmagic.Storage
	if cfg.Storage != "" {
		storage = &certmagic.FileStorage{Path: cfg.Storage}
	}
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})
	magic = certmagic.New(cache, certmagic.Config{Storage: storage})
	issuer, ok := magic.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		cache.Stop()
		return nil, fmt.Errorf("certmagic did not configure an ACME issuer")
	}
	issuer.Email = cfg.Email

	// The HTTP-01 challenge must be answerable before issuance starts; the
	// TLS-ALPN-01 challenge rides whichever server holds port 443.
	if err := serveHTTP01(ctx, issuer); err != nil {
		cache.Stop()
		return nil, err
	}
	return &CertManager{
		tlsCfg: &tls.Config{
			GetCertificate: magic.GetCertificate,
			NextProtos:     []string{"h3"},
			MinVersion:     tls.VersionTLS13,
		},
		magic:  magic,
		domain: cfg.Domain,
	}, nil
}

// TLSConfig returns the prepared identity. The configuration is shared, not
// copied: a serving surface clones it and names its own protocols.
func (m *CertManager) TLSConfig() *tls.Config { return m.tlsCfg }

// ACMEManaged reports whether certmagic maintains the identity — the
// certificate obtained and renewed under ACME, its TLS-ALPN-01 challenge
// answered on the HTTPS port. Static files manage nothing and bind no port
// of their own.
func (m *CertManager) ACMEManaged() bool { return m.magic != nil }

// Manage maintains the certificate — obtaining it at first need and
// renewing it on the cache's own schedule. Static files manage nothing.
func (m *CertManager) Manage(ctx context.Context) error {
	if m.magic == nil {
		return nil
	}
	if err := m.magic.ManageSync(ctx, []string{m.domain}); err != nil {
		return fmt.Errorf("obtaining certificate for %s: %w", m.domain, err)
	}
	return nil
}

// ListenHTTPS binds the node's HTTPS server on the address the assembly
// names — the listener held when the call returns, so the certificate
// maintenance launches against a listening server and a first issuance's
// probe finds the port answered. The TLS configuration is the shared
// identity's clone advertising http/1.1 and the ACME TLS-ALPN name: the
// mounted handler's protocol and the challenge inside one handshake, both
// answered by the one GetCertificate.
func (m *CertManager) ListenHTTPS(addr string) (net.Listener, error) {
	ln, err := tls.Listen("tcp", addr, m.httpsTLSConfig())
	if err != nil {
		return nil, fmt.Errorf("binding the HTTPS port: %w", err)
	}
	return ln, nil
}

// ServeHTTPS serves the handler on the listener until the context is
// canceled. The server carries the settings the surface needs — a
// read-header timeout and nothing beside — for the netmap poll and the
// relay conversations are long-lived connections a server-level write
// timeout would cut.
func (m *CertManager) ServeHTTPS(
	ctx context.Context, ln net.Listener, handler http.Handler,
) error {

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	slog.Info("Serving the node's HTTPS server", "addr", ln.Addr().String())
	err := srv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		return err
	}
	return nil
}

// httpsTLSConfig returns the shared identity cloned for the node's HTTPS
// server: http/1.1 and the ACME TLS-ALPN name beside the GetCertificate
// that answers both — the mounted apps' protocol and the challenge, the
// one a client offering only the challenge name reaches, inside one TLS
// configuration.
func (m *CertManager) httpsTLSConfig() *tls.Config {
	cfg := m.tlsCfg.Clone()
	cfg.NextProtos = []string{"http/1.1", acmez.ACMETLS1Protocol}
	return cfg
}

// serveHTTP01 answers the ACME HTTP-01 challenge on a dedicated TCP
// listener, port 80.
func serveHTTP01(ctx context.Context, issuer *certmagic.ACMEIssuer) error {
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("binding HTTP-01 challenge port: %w", err)
	}
	srv := &http.Server{Handler: issuer.HTTPChallengeHandler(http.NotFoundHandler())}
	go func() {
		defer func() { _ = ln.Close() }()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP-01 challenge server exited", "err", err)
		}
	}()
	return nil
}
