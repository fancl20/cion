package webpki

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// HTTPSPort is the node's HTTPS port — internet HTTPS's one port, where the
// ACME TLS-ALPN challenge is answered beside whatever protocols the mounted
// apps speak.
const HTTPSPort = "443"

// readHeaderTimeout bounds one request's header read — the only
// server-level bound the HTTPS surface carries.
const readHeaderTimeout = 30 * time.Second

// shortlivedProfile is the issuer profile an address identity certifies
// under — the one the CA admits an ip identifier by, its certificates
// living 160 hours inside the maintenance's renewal.
const shortlivedProfile = "shortlived"

// sharedRange is the carrier-grade NAT block, an address of which no public
// CA validates beside the ranges the netip predicates name.
var sharedRange = netip.MustParsePrefix("100.64.0.0/10")

// TLSCertConfig describes how the endpoint's TLS certificate is obtained:
// explicit certificate files, or a certificate for the identity managed
// via ACME (certmagic) as the default.
type TLSCertConfig struct {
	// Domain is the identity the certificate answers for. It is a TLS
	// identity, never resolved: the SCION link is the locator.
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
	// cache holds magic's certificates and runs their renewals; nil for
	// static files.
	cache *certmagic.Cache
	// http01 answers the HTTP-01 challenge on port 80, and http01Done
	// closes once its Serve has returned; nil for static files.
	http01     *http.Server
	http01Done <-chan struct{}
}

// PrepareTLSCert prepares the certificate identity without binding the
// HTTPS port: with certificate files configured it loads them once;
// otherwise certmagic's ACME machinery stands ready, its HTTP-01 challenge
// answered on the dedicated port 80 until Close, and the maintenance runs
// under Manage. Every core takes this half and serves it on the node's
// HTTPS server — ListenHTTPS and ServeHTTPS below — where the TLS-ALPN-01
// challenge is answered beside the mounted apps' own protocols (proposal
// 0023).
func PrepareTLSCert(cfg TLSCertConfig) (*CertManager, error) {
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

	// An address identity takes the shortlived profile — the one the CA
	// certifies ip identifiers under — and a range no public CA validates
	// refuses the boot before any resource binds: an address that cannot
	// certify would retry its issuance forever under the maintenance's
	// Degrade. The refusal names the certificate files the offline
	// deployment uses.
	isAddress := false
	if parsed, err := netip.ParseAddr(cfg.Domain); err == nil {
		if nonvalidatable := unvalidatableRange(parsed.Unmap()); nonvalidatable != "" {
			return nil, fmt.Errorf("--trust.domain %s is %s, a range no public CA "+
				"validates: use the certificate files (--trust.cert-file, "+
				"--trust.key-file) instead", cfg.Domain, nonvalidatable)
		}
		isAddress = true
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
	if isAddress {
		issuer.Profile = shortlivedProfile
	}

	// The HTTP-01 challenge must be answerable before issuance starts; the
	// TLS-ALPN-01 challenge rides whichever server holds port 443.
	http01, http01Done, err := serveHTTP01(issuer)
	if err != nil {
		cache.Stop()
		return nil, err
	}
	return &CertManager{
		tlsCfg: &tls.Config{
			GetCertificate: magic.GetCertificate,
			NextProtos:     []string{"h3"},
			MinVersion:     tls.VersionTLS13,
		},
		magic:      magic,
		domain:     cfg.Domain,
		cache:      cache,
		http01:     http01,
		http01Done: http01Done,
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

// Manage maintains the ACME-managed certificate until the context ends:
// certmagic obtains it in the background, retrying a failed issuance at its
// own backoff, and the cache renews it on its schedule. It returns nil once
// the context ends — the end cancels the retries — or the error that kept
// the maintenance from starting. A static-file identity has nothing to
// manage and runs no Manage.
func (m *CertManager) Manage(ctx context.Context) error {
	if err := m.magic.ManageAsync(ctx, []string{m.domain}); err != nil {
		return fmt.Errorf("managing the certificate for %s: %w", m.domain, err)
	}
	<-ctx.Done()
	return nil
}

// Close stops the certificate cache's renewals and shuts the HTTP-01
// challenge server down, returning once its Serve has returned and port 80
// is free. A static-file manager releases nothing.
func (m *CertManager) Close() error {
	if m.magic == nil {
		return nil
	}
	m.cache.Stop()
	err := m.http01.Close()
	<-m.http01Done
	return err
}

// ListenHTTPS binds the node's HTTPS server on the address the assembly
// names, through the socket source — the listener held when the call
// returns, so the certificate maintenance launches against a listening
// server and a first issuance's probe finds the port answered. The TLS
// configuration is the shared identity's clone advertising http/1.1 and the
// ACME TLS-ALPN name: the mounted handler's protocol and the challenge
// inside one handshake, both answered by the one GetCertificate.
func (m *CertManager) ListenHTTPS(addr string, sockets underlay.Sockets) (net.Listener, error) {
	ln, err := sockets.NewTCP(addr)
	if err != nil {
		return nil, fmt.Errorf("binding the HTTPS port: %w", err)
	}
	return tls.NewListener(ln, m.httpsTLSConfig()), nil
}

// ServeHTTPS serves the handler on the listener until the context is
// canceled. The server carries the settings the surface needs — a
// read-header timeout and nothing beside — for the netmap poll and the
// relay conversations are long-lived connections a server-level write
// timeout would cut. The context's end closes the server — the listener and
// the connections it tracks; a hijacked connection stays its handler's —
// and ServeHTTPS returns with them closed, waiting on a close already under
// way, for a second Close returns before the first's release finishes.
func (m *CertManager) ServeHTTPS(
	ctx context.Context, ln net.Listener, handler http.Handler,
) error {

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	release := sync.OnceValue(srv.Close)
	stop := context.AfterFunc(ctx, func() { _ = release() })
	defer func() {
		stop()
		_ = release()
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

// unvalidatableRange names the range an address belongs to that no public
// CA validates — private, loopback, link-local, shared, unspecified, and
// multicast ranges are the CA's refusals — the empty string for an address
// one validates: a global unicast address outside them.
func unvalidatableRange(addr netip.Addr) string {
	switch {
	case addr.IsUnspecified():
		return "an unspecified address"
	case addr.IsLoopback():
		return "a loopback address"
	case addr.IsMulticast():
		return "a multicast address"
	case addr.IsLinkLocalUnicast():
		return "a link-local address"
	case addr.IsPrivate():
		return "a private address"
	case sharedRange.Contains(addr):
		return "a shared address"
	}
	return ""
}

// serveHTTP01 answers the ACME HTTP-01 challenge on a dedicated TCP
// listener, port 80, returning the server and a channel that closes once
// its Serve has returned.
func serveHTTP01(issuer *certmagic.ACMEIssuer) (*http.Server, <-chan struct{}, error) {
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return nil, nil, fmt.Errorf("binding HTTP-01 challenge port: %w", err)
	}
	srv := &http.Server{Handler: issuer.HTTPChallengeHandler(http.NotFoundHandler())}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP-01 challenge server exited", "err", err)
		}
	}()
	return srv, done, nil
}
