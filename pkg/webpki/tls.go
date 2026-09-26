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
)

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
// TLS-ALPN-01 challenge port: with certificate files configured it loads
// them once; otherwise certmagic's ACME machinery stands ready, its
// HTTP-01 challenge answered on the dedicated port 80, and the maintenance
// runs under Manage. A caller that serves its own TLS on port 443 — the
// coordination endpoint of ADR-0011, whose GetCertificate answers the
// TLS-ALPN-01 challenge beside its own protocols — takes this half; a
// caller that serves nothing on 443 takes ManageTLSCert, which binds the
// dedicated challenge listener.
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

// ManageTLSCert prepares the certificate identity and serves the parts a
// core that holds no port of its own needs: the ACME TLS-ALPN-01 challenge
// answered on a dedicated TCP listener, port 443, and the maintenance
// running until the context ends. With certificate files configured it
// loads them once.
func ManageTLSCert(ctx context.Context, cfg TLSCertConfig) (*tls.Config, error) {
	manager, err := PrepareTLSCert(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if manager.magic != nil {
		if err := serveTLSALPN01(ctx, manager.magic.TLSConfig()); err != nil {
			return nil, err
		}
		if err := manager.Manage(ctx); err != nil {
			return nil, err
		}
	}
	return manager.TLSConfig(), nil
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

// serveTLSALPN01 answers the ACME TLS-ALPN-01 challenge on a dedicated TCP
// listener, port 443. The challenge is solved by completing a TLS handshake
// presenting the challenge certificate certmagic mints into its cache, so
// plain handshakes are all the listener does.
func serveTLSALPN01(ctx context.Context, conf *tls.Config) error {
	ln, err := tls.Listen("tcp", ":443", conf)
	if err != nil {
		return fmt.Errorf("binding TLS-ALPN-01 challenge port: %w", err)
	}
	go func() {
		defer func() { _ = ln.Close() }()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() == nil {
					slog.Error("TLS-ALPN-01 accept", "err", err)
				}
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				if c, ok := conn.(*tls.Conn); ok {
					// The handshake itself answers the challenge; the
					// connection carries no application protocol.
					_ = c.HandshakeContext(hctx)
				}
			}()
		}
	}()
	return nil
}
