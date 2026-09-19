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

// ManageTLSCert returns the server TLS configuration for the endpoint. With
// certificate files configured it loads them once; otherwise the certificate
// for the domain is managed by certmagic, with the ACME HTTP-01 and
// TLS-ALPN-01 challenges answered on dedicated TCP listeners (ports 80 and
// 443) — ACME servers validate over TCP, never QUIC. DNS-01 support follows
// later.
func ManageTLSCert(ctx context.Context, cfg TLSCertConfig) (*tls.Config, error) {
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS13,
		}, nil
	}
	if cfg.Domain == "" {
		return nil, errors.New("TLSCertConfig needs a domain or certificate files")
	}
	return manageACME(ctx, cfg)
}

// manageACME obtains and maintains the domain certificate with certmagic
// and wires serving of the HTTP-01 and TLS-ALPN-01 challenges.
func manageACME(ctx context.Context, cfg TLSCertConfig) (*tls.Config, error) {
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

	// The challenges must be answerable before certificate issuance starts.
	if err := serveHTTP01(ctx, issuer); err != nil {
		cache.Stop()
		return nil, err
	}
	alpnConf := magic.TLSConfig()
	if err := serveTLSALPN01(ctx, alpnConf); err != nil {
		cache.Stop()
		return nil, err
	}

	if err := magic.ManageSync(ctx, []string{cfg.Domain}); err != nil {
		cache.Stop()
		return nil, fmt.Errorf("obtaining certificate for %s: %w", cfg.Domain, err)
	}
	return &tls.Config{
		GetCertificate: magic.GetCertificate,
		NextProtos:     []string{"h3"},
		MinVersion:     tls.VersionTLS13,
	}, nil
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
