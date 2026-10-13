package webpki

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// idPEACMEIdentifierV1 is the certificate extension an ACME TLS-ALPN
// challenge certificate carries (RFC 8737 §6.1).
var idPEACMEIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// serveHTTPS serves the manager's HTTPS server on the listener under the
// test's supervision.
func serveHTTPS(t *testing.T, m *CertManager, ln net.Listener, handler http.Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.ServeHTTPS(ctx, ln, handler) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ServeHTTPS(%v) = %v, want nil", ln.Addr(), err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the HTTPS server did not stop")
		}
	})
}

// TestServeHTTPSHTTP11 checks the serving half against a static-file
// identity: the bind returns with the port held, and a plain HTTP/1.1
// request reaches the mounted handler over the loaded certificate.
func TestServeHTTPSHTTP11(t *testing.T) {
	ca := webpkitest.New(t)
	manager, err := PrepareTLSCert(TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: ca.CertFile,
		KeyFile:  ca.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mounted", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mounted"))
	})
	ln, err := manager.ListenHTTPS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// The bind returns with the port held: the listener answers before
	// anything serves it, so the certificate maintenance can launch
	// against a listening server.
	probe, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("the port is not held after the bind: %v", err)
	}
	_ = probe.Close()
	serveHTTPS(t, manager, ln, mux)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: ca.Pool,
	}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/mounted")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("the served protocol = %s, want HTTP/1.1", resp.Proto)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "mounted" {
		t.Errorf("the mounted handler's body = %q, want %q", body, "mounted")
	}
}

// TestServeHTTPSReleasesOnCancel checks the server's stop: once its context
// ends, ServeHTTPS closes the server — the listener and the connection it
// tracks, an idle keep-alive here — and returns nil with the port released,
// the address binding again at once.
func TestServeHTTPSReleasesOnCancel(t *testing.T) {
	ca := webpkitest.New(t)
	manager, err := PrepareTLSCert(TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: ca.CertFile,
		KeyFile:  ca.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The package's own loopback host, where only a wildcard bind can take
	// the port between the release and the rebind below.
	ln, err := manager.ListenHTTPS("127.0.0.129:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- manager.ServeHTTPS(ctx, ln, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	}()

	conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: ca.Pool, ServerName: webpkitest.Domain})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req, err := http.NewRequest(http.MethodGet, "https://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	cancel()
	if err := <-served; err != nil {
		t.Errorf("ServeHTTPS = %v, want nil once its context ended", err)
	}
	// The idle connection's read ends with the server's close; the deadline
	// bounds only a connection the stop left open.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := reader.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the idle connection outlived the stop: read = %v", err)
	}
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("the HTTPS address did not bind again: %v", err)
	}
	_ = rebound.Close()
}

// TestServeHTTPSACMEChallenge checks the challenge answers on the mounted
// server — no dedicated listener: a client offering only acme-tls/1
// completes its handshake against certmagic's challenge certificate,
// served from the cache the challenge was seeded into, with the extension
// RFC 8737 names carried by the certificate itself.
func TestServeHTTPSACMEChallenge(t *testing.T) {
	manager, ln := acmeManager(t, webpkitest.Domain)
	serveHTTPS(t, manager, ln, http.NotFoundHandler())

	// An ACME probe: SNI naming the domain, the challenge name the one
	// protocol offered. The challenge certificate is self-signed — the ACME
	// verifier reads the extension, not a chain — so the client verifies
	// nothing here.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		NextProtos:         []string{acmez.ACMETLS1Protocol},
		ServerName:         webpkitest.Domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("the challenge handshake against the mounted server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != acmez.ACMETLS1Protocol {
		t.Fatalf("the negotiated protocol = %q, want %q", proto, acmez.ACMETLS1Protocol)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("the challenge handshake presented no certificate")
	}
	for _, ext := range certs[0].Extensions {
		if ext.Id.Equal(idPEACMEIdentifierV1) {
			return
		}
	}
	t.Errorf("the served certificate carries no ACME identifier extension, "+
		"want the challenge's (subject %q)", certs[0].Subject.CommonName)
}

// acmeManager builds a certmagic-backed identity — PrepareTLSCert's ACME
// arm without its port-80 listener — with a solved TLS-ALPN challenge
// seeded into the cache the way a distributed solve stores it, and binds
// the node's HTTPS server for it.
func acmeManager(t *testing.T, domain string) (*CertManager, net.Listener) {
	t.Helper()
	magic, issuer := newTestIssuer(t)
	seedChallenge(t, magic, issuer, acme.Challenge{
		Type:             "tls-alpn-01",
		Token:            "token",
		KeyAuthorization: "key-authorization",
		Identifier:       acme.Identifier{Type: "dns", Value: domain},
	})
	manager := &CertManager{
		tlsCfg: &tls.Config{
			GetCertificate: magic.GetCertificate,
			MinVersion:     tls.VersionTLS13,
		},
		magic:  magic,
		domain: domain,
	}
	ln, err := manager.ListenHTTPS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return manager, ln
}

// newTestIssuer builds certmagic's ACME machinery over a throwaway storage,
// the identity the tests seed and read challenges through.
func newTestIssuer(t *testing.T) (*certmagic.Config, *certmagic.ACMEIssuer) {
	t.Helper()
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})
	magic = certmagic.New(cache, certmagic.Config{Storage: storage})
	t.Cleanup(cache.Stop)
	issuer, ok := magic.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatal("certmagic did not configure an ACME issuer")
	}
	return magic, issuer
}

// seedChallenge stores one solved challenge where certmagic's distributed
// solve leaves it — the store its own handlers read the challenge from.
func seedChallenge(
	t *testing.T, magic *certmagic.Config, issuer *certmagic.ACMEIssuer, chal acme.Challenge,
) {

	t.Helper()
	raw, err := json.Marshal(chal)
	if err != nil {
		t.Fatal(err)
	}
	tokenKey := filepath.Join("acme",
		certmagic.StorageKeys.Safe(issuer.IssuerKey()), "challenge_tokens",
		certmagic.StorageKeys.Safe(chal.Identifier.Value)+".json")
	if err := magic.Storage.Store(context.Background(), tokenKey, raw); err != nil {
		t.Fatal(err)
	}
}

// TestHTTP01ChallengeSolves checks the dedicated challenge server: an
// HTTP-01 validation on the conventional port 80 — the number the ACME
// drafts fix for it, the reason the episode binds it — is answered with the
// seeded key authorization, and every other request reaches the wrapped
// handler.
func TestHTTP01ChallengeSolves(t *testing.T) {
	magic, issuer := newTestIssuer(t)
	domain := "cion-core-01.test"
	seedChallenge(t, magic, issuer, acme.Challenge{
		Type:             "http-01",
		Token:            "token",
		KeyAuthorization: "token.key-authorization",
		Identifier:       acme.Identifier{Type: "dns", Value: domain},
	})

	srv, done, err := serveHTTP01(issuer)
	if err != nil {
		t.Fatalf("serving the HTTP-01 challenge: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	// The validation an ACME CA performs: the identifier as the Host, the
	// challenge's resource path.
	req, err := http.NewRequest(http.MethodGet,
		"http://127.0.0.1/.well-known/acme-challenge/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = domain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the challenge request on port 80: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "token.key-authorization" {
		t.Errorf("the challenge answer = %d %q, want the seeded key authorization",
			resp.StatusCode, body)
	}

	// Every other request reaches the wrapped handler.
	resp, err = http.Get("http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an ordinary request = %d, want the wrapped handler's 404",
			resp.StatusCode)
	}
}

// TestCertManagerClose checks the manager's release: an ACME-managed
// manager answers HTTP-01 on port 80 until Close returns, and the port
// binds again at once; a static-file manager's Close releases nothing and
// returns nil.
func TestCertManagerClose(t *testing.T) {
	manager, err := PrepareTLSCert(TLSCertConfig{
		Domain:  "cion-core-02.test",
		Storage: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get("http://127.0.0.1/")
	if err != nil {
		t.Fatalf("the challenge server did not answer on port 80: %v", err)
	}
	_ = resp.Body.Close()
	if err := manager.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		t.Fatalf("port 80 did not bind again after Close: %v", err)
	}
	_ = ln.Close()

	ca := webpkitest.New(t)
	static, err := PrepareTLSCert(TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: ca.CertFile,
		KeyFile:  ca.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := static.Close(); err != nil {
		t.Errorf("a static-file manager's Close = %v, want nil", err)
	}
}

// TestManageRunsUntilItsContextEnds checks the maintenance against a CA
// that accepts and answers nothing: Manage holds while the issuance waits
// on the CA, and returns nil once its context ends.
func TestManageRunsUntilItsContextEnds(t *testing.T) {
	ca, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ca.Close() }()
	manager, err := PrepareTLSCert(TLSCertConfig{
		Domain:  "cion-core-03.test",
		Storage: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	issuer, ok := manager.magic.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatal("certmagic did not configure an ACME issuer")
	}
	issuer.CA = "https://" + ca.Addr().String() + "/directory"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	managed := make(chan error, 1)
	go func() { managed <- manager.Manage(ctx) }()
	// The issuance reaches the CA, whose silence holds it.
	conn, err := ca.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case err := <-managed:
		t.Fatalf("Manage returned %v while the issuance waited on the CA", err)
	default:
	}
	cancel()
	if err := <-managed; err != nil {
		t.Errorf("Manage = %v once its context ended, want nil", err)
	}
}
