package scionrpc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// The SCION-native channel: peers present their AS certificate chains — issued
// with id-kp-serverAuth and id-kp-clientAuth (PKI draft, Section 2.7.4) —
// mutually authenticated by verifying the chain against the pinned TRC's root
// pool instead of WebPKI roots, with the peer's IA extracted from the
// certificate subject. Whatever a peer presents after its chain — its
// membership — goes beside the chain to the credentials, which decide it. A
// node that has not pinned the TRC yet cannot authenticate anyone: its
// handshakes degrade to encryption without authentication, the window in
// which a fresh node receives the unverified beacons that route its
// enrollment fetch, and a connection it accepts then serves no peer identity
// for its life. Beacons carry the authoritative signature; this layer
// authenticates the transport.

// EndpointTLSConfig configures the endpoint's two channels.
type EndpointTLSConfig struct {
	// Domain is the core's WebPKI identity. A domain's bootstrap clients
	// offer it as the TLS server name; an address's arrive nameless, Go's
	// client omitting the SNI extension for an address-shaped ServerName.
	// Empty on non-core nodes, which serve only the SCION-native channel.
	Domain string
	// WebPKI serves the bootstrap channel; typically from
	// pkg/core/webpki's PrepareTLSCert. Nil disables the channel.
	WebPKI *tls.Config
	// Credentials provide the node's AS chain for the SCION-native channel
	// and the TRC anchors peers' chains verify against.
	Credentials Credentials
	// Key is the AS key behind the chain.
	Key crypto.Signer
}

// EndpointTLS composes the endpoint's TLS configuration: the bootstrap channel
// — the WebPKI certificate for the clients the identity takes, a domain's
// naming it as the TLS server name and an address's arriving nameless — and
// the SCION-native channel for everything else, configured per handshake so
// each marks its own connection's record.
func EndpointTLS(cfg EndpointTLSConfig) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if cfg.WebPKI != nil && bootstrapHello(chi.ServerName, cfg.Domain) {
				return cfg.WebPKI, nil
			}
			return nativeServerTLS(cfg, handshakeOf(chi.Context())), nil
		},
	}
}

// nativeServerTLS returns the SCION-native channel's configuration for one
// handshake: any client certificate required, verified against the TRC once
// the node has pinned one, and a chain that verifies marks the handshake's
// record h, when it has one. It issues no session tickets: crypto/tls skips
// VerifyPeerCertificate on a resumed session and carries over the
// certificates of the handshake it resumes, so a resumption would outlive
// the trust that handshake ran under.
func nativeServerTLS(cfg EndpointTLSConfig, h *handshake) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{"h3"},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nativeCert(cfg.Credentials, cfg.Key)
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			verified, err := verifyPeerChain(cfg.Credentials, nil, rawCerts)
			if verified && h != nil {
				h.verified.Store(true)
			}
			return err
		},
	}
}

// bootstrapHello reports whether a ClientHello takes the bootstrap channel:
// a domain identity by offering it as the TLS server name, an address
// identity by carrying no name at all — RFC 6066 admits DNS names alone in
// the SNI extension, so the bootstrap client's hello against an address
// identity arrives nameless. No ambiguity arises: the native channel's
// clients always name their peer, the ISD-AS set on every dial.
func bootstrapHello(offered, identity string) bool {
	if _, err := netip.ParseAddr(identity); err == nil {
		return offered == ""
	}
	return offered == identity
}

// nativeClientTLS returns the client TLS configuration for a connection to
// the given peer over the SCION-native channel: the node's chain as the
// client certificate, and — when verifyServer is set — the peer's chain
// verified against the pinned TRC, with its subject naming the expected IA.
// Beacon sends clear verifyServer: their receivers may not be enrolled yet,
// and the PCB's signatures authenticate the path authoritatively.
func nativeClientTLS(
	peer addr.IA,
	creds Credentials,
	key crypto.Signer,
	verifyServer bool,
) *tls.Config {

	conf := &tls.Config{
		// The peer's IA names the connection; verification below is anchored
		// in the TRC, not in the server name.
		ServerName:         peer.String(),
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true, // verified against the TRC below
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nativeCert(creds, key)
		},
	}
	if verifyServer {
		conf.VerifyPeerCertificate = verifyChainAgainstTRC(creds, &peer)
	}
	return conf
}

// verifyChainAgainstTRC returns a VerifyPeerCertificate callback applying
// verifyPeerChain.
func verifyChainAgainstTRC(creds Credentials, expected *addr.IA) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		_, err := verifyPeerChain(creds, expected, rawCerts)
		return err
	}
}

// verifyPeerChain checks that the presented chain — the first two
// certificates the peer presented — verifies against the anchor pool — the
// pinned newest TRC's roots, the predecessor's beside them while the newest
// is within its grace period — and, when expected is non-nil, that its
// subject names the expected IA, reporting whether it verified one. A chain
// that passes is handed to the credentials to decide, beside the
// certificates the peer presented after it. Without a pinned TRC every
// chain is accepted unverified — the bootstrap window — and none is decided.
func verifyPeerChain(creds Credentials, expected *addr.IA, rawCerts [][]byte) (bool, error) {
	if len(rawCerts) == 0 {
		return false, errors.New("peer presented no certificate")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return false, fmt.Errorf("parsing certificate: %w", err)
		}
		certs[i] = cert
	}
	chain, presented := certs[:min(2, len(certs))], certs[min(2, len(certs)):]
	pool, err := creds.AnchorPool()
	if err != nil {
		return false, err
	}
	if len(pool) == 0 {
		slog.Warn("SCION-native handshake without a pinned TRC; peer not authenticated",
			"peer", chainSubjectIA(chain))
		return false, nil
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC: pool,
	}); err != nil {
		return false, fmt.Errorf("chain does not verify against the anchor pool: %w", err)
	}
	if expected != nil {
		ia, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			return false, fmt.Errorf("extracting peer ISD-AS from certificate: %w", err)
		}
		if !ia.Equal(*expected) {
			return false, serrors.New("certificate is for another ISD-AS",
				"expected", *expected, "actual", ia)
		}
	}
	if err := creds.AcceptChain(chain, presented); err != nil {
		return false, fmt.Errorf("chain refused: %w", err)
	}
	return true, nil
}

// nativeCert returns the node's AS chain as a TLS certificate, the
// certificates its credentials present beside the chain after it. A node
// without a valid chain gets an ephemeral self-signed one: it can then
// receive beacons — whose signatures it cannot verify yet anyway — but not
// send anything whose authentication would matter.
func nativeCert(creds Credentials, key crypto.Signer) (*tls.Certificate, error) {
	ctx := context.Background()
	chain, err := creds.Chain(ctx)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return ephemeralCert()
	}
	beside, err := creds.Beside(ctx, chain)
	if err != nil {
		return nil, err
	}
	raw := make([][]byte, 0, len(chain)+len(beside))
	for _, cert := range chain {
		raw = append(raw, cert.Raw)
	}
	for _, cert := range beside {
		raw = append(raw, cert.Raw)
	}
	return &tls.Certificate{
		Certificate: raw,
		PrivateKey:  key,
		Leaf:        chain[0],
	}, nil
}

// ephemeralCache holds the self-signed certificate serving un-enrolled nodes.
var ephemeralCache struct {
	mtx   sync.Mutex
	cert  *tls.Certificate
	until time.Time
}

// ephemeralCert mints a self-signed certificate valid for an hour; fresh
// ones replace expired ones.
func ephemeralCert() (*tls.Certificate, error) {
	ephemeralCache.mtx.Lock()
	defer ephemeralCache.mtx.Unlock()
	if ephemeralCache.cert != nil && time.Now().Before(ephemeralCache.until) {
		return ephemeralCache.cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serial),
		Subject:      pkix.Name{CommonName: "cion un-enrolled control endpoint"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ephemeralCache.cert = &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	ephemeralCache.until = now.Add(time.Hour)
	return ephemeralCache.cert, nil
}

// chainSubjectIA extracts the IA of a chain's leaf subject for logging.
func chainSubjectIA(chain []*x509.Certificate) addr.IA {
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return 0
	}
	return ia
}
