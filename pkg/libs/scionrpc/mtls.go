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
// certificate subject. A node that has not pinned the TRC yet cannot
// authenticate anyone: its handshakes degrade to encryption without
// authentication, the window in which a fresh node receives the unverified
// beacons that route its enrollment fetch. Beacons carry the authoritative
// signature; this layer authenticates the transport.

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
// the SCION-native channel for everything else.
func EndpointTLS(cfg EndpointTLSConfig) *tls.Config {
	native := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
		// Any client certificate is required, but it is only verified against
		// the TRC once the node has pinned one.
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nativeCert(cfg.Credentials, cfg.Key)
		},
		VerifyPeerCertificate: verifyChainAgainstTRC(cfg.Credentials, nil),
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if cfg.WebPKI != nil && bootstrapHello(chi.ServerName, cfg.Domain) {
				return cfg.WebPKI, nil
			}
			return native, nil
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

// verifyChainAgainstTRC returns a VerifyPeerCertificate callback checking
// that the presented chain verifies against the anchor pool — the pinned
// newest TRC's roots, the predecessor's beside them while the newest is
// within its grace period — and, when expected is non-nil, that its subject
// names the expected IA. Without a pinned TRC every chain is accepted — the
// bootstrap window.
func verifyChainAgainstTRC(creds Credentials, expected *addr.IA) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		chain := make([]*x509.Certificate, len(rawCerts))
		for i, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parsing certificate: %w", err)
			}
			chain[i] = cert
		}
		pool, err := creds.AnchorPool()
		if err != nil {
			return err
		}
		if len(pool) == 0 {
			slog.Warn("SCION-native handshake without a pinned TRC; peer not authenticated",
				"peer", chainSubjectIA(chain))
			return nil
		}
		if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
			TRC: pool,
		}); err != nil {
			return fmt.Errorf("chain does not verify against the anchor pool: %w", err)
		}
		if expected != nil {
			ia, err := cppki.ExtractIA(chain[0].Subject)
			if err != nil {
				return fmt.Errorf("extracting peer ISD-AS from certificate: %w", err)
			}
			if !ia.Equal(*expected) {
				return serrors.New("certificate is for another ISD-AS",
					"expected", *expected, "actual", ia)
			}
		}
		return nil
	}
}

// nativeCert returns the node's AS chain as a TLS certificate. A node without
// a valid chain gets an ephemeral self-signed one: it can then receive
// beacons — whose signatures it cannot verify yet anyway — but not send
// anything whose authentication would matter.
func nativeCert(creds Credentials, key crypto.Signer) (*tls.Certificate, error) {
	chain, err := creds.Chain(context.Background())
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return ephemeralCert()
	}
	return &tls.Certificate{
		Certificate: [][]byte{chain[0].Raw, chain[1].Raw},
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
