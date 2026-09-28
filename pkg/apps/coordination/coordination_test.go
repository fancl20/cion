package coordination

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// memStore is an in-memory registry.
type memStore struct {
	mtx   sync.Mutex
	nodes []wireguard.Entry
	hosts []wireguard.HostEntry
}

func (s *memStore) Publish(_ context.Context, entry wireguard.Entry) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for i := range s.nodes {
		if s.nodes[i].IA.Equal(entry.IA) {
			s.nodes[i] = entry
			return nil
		}
	}
	s.nodes = append(s.nodes, entry)
	return nil
}

func (s *memStore) PublishHost(_ context.Context, entry wireguard.HostEntry) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for i := range s.hosts {
		if s.hosts[i].PublicKey == entry.PublicKey {
			s.hosts[i] = entry
			return nil
		}
	}
	s.hosts = append(s.hosts, entry)
	return nil
}

func (s *memStore) List(context.Context) (wireguard.Directory, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return wireguard.Directory{
		Nodes: append([]wireguard.Entry(nil), s.nodes...),
		Hosts: append([]wireguard.HostEntry(nil), s.hosts...),
	}, nil
}

func (s *memStore) Close() error { return nil }

// askAuthorizer records the facts it is asked with and answers as told.
type askAuthorizer struct {
	mtx    sync.Mutex
	asked  []enrollauth.AdmissionFacts
	answer enrollauth.AdmissionAnswer
}

func (a *askAuthorizer) Authorize(
	_ context.Context, f enrollauth.AdmissionFacts) enrollauth.AdmissionAnswer {

	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.asked = append(a.asked, f)
	return a.answer
}

func (a *askAuthorizer) asks() []enrollauth.AdmissionFacts {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return append([]enrollauth.AdmissionFacts(nil), a.asked...)
}

// testCert mints a self-signed certificate for 127.0.0.1, the harness's
// stand-in for the WebPKI: the pool that trusts it and the TLS
// configuration that presents it.
func testCert(t *testing.T) (*x509.CertPool, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: TestDomain},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{TestDomain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, certKeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	}
	return pool, tlsCfg
}

// TestDomain is the test core's DNS identity.
const TestDomain = "cion-core.test"

// certKeyPEM wraps a private key in the PEM the key pair loader wants.
func certKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// freePort reserves an ephemeral port and releases it for the listener —
// the port only needs to be free at bind.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return uint16(port)
}

// testNode is one node entry of a test registry.
func testNode(ia addr.IA, subnet string, endpoint string) wireguard.Entry {
	return wireguard.Entry{
		IA:           ia,
		PublicKey:    wireguard.PublicKey{},
		Overlay:      netip.MustParsePrefix(subnet),
		HostEndpoint: netip.MustParseAddrPort(endpoint),
	}
}

// testHostKey derives one host's registry key from a byte.
func testHostKey(b byte) wireguard.PublicKey {
	var key wireguard.PublicKey
	for i := range key {
		key[i] = b
	}
	return key
}

// registeredHost is one host the registry holds, owned by 1-ff00:0:1.
func registeredHost(key wireguard.PublicKey) wireguard.HostEntry {
	return wireguard.HostEntry{
		PublicKey: key,
		Addr:      netip.MustParseAddr("100.64.1.2"),
		IA:        mustIA("1-ff00:0:1"),
		Note:      "telegram operator",
	}
}

// machineZero is the zero machine key, where a test carries none.
func machineZero() key.MachinePublic { return key.MachinePublic{} }

// testApp builds an application around the given registry with the test
// core's identity, its handler ready for an externally assembled server.
func testApp(t *testing.T, cfg Config) *App {
	t.Helper()
	cfg.Domain = TestDomain
	cfg.StateDir = t.TempDir()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func mustIA(s string) addr.IA {
	return addr.MustParseIA(s)
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// ipMasked builds 100.64.1.N-style addresses the way the helper's callers
// enumerate them.
func ipMasked(prefix string, last byte) netip.Addr {
	base := netip.MustParseAddr(prefix + "0")
	b := base.As4()
	b[3] = last
	return netip.AddrFrom4(b)
}
