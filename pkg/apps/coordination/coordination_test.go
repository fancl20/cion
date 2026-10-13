package coordination

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// askAuthorizer records the facts it is asked with and answers as told,
// after the delay a slow seam answers in.
type askAuthorizer struct {
	mtx    sync.Mutex
	asked  []enrollauth.AdmissionFacts
	answer enrollauth.AdmissionAnswer
	delay  time.Duration
}

func (a *askAuthorizer) Authorize(
	_ context.Context, f enrollauth.AdmissionFacts) enrollauth.AdmissionAnswer {

	a.mtx.Lock()
	a.asked = append(a.asked, f)
	a.mtx.Unlock()
	if a.delay > 0 {
		time.Sleep(a.delay)
	}
	return a.answer
}

func (a *askAuthorizer) asks() []enrollauth.AdmissionFacts {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return append([]enrollauth.AdmissionFacts(nil), a.asked...)
}

// testCert presents the shared test CA's certificate for webpkitest.Domain
// and 127.0.0.1, returning the pool that trusts the CA and the TLS
// configuration that presents the certificate.
func testCert(t *testing.T) (*x509.CertPool, *tls.Config) {
	t.Helper()
	ca := webpkitest.New(t)
	pair, err := tls.LoadX509KeyPair(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return ca.Pool, &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	}
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
	cfg.Domain = webpkitest.Domain
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
