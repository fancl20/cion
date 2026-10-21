package apps

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/portal"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// chainFor builds a two-certificate chain whose AS certificate names the
// ISD-AS, carries the subject key ID, and expires at notAfter; the second
// certificate stands in for the CA's.
func chainFor(t *testing.T, ia addr.IA, skid byte, notAfter time.Time) []*x509.Certificate {
	t.Helper()
	cert := func(subject pkix.Name, id []byte) *x509.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      subject,
			SubjectKeyId: id,
			NotBefore:    notAfter.Add(-72 * time.Hour),
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	return []*x509.Certificate{
		cert(pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: cppki.OIDNameIA, Value: ia.String()},
		}}, []byte{skid, skid}),
		cert(pkix.Name{CommonName: "CA"}, []byte{0xca}),
	}
}

// TestPortalRecordsNodes checks the console's view of the nodes: one per
// ISD-AS holding a chain, its newest chain's key and expiry; the roles from
// the founder's ISD-AS and the TRC's cores; and the directory's slice,
// endpoint, and issued count beside each.
func TestPortalRecordsNodes(t *testing.T) {
	ctx := t.Context()
	founder, core := addr.MustParseIA("1-ff00:0:1"), addr.MustParseIA("1-ff00:0:2")
	node := addr.MustParseIA("1-ff00:0:3")
	now := time.Now().UTC().Truncate(time.Second)
	chains := [][]*x509.Certificate{
		chainFor(t, founder, 0x01, now.Add(72*time.Hour)),
		chainFor(t, core, 0x02, now.Add(60*time.Hour)),
		chainFor(t, node, 0x03, now.Add(24*time.Hour)),
		chainFor(t, node, 0x03, now.Add(48*time.Hour)),
	}
	registry := &dbtest.MemStore{}
	registry.Seed(wireguard.Entry{
		IA:           founder,
		Overlay:      netip.MustParsePrefix("100.64.0.0/24"),
		HostEndpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
	})
	for i, a := range []string{"100.64.0.2", "100.64.0.3"} {
		if err := registry.PublishHost(ctx, wireguard.HostEntry{
			PublicKey: dbtest.MustKey(byte(0x80 + i)),
			Addr:      netip.MustParseAddr(a),
			IA:        founder,
		}); err != nil {
			t.Fatal(err)
		}
	}
	r := &portalRecords{
		chains:   func(context.Context) ([][]*x509.Certificate, error) { return chains, nil },
		cores:    func(addr.ISD) ([]addr.IA, error) { return []addr.IA{founder, core}, nil },
		founder:  founder,
		registry: registry,
	}
	nodes, err := r.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []portal.Node{
		{
			IA:       founder,
			Key:      "0101",
			Expires:  now.Add(72 * time.Hour),
			Role:     portal.RoleFounder,
			Overlay:  netip.MustParsePrefix("100.64.0.0/24"),
			Endpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
			Issued:   2,
		},
		{IA: core, Key: "0202", Expires: now.Add(60 * time.Hour), Role: portal.RoleCore},
		{IA: node, Key: "0303", Expires: now.Add(48 * time.Hour), Role: portal.RoleNode},
	}
	if diff := cmp.Diff(want, nodes,
		cmpopts.EquateComparable(netip.Prefix{}, netip.AddrPort{})); diff != "" {
		t.Errorf("the nodes mismatch (-want +got):\n%s", diff)
	}
}

// TestPortalRecordsHosts checks the console's view of the hosts: the
// registry's entries sorted by address with the claims their admission
// recorded and a legacy record's empty machine key; a release reaching the
// registry through the coordination application; and neither without it.
func TestPortalRecordsHosts(t *testing.T) {
	ctx := t.Context()
	owner := addr.MustParseIA("1-ff00:0:1")
	registry := &dbtest.MemStore{}
	recorded := []wireguard.HostEntry{
		{
			PublicKey: dbtest.MustKey(0x82),
			Addr:      netip.MustParseAddr("100.64.0.3"),
			IA:        owner,
		},
		{
			PublicKey:  dbtest.MustKey(0x81),
			MachineKey: dbtest.MustKey(0x91),
			Addr:       netip.MustParseAddr("100.64.0.2"),
			IA:         owner,
			Note:       "portal operator",
			Hostname:   "laptop",
			OS:         "linux",
		},
	}
	for _, h := range recorded {
		if err := registry.PublishHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	coord, err := coordination.New(coordination.Config{
		Domain:     webpkitest.Domain,
		Store:      registry,
		StateDir:   t.TempDir(),
		MountHTTPS: http.NewServeMux().Handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coord.Close)
	r := &portalRecords{registry: registry, coord: coord}
	hosts, err := r.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []portal.Host{
		{
			Addr:       netip.MustParseAddr("100.64.0.2"),
			NodeKey:    strings.Repeat("81", 32),
			MachineKey: strings.Repeat("91", 32),
			Owner:      owner,
			Note:       "portal operator",
			Hostname:   "laptop",
			OS:         "linux",
		},
		{
			Addr:    netip.MustParseAddr("100.64.0.3"),
			NodeKey: strings.Repeat("82", 32),
			Owner:   owner,
		},
	}
	if diff := cmp.Diff(want, hosts, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("the hosts mismatch (-want +got):\n%s", diff)
	}

	if err := r.RemoveHost(ctx, strings.Repeat("81", 32)); err != nil {
		t.Fatalf("releasing the laptop: %v", err)
	}
	directory, err := registry.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Hosts) != 1 || directory.Hosts[0].PublicKey != dbtest.MustKey(0x82) {
		t.Errorf("after the release the registry holds %+v, want the other host alone", directory.Hosts)
	}

	bare := &portalRecords{registry: registry}
	if _, err := bare.Hosts(ctx); !errors.Is(err, portal.ErrNoCoordination) {
		t.Errorf("hosts without coordination = %v, want ErrNoCoordination", err)
	}
	if err := bare.RemoveHost(ctx, strings.Repeat("82", 32)); !errors.Is(err, portal.ErrNoCoordination) {
		t.Errorf("a release without coordination = %v, want ErrNoCoordination", err)
	}
}
