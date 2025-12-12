package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"cion/pkg/pki"
)

func TestIntegrationDirectLink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Generate TRC and root certificate for ISD 1
	isd := 1
	version := 1
	baseVersion := 1
	description := "Integration Test TRC"
	validity := cppki.Validity{
		NotBefore: time.Now().Truncate(time.Second),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
	}
	coreASes := []addr.AS{addr.MustParseAS("ff00:0:110"), addr.MustParseAS("ff00:0:111")}
	authoritativeASes := []addr.AS{addr.MustParseAS("ff00:0:110"), addr.MustParseAS("ff00:0:111")}

	coreASIA := addr.MustParseIA(fmt.Sprintf("%d-%s", isd, coreASes[0])) // Assuming the first core AS will be used for cert generation
	coreCerts := pki.NewCertificates()
	if err := coreCerts.Create(coreASIA, pki.ASTypeCore, validity); err != nil {
		t.Fatalf("Failed to create core certificates: %v", err)
	}

	trc, err := pki.GenerateBaseTRC(isd, version, baseVersion, description, validity, coreASes, authoritativeASes, coreCerts)
	if err != nil {
		t.Fatalf("TRC generation failed: %v", err)
	}
	if trc == nil {
		t.Fatal("Generated TRC is nil")
	}

	// Create TrustStore for both nodes
	trustStoreNodeA := pki.NewMemoryTrustStore()
	trustStoreNodeB := pki.NewMemoryTrustStore()

	// Add the generated TRC and root cert to both trust stores
	trustStoreNodeA.AddTRC(*trc)
	trustStoreNodeB.AddTRC(*trc)

	// In this PoC, we add the first certificate from the TRC as a root cert. A more robust implementation might
	// iterate through all root certificates in the TRC or manage them at the AS level.
	if len(trc.Certificates) > 0 {
		trustStoreNodeA.AddCertificate(trc.Certificates[0])
		trustStoreNodeB.AddCertificate(trc.Certificates[0])
	}

	// 2. Create two control plane instances (Node A and Node B)
	localIA_A := addr.MustParseIA("1-ff00:0:110")
	localIA_B := addr.MustParseIA("1-ff00:0:111")
	addrA := "127.0.0.1:30000"
	addrB := "127.0.0.1:30001"

	// Prepare TLS config for Node A (server and client)
	tlsCertA, err := coreCerts.GetTLSCertificate()
	if err != nil {
		t.Fatalf("Failed to get TLS cert for A: %v", err)
	}
	tlsConfigA := &tls.Config{
		Certificates: []tls.Certificate{*tlsCertA},
		NextProtos:   []string{"h3"},
		ClientAuth:   tls.RequireAnyClientCert, // Require client certificates for mTLS
	}

	// Prepare TLS config for Node B (server and client)
	coreCertsB := pki.NewCertificates()
	if err := coreCertsB.Create(localIA_B, pki.ASTypeCore, validity); err != nil {
		t.Fatalf("Failed to create certificates for B: %v", err)
	}
	tlsCertB, err := coreCertsB.GetTLSCertificate()
	if err != nil {
		t.Fatalf("Failed to get TLS cert for B: %v", err)
	}
	tlsConfigB := &tls.Config{
		Certificates: []tls.Certificate{*tlsCertB},
		NextProtos:   []string{"h3"},
		ClientAuth:   tls.RequireAnyClientCert,
	}

	// Node A setup
	discoveryA := NewDiscovery()
	discoveryA.AddNeighbor(SCIONAddress(localIA_B.String()), addrB) // Node A knows Node B
	serviceA := NewControlPlaneImpl(discoveryA, SCIONAddress(localIA_A.String()), trustStoreNodeA)
	serverA := NewServer(addrA, tlsConfigA, serviceA)
	// Start Server A
	go func() {
		if err := serverA.ListenAndServe(); err != nil {
			t.Logf("Server A stopped: %v", err)
		}
	}()
	defer serverA.Close()

	// Node A client to talk to Node B
	clientATLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCertA},
		RootCAs:      x509.NewCertPool(),
		NextProtos:   []string{"h3"},
	}
	clientATLSConfig.RootCAs.AddCert(tlsCertB.Leaf) // Trust Node B's certificate
	clientA := NewDirectLinkClient(SCIONAddress(localIA_A.String()), discoveryA, clientATLSConfig, serviceA)
	go clientA.MonitorNeighbors(ctx, 50*time.Millisecond)

	// Node B setup (Node B doesn't necessarily need to know Node A for A to find B, but good practice)
	discoveryB := NewDiscovery()
	discoveryB.AddNeighbor(SCIONAddress(localIA_A.String()), addrA) // Node B knows Node A
	serviceB := NewControlPlaneImpl(discoveryB, SCIONAddress(localIA_B.String()), trustStoreNodeB)
	serverB := NewServer(addrB, tlsConfigB, serviceB)
	// Start Server B
	go func() {
		if err := serverB.ListenAndServe(); err != nil {
			t.Logf("Server B stopped: %v", err)
		}
	}()
	defer serverB.Close()

	// Node B client to talk to Node A
	clientBTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCertB},
		RootCAs:      x509.NewCertPool(),
		NextProtos:   []string{"h3"},
	}
	clientBTLSConfig.RootCAs.AddCert(tlsCertA.Leaf) // Trust Node A's certificate
	clientB := NewDirectLinkClient(SCIONAddress(localIA_B.String()), discoveryB, clientBTLSConfig, serviceB)
	go clientB.MonitorNeighbors(ctx, 50*time.Millisecond)

	// Give servers and clients a moment to start and exchange beacons
	time.Sleep(200 * time.Millisecond)

	// 3. Node A requests a path to Node B
	paths, err := serviceA.GetPaths(ctx, SCIONAddress(localIA_A.String()), SCIONAddress(localIA_B.String()))
	if err != nil {
		t.Fatalf("Path lookup from A to B failed: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("Should find exactly one path, found %d", len(paths))
	}

	// Verify the path is a direct link
	path := paths[0]
	if len(path.Segments) != 1 {
		t.Fatalf("Path should consist of a single segment for direct link, got %d", len(path.Segments))
	}
	segment := path.Segments[0]

	// Check that the segment ID (which is the neighbor address in our simple impl) matches Node B's address
	if !bytes.Equal([]byte(addrB), segment.ID) {
		t.Errorf("Segment ID mismatch: got %s, want %s", segment.ID, addrB)
	}
}
