package controlplane_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"cion/pkg/controlplane"
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


	// 2. Create two controlplane.Engine instances (Node A and Node B)
	localIA_A := addr.MustParseIA("1-ff00:0:110")
	localIA_B := addr.MustParseIA("1-ff00:0:111")
	addrB := "127.0.0.1:30001"

	// Node A setup
	discoveryA := controlplane.NewDiscovery()
	discoveryA.AddNeighbor(controlplane.SCIONAddress(localIA_B.String()), addrB) // Node A knows Node B
	engineA := controlplane.NewEngine(discoveryA, controlplane.SCIONAddress(localIA_A.String()))

	// Node B setup (Node B doesn't necessarily need to know Node A for A to find B, but good practice)
	discoveryB := controlplane.NewDiscovery()
	discoveryB.AddNeighbor(controlplane.SCIONAddress(localIA_A.String()), "127.0.0.1:30000") // Node B knows Node A
	_ = controlplane.NewEngine(discoveryB, controlplane.SCIONAddress(localIA_B.String()))    // Declared but not used

	// 3. Node A requests a path to Node B
	paths, err := engineA.GetPaths(ctx, controlplane.SCIONAddress(localIA_A.String()), controlplane.SCIONAddress(localIA_B.String()))
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

