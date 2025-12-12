package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cpb "github.com/scionproto/scion/pkg/proto/control_plane"
	"google.golang.org/protobuf/proto"
)

// DirectLinkClient manages client-side interactions for direct links.
type DirectLinkClient struct {
	discovery *Discovery
	localIA   SCIONAddress
	tlsConfig *tls.Config
	cp        ControlPlane
}

// NewDirectLinkClient creates a new DirectLinkClient.
func NewDirectLinkClient(localIA SCIONAddress, discovery *Discovery, tlsConfig *tls.Config, cp ControlPlane) *DirectLinkClient {
	return &DirectLinkClient{
		discovery: discovery,
		localIA:   localIA,
		tlsConfig: tlsConfig,
		cp:        cp,
	}
}

// MonitorNeighbors periodically sends BeaconRequests to configured neighbors.
func (c *DirectLinkClient) MonitorNeighbors(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("DirectLinkClient stopping for AS %s", c.localIA)
			return
		case <-ticker.C:
			log.Printf("DirectLinkClient of AS %s: monitoring neighbors", c.localIA)
			c.sendBeaconsToNeighbors(ctx)
		}
	}
}

// fetchTrustMaterial attempts to fetch TRCs and certificates from a neighbor.
func (c *DirectLinkClient) fetchTrustMaterial(ctx context.Context, neighborIA SCIONAddress, neighborAddress string, httpClient *http.Client) error {
	log.Printf("AS %s: Attempting to fetch trust material from neighbor %s at %s", c.localIA, neighborIA, neighborAddress)

	// 1. Fetch latest TRC
	trcReq := &cpb.TRCRequest{
		Isd:    uint32(addr.MustParseIA(string(neighborIA)).ISD()),
		Serial: 1, // Dummy serial for now
	}

	trcReqBytes, err := proto.Marshal(trcReq)
	if err != nil {
		return fmt.Errorf("failed to marshal TRC request: %w", err)
	}

	httpReqTRC, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s%s", neighborAddress, TrustMaterialServiceTRCProcedure), bytes.NewReader(trcReqBytes))
	if err != nil {
		return fmt.Errorf("failed to create TRC request: %w", err)
	}
	httpReqTRC.Header.Set("Content-Type", "application/protobuf")
	httpReqTRC.Header.Set("Accept", "application/protobuf")

	httpRespTRC, err := httpClient.Do(httpReqTRC)
	if err != nil {
		return fmt.Errorf("failed to send TRC request: %w", err)
	}
	defer httpRespTRC.Body.Close()

	if httpRespTRC.StatusCode != http.StatusOK {
		return fmt.Errorf("TRC request failed with status: %s", httpRespTRC.Status)
	}

	trcRespBytes, err := io.ReadAll(httpRespTRC.Body)
	if err != nil {
		return fmt.Errorf("failed to read TRC response body: %w", err)
	}

	trcResp := &cpb.TRCResponse{}
	if err := proto.Unmarshal(trcRespBytes, trcResp); err != nil {
		return fmt.Errorf("failed to unmarshal TRC response: %w", err)
	}
	log.Printf("AS %s: Successfully fetched TRC from %s, TRC size: %d", c.localIA, neighborIA, len(trcResp.GetTrc()))

	// TODO: Parse TRC and add to local TrustStore

	// 2. Fetch Chains (AS certificates)
	chainsReq := &cpb.ChainsRequest{
		IsdAs: uint64(addr.MustParseIA(string(neighborIA))), // Direct cast of addr.IA to uint64
	}

	chainsReqBytes, err := proto.Marshal(chainsReq)
	if err != nil {
		return fmt.Errorf("failed to marshal Chains request: %w", err)
	}

	httpReqChains, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s%s", neighborAddress, TrustMaterialServiceChainsProcedure), bytes.NewReader(chainsReqBytes))
	if err != nil {
		return fmt.Errorf("failed to create Chains request: %w", err)
	}
	httpReqChains.Header.Set("Content-Type", "application/protobuf")
	httpReqChains.Header.Set("Accept", "application/protobuf")

	httpRespChains, err := httpClient.Do(httpReqChains)
	if err != nil {
		return fmt.Errorf("failed to send Chains request: %w", err)
	}
	defer httpRespChains.Body.Close()

	if httpRespChains.StatusCode != http.StatusOK {
		return fmt.Errorf("Chains request failed with status: %s", httpRespChains.Status)
	}

	chainsRespBytes, err := io.ReadAll(httpRespChains.Body)
	if err != nil {
		return fmt.Errorf("failed to read Chains response body: %w", err)
	}

	chainsResp := &cpb.ChainsResponse{}
	if err := proto.Unmarshal(chainsRespBytes, chainsResp); err != nil {
		return fmt.Errorf("failed to unmarshal Chains response: %w", err)
	}
	log.Printf("AS %s: Successfully fetched %d certificate chains from %s", c.localIA, len(chainsResp.GetChains()), neighborIA)

	// TODO: Parse certificates and add to local TrustStore

	return nil
}

func (c *DirectLinkClient) sendBeaconsToNeighbors(ctx context.Context) {
	neighbors := c.discovery.GetNeighbors()
	for _, neighbor := range neighbors {
		log.Printf("AS %s: Sending Beacon to neighbor %s at %s", c.localIA, neighbor.ISD_AS, neighbor.Address)

		// Create a new HTTP client for each neighbor to handle mTLS
		httpClient := &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig: c.tlsConfig,
				QUICConfig:      &quic.Config{},
			},
		}

		// Marshal BeaconRequest
		beaconReq := &cpb.BeaconRequest{
			Segment: &cpb.PathSegment{
				SegmentInfo: []byte(fmt.Sprintf("Hello from %s", c.localIA)),
				AsEntries:   []*cpb.ASEntry{},
			},
		}
		beaconReqBytes, err := proto.Marshal(beaconReq)
		if err != nil {
			log.Printf("AS %s: Failed to marshal BeaconRequest: %v", c.localIA, err)
			continue
		}

		httpReqBeacon, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s%s", neighbor.Address, SegmentCreationServiceBeaconProcedure), bytes.NewReader(beaconReqBytes))
		if err != nil {
			log.Printf("AS %s: Failed to create HTTP request for Beacon to %s (%s): %v", c.localIA, neighbor.ISD_AS, neighbor.Address, err)
			continue
		}
		httpReqBeacon.Header.Set("Content-Type", "application/protobuf")
		httpReqBeacon.Header.Set("Accept", "application/protobuf")

		httpRespBeacon, err := httpClient.Do(httpReqBeacon)
		if err != nil {
			log.Printf("AS %s: Failed to send Beacon to %s (%s): %v", c.localIA, neighbor.ISD_AS, neighbor.Address, err)

			// Attempt to fetch trust material if there's a TLS handshake error.
			// For PoC, a simple check for any TLS error.
			if _, ok := err.(*tls.RecordHeaderError); ok {
				log.Printf("AS %s: TLS handshake error with %s, attempting to fetch trust material", c.localIA, neighbor.ISD_AS)
				fetchErr := c.fetchTrustMaterial(ctx, neighbor.ISD_AS, neighbor.Address, httpClient)
				if fetchErr != nil {
					log.Printf("AS %s: Failed to fetch trust material from %s: %v", c.localIA, neighbor.ISD_AS, fetchErr)
				} else {
					log.Printf("AS %s: Successfully fetched trust material from %s (attempting retry on next interval)", c.localIA, neighbor.ISD_AS)
				}
			}
		} else {
			defer httpRespBeacon.Body.Close()
			if httpRespBeacon.StatusCode != http.StatusOK {
				log.Printf("AS %s: Beacon request failed with status for %s (%s): %s", c.localIA, neighbor.ISD_AS, neighbor.Address, httpRespBeacon.Status)
				continue
			}

			// Read and unmarshal BeaconResponse (optional, as it's empty)
			_, err := io.ReadAll(httpRespBeacon.Body)
			if err != nil {
				log.Printf("AS %s: Failed to read Beacon response body from %s (%s): %v", c.localIA, neighbor.ISD_AS, neighbor.Address, err)
				continue
			}

			log.Printf("AS %s: Successfully sent Beacon to %s (%s)", c.localIA, neighbor.ISD_AS, neighbor.Address)
			// Convert successful beacon into a direct path and store it.
			// For simplicity, we create a dummy PathSegment for now.
			directPath := Path{
				Segments: []PathSegment{{
					ID:         []byte(neighbor.Address), // Use neighbor address as ID
					Interfaces: []uint64{1},              // Dummy interface ID
				}},
			}
			c.cp.SetActiveDirectPath(neighbor.ISD_AS, directPath)
		}
	}
}
