package controlplane

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// ControlPlaneImpl implements the control plane logic.
type ControlPlaneImpl struct {
	discovery    *Discovery
	localAddress SCIONAddress
	trustStore   TrustStore

	directPathsMx     sync.RWMutex
	activeDirectPaths map[SCIONAddress]Path
}

// NewControlPlaneImpl creates a new control plane service implementation.
func NewControlPlaneImpl(discovery *Discovery, localAddr SCIONAddress, ts TrustStore) *ControlPlaneImpl {
	return &ControlPlaneImpl{
		discovery:         discovery,
		localAddress:      localAddr,
		trustStore:        ts,
		activeDirectPaths: make(map[SCIONAddress]Path),
	}
}

// GetLocalAddress returns the local ISD-AS address.
func (c *ControlPlaneImpl) GetLocalAddress() SCIONAddress {
	return c.localAddress
}

// SetActiveDirectPath stores an active direct path for a given destination.
func (c *ControlPlaneImpl) SetActiveDirectPath(destination SCIONAddress, path Path) {
	c.directPathsMx.Lock()
	defer c.directPathsMx.Unlock()
	c.activeDirectPaths[destination] = path
}

// GetTRC retrieves a specific TRC from the underlying TrustStore.
func (c *ControlPlaneImpl) GetTRC(ctx context.Context, isd int, version int) (cppki.TRC, error) {
	return c.trustStore.GetTRC(ctx, isd, version)
}

// GetCertificate retrieves a specific certificate from the underlying TrustStore.
func (c *ControlPlaneImpl) GetCertificate(ctx context.Context, isd int, as int) (*x509.Certificate, error) {
	return c.trustStore.GetCertificate(ctx, isd, as)
}

// GetLatestTRC retrieves the latest TRC for an ISD from the underlying TrustStore.
func (c *ControlPlaneImpl) GetLatestTRC(ctx context.Context, isd int) (cppki.TRC, error) {
	return c.trustStore.GetLatestTRC(ctx, isd)
}

// GetPaths returns paths to the destination. For now, only direct links.
func (c *ControlPlaneImpl) GetPaths(ctx context.Context, src, dst SCIONAddress) ([]Path, error) {
	c.directPathsMx.RLock()
	defer c.directPathsMx.RUnlock()

	path, ok := c.activeDirectPaths[dst]
	if !ok {
		return nil, fmt.Errorf("no direct path found to %s", dst)
	}

	return []Path{path}, nil
}
