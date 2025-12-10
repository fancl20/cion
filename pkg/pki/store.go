package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	_ "github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// MemoryTrustStore implements TrustStore using in-memory maps.
type MemoryTrustStore struct {
	mu           sync.RWMutex
	trcs         map[int]map[int]cppki.TRC         // ISD -> Version -> TRC
	certificates map[int]map[int]*x509.Certificate // ISD -> AS -> Certificate
}

// NewMemoryTrustStore creates a new MemoryTrustStore.
func NewMemoryTrustStore() *MemoryTrustStore {
	return &MemoryTrustStore{
		trcs:         make(map[int]map[int]cppki.TRC),
		certificates: make(map[int]map[int]*x509.Certificate),
	}
}

// AddTRC adds a TRC to the store.
func (s *MemoryTrustStore) AddTRC(trc cppki.TRC) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.trcs[int(trc.ID.ISD)]; !ok {
		s.trcs[int(trc.ID.ISD)] = make(map[int]cppki.TRC)
	}
	s.trcs[int(trc.ID.ISD)][int(trc.ID.Serial)] = trc
}

// GetTRC retrieves a specific TRC.
func (s *MemoryTrustStore) GetTRC(ctx context.Context, isd int, version int) (cppki.TRC, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if isdMap, ok := s.trcs[isd]; ok {
		if trc, ok := isdMap[version]; ok {
			return trc, nil
		}
	}
	return cppki.TRC{}, fmt.Errorf("TRC not found: ISD %d, Version %d", isd, version)
}

// GetLatestTRC retrieves the latest TRC for an ISD.
func (s *MemoryTrustStore) GetLatestTRC(ctx context.Context, isd int) (cppki.TRC, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	isdMap, ok := s.trcs[isd]
	if !ok || len(isdMap) == 0 {
		return cppki.TRC{}, fmt.Errorf("no TRCs found for ISD %d", isd)
	}

	var maxVer int
	var latest cppki.TRC
	for v, trc := range isdMap {
		if v > maxVer {
			maxVer = v
			latest = trc
		}
	}
	return latest, nil
}

// GetCertificate retrieves a specific certificate.
func (s *MemoryTrustStore) GetCertificate(ctx context.Context, isd int, as int) (*x509.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if isdMap, ok := s.certificates[isd]; ok {
		if cert, ok := isdMap[as]; ok {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("certificate not found: ISD %d, AS %d", isd, as)
}

// AddCertificate adds a certificate to the store.
func (s *MemoryTrustStore) AddCertificate(cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ia, err := cppki.ExtractIA(cert.Subject)
	if err != nil {
		// Log error, or handle it as appropriate for your application.
		// For now, we'll just not add the certificate if IA extraction fails.
		return
	}

	isd := int(ia.ISD())
	as := int(ia.AS())

	if _, ok := s.certificates[isd]; !ok {
		s.certificates[isd] = make(map[int]*x509.Certificate)
	}
	s.certificates[isd][as] = cert
}
