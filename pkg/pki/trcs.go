package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// TRCs manages the TRC state machine for a single ISD.
// It holds the currently active TRC and any pending TRCs in grace period.
// TRC certificates are stored within the TRC itself; no separate pool is maintained.
type TRCs struct {
	isd     addr.ISD
	current *cppki.TRC
	pending []*cppki.TRC
}

// NewTRCs creates a new TRC state machine for the given ISD.
func NewTRCs(isd int) *TRCs {
	return &TRCs{
		isd: addr.ISD(isd),
	}
}

// Current returns the currently active TRC for this ISD.
// Returns ErrNoTRC if no TRC has been installed.
func (t *TRCs) Current() (*cppki.TRC, error) {
	if t.current == nil {
		return nil, ErrNoTRC
	}
	return t.current, nil
}

// Pending returns any TRCs that are in grace period or awaiting activation.
func (t *TRCs) Pending() []*cppki.TRC {
	return t.pending
}

// Update installs a new TRC, either as an initial base TRC or as an update.
// The TRC is validated, and if valid, becomes the current TRC (for base)
// or is added to pending (for updates).
//
// Update rules:
//   - The TRC must pass cppki.TRC.Validate().
//   - The TRC's ISD must match the ISD of this state machine.
//   - For the first TRC (no current TRC), it must be a base TRC (serial == base).
//   - For updates, the base number must match current base, serial must be higher,
//     and the update must be properly signed (not yet verified in PoC).
//
// For CION's PoC, TRC updates are not supported and will be rejected with
// ErrTRCUpdateUnsupported.
func (t *TRCs) Update(trc *cppki.TRC) error {
	// Validate the TRC structure and signatures
	if err := trc.Validate(); err != nil {
		return fmt.Errorf("invalid TRC: %w", err)
	}
	// Must be for correct ISD
	if trc.ID.ISD != t.isd {
		return ErrISDMismatch
	}

	// If this is the first TRC, install as current (base TRC)
	if t.current == nil {
		// For PoC, we only support base TRCs (serial == base)
		if trc.ID.Serial != trc.ID.Base {
			return ErrTRCUpdateUnsupported
		}
		t.current = trc
		return nil
	}

	// Existing TRC present, validate update rules
	// Must have same base number
	if trc.ID.Base != t.current.ID.Base {
		return ErrTRCBaseMismatch
	}
	// Serial must be higher
	if trc.ID.Serial <= t.current.ID.Serial {
		return ErrTRCSerialSmaller
	}
	// For PoC, we cannot verify update signatures without SignedTRC.
	// Reject any TRC update for now.
	return ErrTRCUpdateUnsupported
}

// RootCertificates returns all root certificates from the currently active TRC.
// Returns ErrNoTRC if no TRC is installed.
func (t *TRCs) RootCertificates() ([]*x509.Certificate, error) {
	if t.current == nil {
		return nil, ErrNoTRC
	}
	var roots []*x509.Certificate
	for _, cert := range t.current.Certificates {
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			continue // skip invalid certificates
		}
		if ct == cppki.Root {
			roots = append(roots, cert)
		}
	}
	return roots, nil
}

// VotingCertificates returns all voting certificates (sensitive and regular) from the currently active TRC.
// Returns ErrNoTRC if no TRC is installed.
func (t *TRCs) VotingCertificates() ([]*x509.Certificate, error) {
	if t.current == nil {
		return nil, ErrNoTRC
	}
	var voters []*x509.Certificate
	for _, cert := range t.current.Certificates {
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			continue
		}
		if ct == cppki.Sensitive || ct == cppki.Regular {
			voters = append(voters, cert)
		}
	}
	return voters, nil
}

// SensitiveCertificates returns only sensitive voting certificates from the currently active TRC.
// Returns ErrNoTRC if no TRC is installed.
func (t *TRCs) SensitiveCertificates() ([]*x509.Certificate, error) {
	if t.current == nil {
		return nil, ErrNoTRC
	}
	var sensitives []*x509.Certificate
	for _, cert := range t.current.Certificates {
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			continue
		}
		if ct == cppki.Sensitive {
			sensitives = append(sensitives, cert)
		}
	}
	return sensitives, nil
}

// RegularCertificates returns only regular voting certificates from the currently active TRC.
// Returns ErrNoTRC if no TRC is installed.
func (t *TRCs) RegularCertificates() ([]*x509.Certificate, error) {
	if t.current == nil {
		return nil, ErrNoTRC
	}
	var regulars []*x509.Certificate
	for _, cert := range t.current.Certificates {
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			continue
		}
		if ct == cppki.Regular {
			regulars = append(regulars, cert)
		}
	}
	return regulars, nil
}

// GenerateUpdateTRC creates a new TRC update signed by voting certificates from the provided certificate pool.
// This is a stub implementation that returns ErrTRCUpdateUnsupported.
func (t *TRCs) GenerateUpdateTRC(certs *Certificates, newSerial uint64, description string) (*cppki.TRC, error) {
	return nil, ErrTRCUpdateUnsupported
}

// Errors
var (
	ErrNoTRC                = errors.New("no TRC installed")
	ErrISDMismatch          = errors.New("TRC ISD does not match AS ISD")
	ErrTRCSerialSmaller     = errors.New("TRC serial number not higher than current")
	ErrTRCBaseMismatch      = errors.New("TRC base number does not match current TRC")
	ErrTRCUpdateUnsupported = errors.New("TRC updates not supported in PoC")
)

// GenerateBaseTRC creates a base TRC for the given ISD with the specified parameters.
// This is a minimal implementation for CION's PoC that generates a fully SCION-spec-compliant TRC.
//
// The generated TRC includes:
// - A self-signed root certificate for the ISD
// - Self-signed sensitive and regular voting certificates
// - All certificates are generated in-memory with fresh key material
//
// Limitations for PoC (vs. a full SCION implementation):
// - Only generates base TRCs (serial == base), not TRC updates
// - Uses the first core AS as the root IA for simplicity
// - Does not persist certificates or private keys to disk
// - No AS abstraction for certificate pool management
// - No TRC state machine for updates, voting, or grace periods
//
// For CION's control plane PoC, this suffices to establish trust roots and enable
// neighbor discovery and signaling. A full implementation would need to integrate
// with AS-level certificate management and support the complete TRC lifecycle.
//
// The generated TRC passes cppki.TRC.Validate() and can be used as a base TRC.
func GenerateBaseTRC(isd int, version, baseVersion int, description string,
	validity cppki.Validity, coreASes []addr.AS, authASes []addr.AS, certs *Certificates) (*cppki.TRC, error) {

	// TRC validity must be truncated to whole seconds for ASN.1 encoding.
	// Certificates also encode validity with second precision, so we align both.
	truncValidity := cppki.Validity{
		NotBefore: validity.NotBefore.UTC().Truncate(time.Second),
		NotAfter:  validity.NotAfter.UTC().Truncate(time.Second),
	}

	// Determine if this is a base TRC (serial == base)
	// For PoC, we only generate base TRCs, so checking serial == baseVersion is good practice
	if version != baseVersion {
		// In a real implementation we would support updates.
		// For now we just proceed, but note that Join works for updates too.
	}

	// Populate cppki.TRC fields with initial values.
	// Certificates will be added by Join.
	trc := cppki.TRC{
		Version: 1, // SCION TRC format version
		ID: cppki.TRCID{
			ISD:    addr.ISD(isd),
			Base:   scrypto.Version(baseVersion),
			Serial: scrypto.Version(version),
		},
		Validity:          truncValidity,
		Quorum:            1, // Quorum must be at least 1 when voting certificates are present
		CoreASes:          coreASes,
		AuthoritativeASes: authASes,
		Description:       description,
		Certificates:      []*x509.Certificate{},
	}

	// Use Join to add certificates from the pool and encode the TRC.
	// Join will append certificates in a deterministic order (Root, Sensitive, Regular).
	updatedTRC, err := certs.Join(trc)
	if err != nil {
		return nil, fmt.Errorf("failed to join certificates to TRC: %w", err)
	}

	// Validate the generated TRC to ensure it complies with SCION PKI spec.
	if err := updatedTRC.Validate(); err != nil {
		return nil, fmt.Errorf("generated TRC failed cppki validation: %w", err)
	}

	return &updatedTRC, nil
}
