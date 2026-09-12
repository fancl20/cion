package trust

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Remote resolves trust material over the network, typically from the core's
// control endpoint.
type Remote interface {
	// TRC fetches the signed TRC with the given ID.
	TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error)
	// Chains fetches the chains matching the query.
	Chains(ctx context.Context, q ChainQuery) ([][]*x509.Certificate, error)
	// RenewChain requests a certificate chain for the CSR, proving possession
	// of the subject key with the given signer. It returns the chain carried
	// by the verified renewal response.
	RenewChain(ctx context.Context, csr *x509.CertificateRequest,
		key crypto.Signer) ([]*x509.Certificate, error)
}

// NetworkProvider is a DB-first trust.Provider: lookups go to the local
// database and fall back to a Remote on a miss, caching the result.
type NetworkProvider struct {
	// DB is the local trust database.
	DB DB
	// Remote resolves missing trust material over the network.
	Remote Remote
}

var _ Provider = (*NetworkProvider)(nil)

// GetSignedTRC returns the TRC with the given ID, fetching and validating it
// from the Remote if it is not in the DB. A base TRC is verified with its
// own voting certificates; updates are not supported yet.
func (p *NetworkProvider) GetSignedTRC(
	ctx context.Context,
	id cppki.TRCID,
	opts ...Option,
) (cppki.SignedTRC, error) {

	trc, err := p.DB.SignedTRC(ctx, id)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if !trc.IsZero() {
		return trc, nil
	}
	return fetchTRC(ctx, p.DB, p.Remote, id)
}

// GetChains returns the chains matching the query, fetching them from the
// Remote on a DB miss. Only chains that verify against the ISD's TRC are
// returned and cached.
func (p *NetworkProvider) GetChains(
	ctx context.Context,
	q ChainQuery,
	opts ...Option,
) ([][]*x509.Certificate, error) {

	chains, err := p.DB.Chains(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(chains) != 0 {
		return chains, nil
	}
	chains, err = p.Remote.Chains(ctx, q)
	if err != nil {
		return nil, serrors.Wrap("fetching chains from remote", err)
	}
	if len(chains) == 0 {
		return nil, nil
	}
	trc, err := p.GetSignedTRC(ctx, cppki.TRCID{ISD: q.IA.ISD(), Base: 1, Serial: 1})
	if err != nil {
		return nil, serrors.Wrap("fetching TRC to verify chains", err)
	}
	var verified [][]*x509.Certificate
	for _, chain := range chains {
		if err := cppki.VerifyChain(chain,
			cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}); err != nil {

			slog.Warn("Dropping fetched chain that does not verify against TRC", "err", err)
			continue
		}
		verified = append(verified, chain)
		if _, err := p.DB.InsertChain(ctx, chain); err != nil {
			return nil, fmt.Errorf("caching fetched chain: %w", err)
		}
	}
	return verified, nil
}

// NotifyTRC ensures the TRC with the given ID is known locally.
func (p *NetworkProvider) NotifyTRC(ctx context.Context, id cppki.TRCID, opts ...Option) error {
	_, err := p.GetSignedTRC(ctx, id, opts...)
	return err
}

// Enroll obtains an AS certificate chain for the node's key from the core
// via the Remote and stores it in the DB. A chain that is still valid in the
// DB short-circuits the round trip. The ISD's base TRC is fetched and
// verified if not yet known, and the issued chain is verified against it
// before it is stored.
func Enroll(
	ctx context.Context,
	db DB,
	remote Remote,
	ia addr.IA,
	key crypto.Signer,
) ([]*x509.Certificate, error) {

	if err := validateISD(ia); err != nil {
		return nil, err
	}
	now := time.Now()
	if chains, err := db.Chains(ctx, ChainQuery{
		IA:       ia,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	}); err != nil {
		return nil, err
	} else if len(chains) != 0 {
		return chains[0], nil
	}

	csr, err := CreateCSR(ia, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	chain, err := remote.RenewChain(ctx, csr, key)
	if err != nil {
		return nil, serrors.Wrap("requesting chain", err)
	}
	if len(chain) != 2 {
		return nil, serrors.New("chain must contain two certificates", "len", len(chain))
	}
	if certIA, err := cppki.ExtractIA(chain[0].Subject); err != nil || !certIA.Equal(ia) {
		return nil, serrors.New("issued chain is for another ISD-AS", "expected", ia)
	}
	trc, err := fetchTRC(ctx, db, remote, cppki.TRCID{ISD: ia.ISD(), Base: 1, Serial: 1})
	if err != nil {
		return nil, err
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}); err != nil {
		return nil, serrors.Wrap("issued chain does not verify against TRC", err)
	}
	if _, err := db.InsertChain(ctx, chain); err != nil {
		return nil, fmt.Errorf("storing chain: %w", err)
	}
	return chain, nil
}

// fetchTRC fetches the TRC with the given ID from the Remote, checks its ID
// and signature, and caches it in the DB.
func fetchTRC(
	ctx context.Context,
	db DB,
	remote Remote,
	id cppki.TRCID,
) (cppki.SignedTRC, error) {

	if trc, err := db.SignedTRC(ctx, id); err != nil {
		return cppki.SignedTRC{}, err
	} else if !trc.IsZero() {
		return trc, nil
	}
	trc, err := remote.TRC(ctx, id)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("fetching TRC from remote", err, "id", id)
	}
	if trc.TRC.ID != id {
		return cppki.SignedTRC{}, serrors.New("fetched TRC has unexpected ID",
			"expected", id, "actual", trc.TRC.ID)
	}
	if err := trc.Verify(nil); err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("verifying fetched TRC", err, "id", id)
	}
	if _, err := db.InsertTRC(ctx, trc); err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("caching fetched TRC: %w", err)
	}
	return trc, nil
}

// CreateCSR creates a self-signed certificate signing request for the node's
// key; the self-signature is the proof of possession of the subject key.
func CreateCSR(ia addr.IA, key crypto.Signer) (*x509.CertificateRequest, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: subject(ia, "")}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}
