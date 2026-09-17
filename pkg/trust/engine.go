package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
)

// ChainRenewalThreshold is the remaining validity below which the enrollment
// loop re-enrolls: roughly one day, against the three-day ASValidity. A node
// crossing it still holds a valid chain while the renewal round trip runs.
const ChainRenewalThreshold = 24 * time.Hour

// Engine composes the signer, verifier, and provider into the node's trust
// interface: it signs control-plane messages with a signer backed by the
// node's own chains, and verifies signatures against TRC-anchored chains
// resolved through the provider (proposal 0004).
type Engine struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Key is the AS private key certifying the node's messages.
	Key crypto.Signer
	// Provider resolves the node's chains and TRCs; DB-first, network-backed
	// on the nodes that enroll.
	Provider Provider

	// cache holds the verifier's recently used chains.
	cache *cache.Cache
}

// NewEngine returns an engine for the node's IA, AS key, and provider.
func NewEngine(ia addr.IA, key crypto.Signer, provider Provider) *Engine {
	// No janitor: expiry is checked on every read, and a cache without a
	// background goroutine keeps the engine whole inside a fake-time bubble.
	return &Engine{
		IA:       ia,
		Key:      key,
		Provider: provider,
		cache:    cache.New(defaultCacheExpiration, 0),
	}
}

// Signer returns a signer backed by the node's newest chain valid now: the
// algorithm is selected for the AS key, the TRC ID comes from the ISD's base
// TRC, and validity and subject from the chain (proposal 0004).
func (e *Engine) Signer(ctx context.Context) (Signer, error) {
	now := time.Now()
	chains, err := e.Provider.GetChains(ctx, ChainQuery{
		IA:       e.IA,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		return Signer{}, serrors.Wrap("querying own chains", err)
	}
	if len(chains) == 0 {
		return Signer{}, serrors.New("no valid chain for signing; enrollment required",
			"isd_as", e.IA)
	}
	trc, err := e.baseTRC(ctx)
	if err != nil {
		return Signer{}, err
	}
	algorithm, err := signed.SelectSignatureAlgorithm(e.Key.Public())
	if err != nil {
		return Signer{}, serrors.Wrap("selecting signature algorithm", err)
	}
	candidates := make([]Signer, 0, len(chains))
	for _, chain := range chains {
		candidates = append(candidates, Signer{
			PrivateKey:    e.Key,
			Algorithm:     algorithm,
			IA:            e.IA,
			Subject:       chain[0].Subject,
			Chain:         chain,
			SubjectKeyID:  chain[0].SubjectKeyId,
			Expiration:    chain[0].NotAfter,
			TRCID:         trc.TRC.ID,
			ChainValidity: cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter},
		})
	}
	return LastExpiring(candidates, cppki.Validity{NotBefore: now, NotAfter: now})
}

// Sign signs the message with the associated data using the current signer
// (control plane draft, Section 2.2.2.6).
func (e *Engine) Sign(
	ctx context.Context,
	msg []byte,
	associatedData ...[]byte,
) (*cryptopb.SignedMessage, error) {

	s, err := e.Signer(ctx)
	if err != nil {
		return nil, err
	}
	return s.Sign(ctx, msg, associatedData...)
}

// Verify verifies the signed message against chains resolved through the
// engine's provider, with the engine's certificate cache.
func (e *Engine) Verify(
	ctx context.Context,
	signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte,
) (*signed.Message, error) {

	v := Verifier{Engine: e.Provider, Cache: e.cache}
	return v.Verify(ctx, signedMsg, associatedData...)
}

// Chain returns the node's newest chain valid now, for the SCION-native TLS
// channel's certificates. It reads local state only: a TLS handshake must
// not spawn trust fetches, and an un-enrolled node simply has none.
func (e *Engine) Chain(ctx context.Context) ([]*x509.Certificate, error) {
	now := time.Now()
	q := ChainQuery{IA: e.IA, Validity: cppki.Validity{NotBefore: now, NotAfter: now}}
	var chains [][]*x509.Certificate
	var err error
	if db, ok := e.Provider.(DBProvider); ok {
		chains, err = db.LocalChains(ctx, q)
	} else {
		chains, err = e.Provider.GetChains(ctx, q)
	}
	if err != nil {
		return nil, serrors.Wrap("querying own chains", err)
	}
	return newest(chains, now)
}

// BaseTRC returns the ISD's base TRC as pinned in the provider, without
// fetching it over the network. The zero TRC means the node has not pinned
// the TRC yet.
func (e *Engine) BaseTRC() (cppki.SignedTRC, error) {
	db, ok := e.Provider.(DBProvider)
	if !ok {
		return cppki.SignedTRC{}, serrors.New("provider holds no local database")
	}
	return db.LocalTRC(cppki.TRCID{ISD: e.IA.ISD(), Base: 1, Serial: 1})
}

// DBProvider is implemented by providers that hold a local trust database.
type DBProvider interface {
	LocalTRC(id cppki.TRCID) (cppki.SignedTRC, error)
	LocalChains(ctx context.Context, q ChainQuery) ([][]*x509.Certificate, error)
}

// baseTRC fetches the ISD's base TRC through the provider.
func (e *Engine) baseTRC(ctx context.Context) (cppki.SignedTRC, error) {
	trc, err := e.Provider.GetSignedTRC(ctx,
		cppki.TRCID{ISD: e.IA.ISD(), Base: 1, Serial: 1})
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("resolving base TRC", err)
	}
	if trc.IsZero() {
		return cppki.SignedTRC{}, serrors.New("base TRC not available", "isd", e.IA.ISD())
	}
	return trc, nil
}

// CoreASes returns the core ASes of the given ISD named by the pinned base
// TRC, with the ISD substituted. An empty result means the TRC is not pinned.
func (e *Engine) CoreASes(isd addr.ISD) ([]addr.IA, error) {
	trc, err := e.BaseTRC()
	if err != nil {
		return nil, err
	}
	if trc.IsZero() {
		return nil, nil
	}
	cores := make([]addr.IA, 0, len(trc.TRC.CoreASes))
	for _, as := range trc.TRC.CoreASes {
		cores = append(cores, addr.MustIAFrom(isd, as))
	}
	return cores, nil
}

// NewestChain returns the chain for ia with the latest expiration among the
// chains valid at now, or nil when none is valid.
func NewestChain(
	ctx context.Context,
	db DB,
	ia addr.IA,
	now time.Time,
) ([]*x509.Certificate, error) {

	chains, err := db.Chains(ctx, ChainQuery{
		IA:       ia,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		return nil, fmt.Errorf("querying chains: %w", err)
	}
	return newest(chains, now)
}

// newest picks the valid chain with the latest expiration.
func newest(chains [][]*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	var best []*x509.Certificate
	for _, chain := range chains {
		if best == nil || chain[0].NotAfter.After(best[0].NotAfter) {
			best = chain
		}
	}
	return best, nil
}
