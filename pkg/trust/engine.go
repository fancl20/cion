package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// ChainRenewalThreshold is the remaining validity below which the enrollment
// loop re-enrolls: roughly one day, against the three-day ASValidity. A node
// crossing it still holds a valid chain while the renewal round trip runs.
const ChainRenewalThreshold = 24 * time.Hour

// RotationThreshold is the remaining validity below which a core's rotation
// watch rolls the trust material it holds: thirty days, the counterpart of
// the chain renewal threshold's one day against the three-day chain validity.
// Long enough to tolerate a month of failed casts, short enough that the
// successor's validity stays comfortable.
const RotationThreshold = 30 * 24 * time.Hour

// Engine composes the signer, verifier, and provider into the node's trust
// interface: it signs control-plane messages with a signer backed by the
// node's own chains, and verifies signatures against TRC-anchored chains
// resolved through the provider.
type Engine struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Key is the AS private key certifying the node's messages.
	Key crypto.Signer
	// Provider resolves the node's chains and TRCs; DB-first, network-backed
	// on the nodes that enroll.
	Provider Provider

	// chains and notifies cache the verifiers' recently used chains and
	// deduplicate their TRC reports.
	chains   *ttlCache[[][]*x509.Certificate]
	notifies *ttlCache[struct{}]
}

// NewEngine returns an engine for the node's IA, AS key, and provider.
func NewEngine(ia addr.IA, key crypto.Signer, provider Provider) *Engine {
	return &Engine{
		IA:       ia,
		Key:      key,
		Provider: provider,
		chains:   newTTLCache[[][]*x509.Certificate](),
		notifies: newTTLCache[struct{}](),
	}
}

// Signer returns a signer backed by the node's newest chain valid now: the
// algorithm is selected for the AS key, the TRC ID cites the newest TRC held
// locally, and validity and subject come from the chain.
func (e *Engine) Signer(ctx context.Context) (Signer, error) {
	now := time.Now()
	chains, err := e.Provider.GetChains(ctx, trustdb.ChainQuery{
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
	trc, err := e.newestTRC(ctx)
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

	v := Verifier{Engine: e.Provider, chains: e.chains, notifies: e.notifies}
	return v.Verify(ctx, signedMsg, associatedData...)
}

// VerifyBound verifies the signed message with the signer bound to ia: a
// signature whose verification key names another ISD-AS fails with the
// mismatch named. The signed bytes of a beacon's AS entry claim the entry's
// own ISD-AS; this form reads the claim back to the signer and refuses the
// difference.
func (e *Engine) VerifyBound(
	ctx context.Context,
	ia addr.IA,
	signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte,
) (*signed.Message, error) {

	v := Verifier{Engine: e.Provider, chains: e.chains, notifies: e.notifies, BoundIA: ia}
	return v.Verify(ctx, signedMsg, associatedData...)
}

// Chain returns the node's newest chain valid now, for the SCION-native TLS
// channel's certificates. It reads local state only: a TLS handshake must
// not spawn trust fetches, and an un-enrolled node simply has none.
func (e *Engine) Chain(ctx context.Context) ([]*x509.Certificate, error) {
	now := time.Now()
	q := trustdb.ChainQuery{IA: e.IA, Validity: cppki.Validity{NotBefore: now, NotAfter: now}}
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

// AnchorPool returns the TRCs whose root pools anchor chain verification:
// the newest pinned TRC, plus the predecessors it carries — each successor
// holding its own inside its grace period, the window the draft's Section
// 3.2.4 defines for updates, in which a chain issued under the replaced
// material keeps verifying. Local state only, like BaseTRC: a TLS handshake
// must not spawn trust fetches. An empty pool means the node has not pinned
// the TRC yet.
func (e *Engine) AnchorPool() ([]*cppki.TRC, error) {
	db, ok := e.Provider.(DBProvider)
	if !ok {
		return nil, serrors.New("provider holds no local database")
	}
	newest, err := db.LocalTRC(newestTRCID(e.IA.ISD()))
	if err != nil {
		return nil, err
	}
	if newest.IsZero() {
		return nil, nil
	}
	pool := []*cppki.TRC{&newest.TRC}
	// The walk holds its own copy, so the pointer the pool keeps into the
	// newest is not overwritten by the predecessors it moves through.
	cur := newest
	for !cur.TRC.ID.IsBase() && cur.TRC.InGracePeriod(time.Now()) {
		pred, err := db.LocalTRC(predecessorID(cur.TRC.ID))
		if err != nil {
			return nil, err
		}
		if pred.IsZero() {
			break
		}
		pool = append(pool, &pred.TRC)
		cur = pred
	}
	return pool, nil
}

// DBProvider is implemented by providers that hold a local trust database.
type DBProvider interface {
	LocalTRC(id cppki.TRCID) (cppki.SignedTRC, error)
	LocalChains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error)
}

// newestTRC resolves the ISD's newest TRC through the provider: the newest
// pinned one, fetched when nothing is pinned at all.
func (e *Engine) newestTRC(ctx context.Context) (cppki.SignedTRC, error) {
	trc, err := e.Provider.GetSignedTRC(ctx, newestTRCID(e.IA.ISD()))
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("resolving newest TRC", err)
	}
	if trc.IsZero() {
		return cppki.SignedTRC{}, serrors.New("no TRC of the ISD is available", "isd", e.IA.ISD())
	}
	return trc, nil
}

// newestLocalTRC returns the newest TRC pinned in the provider, without
// fetching over the network. The zero TRC means none is pinned.
func (e *Engine) newestLocalTRC() (cppki.SignedTRC, error) {
	db, ok := e.Provider.(DBProvider)
	if !ok {
		return cppki.SignedTRC{}, serrors.New("provider holds no local database")
	}
	return db.LocalTRC(newestTRCID(e.IA.ISD()))
}

// CoreASes returns the core ASes of the given ISD named by the newest pinned
// TRC, with the ISD substituted. An empty result means the TRC is not pinned.
func (e *Engine) CoreASes(isd addr.ISD) ([]addr.IA, error) {
	trc, err := e.newestLocalTRC()
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

// IssuerASes returns the ASes of the given ISD a root certificate in the
// newest pinned TRC names as its subject — exactly the nodes that can serve
// a chain renewal, the signal enrollment's core route selects by. An empty
// result means the TRC is not pinned.
func (e *Engine) IssuerASes(isd addr.ISD) ([]addr.IA, error) {
	trc, err := e.newestLocalTRC()
	if err != nil {
		return nil, err
	}
	if trc.IsZero() {
		return nil, nil
	}
	roots, err := trc.TRC.RootCerts()
	if err != nil {
		return nil, err
	}
	issuers := make([]addr.IA, 0, len(roots))
	for _, root := range roots {
		ia, err := cppki.ExtractIA(root.Subject)
		if err != nil {
			return nil, serrors.Wrap("extracting the root certificate's ISD-AS", err)
		}
		issuers = append(issuers, addr.MustIAFrom(isd, ia.AS()))
	}
	return issuers, nil
}

// NewestChain returns the chain for ia with the latest expiration among the
// chains valid at now, or nil when none is valid.
func NewestChain(
	ctx context.Context,
	db trustdb.DB,
	ia addr.IA,
	now time.Time,
) ([]*x509.Certificate, error) {

	chains, err := db.Chains(ctx, trustdb.ChainQuery{
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
