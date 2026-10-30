package trust

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// Fetcher resolves trust material over the network from one source: the
// core's control endpoint, or the control service of a message's sender.
type Fetcher interface {
	// TRC fetches the signed TRC with the given ID.
	TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error)
	// Chains fetches the chains matching the query.
	Chains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error)
}

// Remote resolves trust material over the network from a core's control
// endpoint, and renews the node's chain there.
type Remote interface {
	Fetcher
	// RenewChain requests a certificate chain for the CSR, the request
	// signed with key: under chain, the node's current one a renewal rests
	// on, or, with a nil chain, as the subject key's own proof of
	// possession. It returns the chain carried by the verified renewal
	// response.
	RenewChain(ctx context.Context, csr *x509.CertificateRequest,
		key crypto.Signer, chain []*x509.Certificate) ([]*x509.Certificate, error)
}

// NetworkProvider is a DB-first trust.Provider: lookups go to the local
// database and fall back on a miss to the network, caching the result. The
// founding core runs without a Remote — the bootstrap channel a Remote rides
// is its own, and what its DB lacks comes from the messages' senders — and
// a nil Remote resolves to "not found", never a panic.
type NetworkProvider struct {
	// DB is the local trust database.
	DB trustdb.DB
	// Remote resolves missing trust material over the network. Nil means the
	// provider is local-only.
	Remote Remote
	// Peer returns the fetcher that asks the server a Server option names:
	// the sender of the message under verification, which holds the material
	// that verifies it (control plane draft, Section 1.6). The provider asks
	// the sender first and the Remote when the sender yields nothing: a node
	// not yet enrolled cannot reach a sender's control service, whose channel
	// admits enrolled peers alone, while the core's bootstrap channel serves
	// it. Nil leaves the option unread.
	Peer func(server net.Addr) Fetcher
}

var _ Provider = (*NetworkProvider)(nil)
var _ DBProvider = (*NetworkProvider)(nil)

// LocalTRC looks up the TRC in the local database only.
func (p *NetworkProvider) LocalTRC(id cppki.TRCID) (cppki.SignedTRC, error) {
	return p.DB.SignedTRC(context.Background(), id)
}

// LocalChains looks up chains in the local database only.
func (p *NetworkProvider) LocalChains(
	ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {

	return p.DB.Chains(ctx, q)
}

// StoreChain stores a chain in the local database.
func (p *NetworkProvider) StoreChain(ctx context.Context, chain []*x509.Certificate) error {
	_, err := p.DB.InsertChain(ctx, chain)
	return err
}

// GetSignedTRC returns the TRC with the given ID, fetching and validating it
// from the network if it is not in the DB. A base TRC is verified with its
// own voting certificates; an update is verified against its pinned
// predecessor — fetched first when it is missing, so a node holding only the
// base can chain its way to any successor. The numbers-less ID asks the
// ISD's newest TRC.
func (p *NetworkProvider) GetSignedTRC(
	ctx context.Context,
	id cppki.TRCID,
	opts ...Option,
) (cppki.SignedTRC, error) {

	return fetchTRC(ctx, p.DB, p.fetcher(collect(opts)), id)
}

// GetChains returns the chains matching the query that verify against the
// anchor pool — the newest pinned TRC's roots, the predecessor's beside them
// while the newest is within its grace period — now, or at the time an At
// option names: the database's when any of them verifies, else the
// network's, which are cached. A stored chain whose root no pooled TRC
// carries is passed over.
func (p *NetworkProvider) GetChains(
	ctx context.Context,
	q trustdb.ChainQuery,
	opts ...Option,
) ([][]*x509.Certificate, error) {

	o := collect(opts)
	fetcher := p.fetcher(o)
	stored, err := p.DB.Chains(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 && fetcher == nil {
		return nil, nil
	}
	pool, err := anchorPool(ctx, p.DB, fetcher, q.IA.ISD())
	if err != nil {
		return nil, serrors.Wrap("fetching TRCs to verify chains", err)
	}
	verify := cppki.VerifyOptions{TRC: pool, CurrentTime: o.at}
	if verified, _ := verifiedChains(stored, verify); len(verified) != 0 {
		return verified, nil
	}
	if fetcher == nil {
		return nil, nil
	}
	fetched, err := fetcher.Chains(ctx, q)
	if err != nil {
		return nil, serrors.Wrap("fetching chains", err)
	}
	verified, failures := verifiedChains(fetched, verify)
	for _, err := range failures {
		slog.Warn("Dropping fetched chain that does not verify against TRC", "err", err)
	}
	for _, chain := range verified {
		if _, err := p.DB.InsertChain(ctx, chain); err != nil {
			return nil, fmt.Errorf("caching fetched chain: %w", err)
		}
	}
	return verified, nil
}

// fetcher returns where the options send a fetch: the Peer fetcher of the
// server a Server option names, then the Remote; nil when neither applies.
func (p *NetworkProvider) fetcher(o options) Fetcher {
	var sources inOrder
	if o.server != nil && p.Peer != nil {
		sources = append(sources, p.Peer(o.server))
	}
	if p.Remote != nil {
		sources = append(sources, p.Remote)
	}
	switch len(sources) {
	case 0:
		return nil
	case 1:
		return sources[0]
	default:
		return sources
	}
}

// inOrder asks its fetchers in turn and keeps the first answer: a TRC
// fetched without error, chains fetched without error and not empty. Its
// error joins the errors of every fetcher asked.
type inOrder []Fetcher

func (fs inOrder) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	var errs []error
	for _, f := range fs {
		trc, err := f.TRC(ctx, id)
		if err == nil {
			return trc, nil
		}
		errs = append(errs, err)
	}
	return cppki.SignedTRC{}, errors.Join(errs...)
}

func (fs inOrder) Chains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {
	var errs []error
	for _, f := range fs {
		chains, err := f.Chains(ctx, q)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(chains) != 0 {
			return chains, nil
		}
	}
	return nil, errors.Join(errs...)
}

// verifiedChains returns the chains that verify with the options, beside
// the failures of the ones that do not.
func verifiedChains(
	chains [][]*x509.Certificate, opts cppki.VerifyOptions,
) ([][]*x509.Certificate, []error) {

	var verified [][]*x509.Certificate
	var failures []error
	for _, chain := range chains {
		if err := cppki.VerifyChain(chain, opts); err != nil {
			failures = append(failures, err)
			continue
		}
		verified = append(verified, chain)
	}
	return verified, failures
}

// NotifyTRC ensures the TRC with the given ID is known locally.
func (p *NetworkProvider) NotifyTRC(ctx context.Context, id cppki.TRCID, opts ...Option) error {
	_, err := p.GetSignedTRC(ctx, id, opts...)
	return err
}

// RenewChain requests a fresh chain for the node's key from the remote's
// core and stores it, whatever chains the DB holds: the enrollment loop
// calls it when the node holds no valid chain, when the chain nears its
// expiry, and when the chain no longer anchors in the newest pinned TRC.
// chain is the node's current one, which the request rests on, or nil for a
// first issuance.
func RenewChain(
	ctx context.Context,
	db trustdb.DB,
	remote Remote,
	ia addr.IA,
	key crypto.Signer,
	chain []*x509.Certificate,
) ([]*x509.Certificate, error) {

	if err := validateISD(ia); err != nil {
		return nil, err
	}
	// The newest TRC is pulled, and the pool that anchors chains resolved,
	// before the chain is requested: a chain under a fresh root verifies
	// against the successor and not the predecessor the node still holds,
	// the pool carrying the predecessor beside it while the successor's
	// grace window runs, and an issued chain needs only local work to be
	// kept. A root rolled between the pull and the issuance fails this
	// attempt's verification, and the next attempt pulls the successor.
	if _, err := pullNewestTRC(ctx, db, remote, ia.ISD()); err != nil {
		return nil, err
	}
	pool, err := anchorPool(ctx, db, remote, ia.ISD())
	if err != nil {
		return nil, err
	}
	csr, err := CreateCSR(ia, key)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	issued, err := remote.RenewChain(ctx, csr, key, chain)
	if err != nil {
		return nil, serrors.Wrap("requesting chain", err)
	}
	if len(issued) != 2 {
		return nil, serrors.New("chain must contain two certificates", "len", len(issued))
	}
	if certIA, err := cppki.ExtractIA(issued[0].Subject); err != nil || !certIA.Equal(ia) {
		return nil, serrors.New("issued chain is for another ISD-AS", "expected", ia)
	}
	if err := cppki.VerifyChain(issued, cppki.VerifyOptions{TRC: pool}); err != nil {
		return nil, serrors.Wrap("issued chain does not verify against TRC", err)
	}
	if _, err := db.InsertChain(ctx, issued); err != nil {
		return nil, fmt.Errorf("storing chain: %w", err)
	}
	return issued, nil
}

// PinnedPool returns the active TRCs pinned in the DB that anchor chain
// verification, as activePool reads them, fetching nothing: an ISD with no
// TRC pinned yields the zero TRC alone, which verifies no chain.
func PinnedPool(ctx context.Context, db trustdb.DB, isd addr.ISD) ([]*cppki.TRC, error) {
	return anchorPool(ctx, db, nil, isd)
}

// anchorPool resolves the active TRCs that anchor chain verification, as
// activePool reads them: the ISD's newest and, inside its grace period, its
// predecessor, each from the DB or the fetcher.
func anchorPool(
	ctx context.Context,
	db trustdb.DB,
	fetcher Fetcher,
	isd addr.ISD,
) ([]*cppki.TRC, error) {

	newest, err := fetchTRC(ctx, db, fetcher, NewestTRCID(isd))
	if err != nil {
		return nil, err
	}
	return activePool(newest, func(id cppki.TRCID) (cppki.SignedTRC, error) {
		return fetchTRC(ctx, db, fetcher, id)
	})
}

// activePool returns the active TRCs the draft's Section 3.4 builds the
// trust anchor pool from: the newest, and its predecessor beside it while the
// newest is within its grace period, the window in which a chain issued under
// the replaced material keeps verifying. No TRC before the predecessor is
// active: a successor landing inside its predecessor's window resets the
// window (Section 3.2.4). lookup resolves the predecessor; one it does not
// find leaves the newest alone.
func activePool(
	newest cppki.SignedTRC,
	lookup func(cppki.TRCID) (cppki.SignedTRC, error),
) ([]*cppki.TRC, error) {

	pool := []*cppki.TRC{&newest.TRC}
	if newest.TRC.ID.IsBase() || !newest.TRC.InGracePeriod(time.Now()) {
		return pool, nil
	}
	pred, err := lookup(predecessorID(newest.TRC.ID))
	if err != nil {
		return nil, err
	}
	if pred.IsZero() {
		return pool, nil
	}
	return append(pool, &pred.TRC), nil
}

// fetchTRC returns the TRC with the given ID — the newest of the ISD when the
// ID is numbers-less — from the DB or the fetcher, verifying what it fetches
// and caching it in the DB; with a nil fetcher, a DB miss is the zero TRC.
func fetchTRC(
	ctx context.Context,
	db trustdb.DB,
	fetcher Fetcher,
	id cppki.TRCID,
) (cppki.SignedTRC, error) {

	if trc, err := db.SignedTRC(ctx, id); err != nil {
		return cppki.SignedTRC{}, err
	} else if !trc.IsZero() {
		return trc, nil
	}
	if fetcher == nil {
		return cppki.SignedTRC{}, nil
	}
	if id.Base.IsLatest() {
		return pullNewestTRC(ctx, db, fetcher, id.ISD)
	}
	trc, err := fetcher.TRC(ctx, id)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("fetching TRC", err, "id", id)
	}
	if trc.TRC.ID != id {
		return cppki.SignedTRC{}, serrors.New("fetched TRC has unexpected ID",
			"expected", id, "actual", trc.TRC.ID)
	}
	return verifyAndPinTRC(ctx, db, fetcher, trc)
}

// pullNewestTRC asks the fetcher for the ISD's newest TRC — the drafts'
// numbers-less request — whatever the DB holds, and pins it once it
// verifies, fetching the predecessors it stands on.
func pullNewestTRC(
	ctx context.Context,
	db trustdb.DB,
	fetcher Fetcher,
	isd addr.ISD,
) (cppki.SignedTRC, error) {

	trc, err := fetcher.TRC(ctx, NewestTRCID(isd))
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("fetching the newest TRC", err, "isd", isd)
	}
	if trc.TRC.ID.ISD != isd {
		return cppki.SignedTRC{}, serrors.New("fetched TRC is for another ISD",
			"expected", isd, "actual", trc.TRC.ID.ISD)
	}
	return verifyAndPinTRC(ctx, db, fetcher, trc)
}

// verifyAndPinTRC verifies the TRC — a base TRC with its own voting
// certificates, an update against the resolved predecessor — and pins it in
// the DB. The posture is fail-closed: a TRC no pinned predecessor vouches
// for never enters the database.
func verifyAndPinTRC(
	ctx context.Context,
	db trustdb.DB,
	fetcher Fetcher,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	if trc.TRC.ID.IsBase() {
		if err := trc.Verify(nil); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap("verifying fetched TRC", err, "id", trc.TRC.ID)
		}
	} else {
		pred, err := fetchTRC(ctx, db, fetcher, predecessorID(trc.TRC.ID))
		if err != nil {
			return cppki.SignedTRC{}, err
		}
		if err := trc.Verify(&pred.TRC); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap("verifying fetched TRC against its predecessor",
				err, "id", trc.TRC.ID, "predecessor", pred.TRC.ID)
		}
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
