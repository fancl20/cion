package trust

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

const defaultCacheExpiration = time.Minute

// Verifier is used to verify control plane messages using the AS cert
// stored in the database.
type Verifier struct {
	// BoundIA when non-zero makes sure that only a signature originated from that IA
	// can be valid.
	BoundIA addr.IA
	// BoundServer binds a remote server to ask for missing crypto material.
	BoundServer net.Addr
	// BoundValidity binds the verifier to only use certificates that are valid
	// at the specified time.
	BoundValidity cppki.Validity
	// Engine provides verified certificate chains.
	Engine Provider

	// MaxCacheExpiration bounds how long fetched chains are cached; zero
	// means a minute, and a chain's own validity can shorten the window.
	MaxCacheExpiration time.Duration

	// chains and notifies hold the verifier's recently used certificate
	// chains and deduplicate its TRC reports for a minute; the engine sets
	// both, and a verifier built without them verifies uncached, every
	// read through the provider.
	chains   *ttlCache[[][]*x509.Certificate]
	notifies *ttlCache[struct{}]
}

// Verify verifies the signature of the msg.
func (v Verifier) Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	hdr, err := signed.ExtractUnverifiedHeader(signedMsg)
	if err != nil {
		return nil, err
	}

	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
		return nil, serrors.Wrap("parsing verification key ID", err)
	}
	if len(keyID.SubjectKeyId) == 0 {
		return nil, serrors.Wrap("subject key ID must be set", err)
	}
	ia := addr.IA(keyID.IsdAs)
	if !v.BoundIA.IsZero() && !v.BoundIA.Equal(ia) {
		return nil, serrors.New("does not match bound ISD-AS", "expected", v.BoundIA, "actual", ia)
	}
	if ia.IsWildcard() {
		return nil, serrors.New("ISD-AS must not contain wildcard", "isd_as", ia)
	}
	if v.Engine == nil {
		return nil, serrors.New("nil engine that provides cert chains")
	}
	id := cppki.TRCID{ISD: ia.ISD(),
		Base:   scrypto.Version(keyID.TrcBase),   // nolint - name from published protobuf
		Serial: scrypto.Version(keyID.TrcSerial), // nolint - name from published protobuf
	}
	if err := v.notifyTRC(ctx, id); err != nil {
		return nil, serrors.Wrap("reporting TRC", err, "id", id)
	}
	query := trustdb.ChainQuery{
		IA:           ia,
		SubjectKeyID: keyID.SubjectKeyId,
		Validity:     v.BoundValidity,
	}
	chains, err := v.getChains(ctx, query)
	if err != nil {
		return nil, serrors.Wrap("getting chains", err,
			"query.isd_as", query.IA,
			"query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
			"query.validity", query.Validity.String(),
		)
	}
	for _, c := range chains {
		signedMsg, err := signed.Verify(signedMsg, c[0].PublicKey, associatedData...)
		if err == nil {
			return signedMsg, nil
		}
	}
	return nil, serrors.New("no chain in database can verify signature",
		"query.isd_as", query.IA,
		"query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID),
		"query.validity", query.Validity.String(),
	)
}

func (v *Verifier) notifyTRC(ctx context.Context, id cppki.TRCID) error {
	key := fmt.Sprintf("notify-%s", id)
	if _, ok := v.notifies.get(key); ok {
		return nil
	}
	if err := v.Engine.NotifyTRC(ctx, id, Server(v.BoundServer)); err != nil {
		return err
	}
	v.notifies.add(key, struct{}{}, time.Minute)
	return nil
}

func (v *Verifier) getChains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {
	key := fmt.Sprintf("chain-%s-%x", q.IA, q.SubjectKeyID)

	if chains, ok := v.chains.get(key); ok {
		return chains, nil
	}

	chains, err := v.Engine.GetChains(ctx, q, Server(v.BoundServer))
	if err != nil {
		return nil, err
	}
	if len(chains) != 0 {
		v.chains.add(key, chains, v.cacheExpiration(chains))
	}
	return chains, nil
}

func (v *Verifier) cacheExpiration(chains [][]*x509.Certificate) time.Duration {
	dur := v.MaxCacheExpiration
	if dur == 0 {
		dur = defaultCacheExpiration
	}
	validity := time.Duration(rand.Int64N(int64(dur-(dur/2))) + int64(dur/2))
	expiration := time.Now().Add(validity)
	for _, chain := range chains {
		if notAfter := chain[0].NotAfter; notAfter.Before(expiration) {
			expiration = notAfter
		}
	}
	return time.Until(expiration)
}
