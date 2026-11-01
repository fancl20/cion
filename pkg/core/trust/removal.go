package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// AssembleRemoval builds the successor TRC that removes the core: the serial
// incremented on the same base, every certificate naming the core dropped,
// its entries dropped from the core and authoritative AS lists, and the
// quorum and noTrustReset untouched — a sensitive update, its one vote the
// predecessor's index of the founder's sensitive voting certificate (PKI
// draft, Section 3.5.5). The founder, the holder of that certificate, is
// never removed. The validity runs from at to the earliest expiry among the
// certificates the successor carries, so the grace period, the window the
// predecessor's roots keep anchoring, runs from at.
func AssembleRemoval(pred cppki.SignedTRC, core addr.IA, grace time.Duration, at time.Time) (cppki.TRC, error) {
	vote, err := sensitiveIndex(pred.TRC)
	if err != nil {
		return cppki.TRC{}, err
	}
	if founder, err := cppki.ExtractIA(pred.TRC.Certificates[vote].Subject); err != nil || founder.Equal(core) {
		return cppki.TRC{}, serrors.New("the founder removes no core of its own", "core", core)
	}
	certs := slices.DeleteFunc(slices.Clone(pred.TRC.Certificates), func(cert *x509.Certificate) bool {
		certIA, err := cppki.ExtractIA(cert.Subject)
		return err == nil && certIA.Equal(core)
	})
	without := func(ases []addr.AS) []addr.AS {
		return slices.DeleteFunc(slices.Clone(ases), func(as addr.AS) bool { return as == core.AS() })
	}
	validity := coveredValidity(certs)
	if at.After(validity.NotBefore) {
		validity.NotBefore = at
	}
	return cppki.TRC{
		Version:           1,
		ID:                successorID(pred.TRC.ID),
		Validity:          validity,
		GracePeriod:       grace,
		NoTrustReset:      pred.TRC.NoTrustReset,
		Votes:             []int{vote},
		Quorum:            pred.TRC.Quorum,
		CoreASes:          without(pred.TRC.CoreASes),
		AuthoritativeASes: without(pred.TRC.AuthoritativeASes),
		Description:       fmt.Sprintf("CION removal of %s", core),
		Certificates:      certs,
	}, nil
}

// RemoveCore removes the core from the TRC by the founder's vote alone, under
// the decision's mutex: the successor AssembleRemoval builds on the newest
// pinned TRC with the grace period, the vote cast with the decision's
// sensitive key, pins once it verifies against the newest. A core the newest
// TRC neither names nor carries a certificate of is removed already, and
// nothing is cast.
func (c *TRCDecider) RemoveCore(ctx context.Context, core addr.IA, grace time.Duration) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	newest, err := c.newestTRC(ctx)
	if err != nil {
		return err
	}
	if !CoreNamed(newest.TRC, core) && len(CertsOf(newest.TRC, core)) == 0 {
		return nil
	}
	trc, err := AssembleRemoval(newest, core, grace, signingTime())
	if err != nil {
		return err
	}
	sensitiveCert, err := SignerCert(newest.TRC, cppki.Sensitive)
	if err != nil {
		return err
	}
	signed, err := signTRCPayload(trc, []*x509.Certificate{sensitiveCert}, []crypto.Signer{c.Sensitive})
	if err != nil {
		return serrors.Wrap("casting the founder's vote", err, "id", trc.ID)
	}
	if err := pinSuccessor(ctx, c.DB, newest, signed); err != nil {
		return err
	}
	slog.Info("Removed a core from the TRC", "core", core, "trc", signed.TRC.ID,
		"grace_period", grace)
	return nil
}

// sensitiveIndex returns the TRC's index of its first sensitive voting
// certificate: the founder's, whose vote a sensitive update carries.
func sensitiveIndex(trc cppki.TRC) (int, error) {
	for i, cert := range trc.Certificates {
		if ct, err := cppki.ValidateCert(cert); err == nil && ct == cppki.Sensitive {
			return i, nil
		}
	}
	return 0, serrors.New("the predecessor holds no sensitive voting certificate", "trc", trc.ID)
}
