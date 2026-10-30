package trust

import (
	"context"
	"log/slog"
	"time"

	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// BindHeldNames binds every ISD-AS that holds a chain valid now in the
// database to the chain's subject key, the bindings the founder's first
// issuances made before it kept them: until every core issued, the founder
// issued every chain, and its database holds each name's current one. A
// name bound to another key already stays bound to it, logged.
func BindHeldNames(ctx context.Context, db trustdb.DB) error {
	now := time.Now()
	chains, err := db.Chains(ctx, trustdb.ChainQuery{
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		return err
	}
	for _, chain := range chains {
		ia, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			return err
		}
		if err := db.BindKey(ctx, ia, chain[0].SubjectKeyId); err != nil {
			slog.Warn("Binding a held name", "isd_as", ia, "err", err)
		}
	}
	return nil
}
