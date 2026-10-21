// Package portal is the admission method the operator's passkey console
// decides: every boundary's new identity pends until the operator approves
// or rejects it, and a registration presenting an auth key the method
// minted is admitted on the key. The console reaches the asks and the keys
// through the Operator surface the method implements beside the
// authorizer.
//
// The asks live in memory; the auth keys persist beneath the state
// directory.
package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// sweepInterval paces Run's sweep of what stopped standing.
const sweepInterval = time.Minute

// Config configures the method.
type Config struct {
	// State is the core's state directory; the auth keys persist beneath
	// its enrollauth directory.
	State string
}

// Portal is the method. Its zero value is not usable; New builds it.
type Portal struct {
	state string

	// mtx guards the asks and the keys, shared by the admission
	// boundaries, the operator's console, and Run.
	mtx  sync.Mutex
	asks map[askKey]*ask
	keys []*authKey
}

var (
	_ enrollauth.AdmissionAuthorizer = (*Portal)(nil)
	_ enrollauth.Operator            = (*Portal)(nil)
)

// New builds the method over its persisted auth keys.
func New(cfg Config) (*Portal, error) {
	p := &Portal{
		state: cfg.State,
		asks:  make(map[askKey]*ask),
	}
	if err := p.loadKeys(); err != nil {
		return nil, err
	}
	return p, nil
}

// Run sweeps what stopped standing — asks and expired auth keys — until
// the context ends.
func (p *Portal) Run(ctx context.Context) {
	for loops.Sleep(ctx, sweepInterval) {
		p.sweep(time.Now())
	}
}

// sweep drops what stopped standing.
func (p *Portal) sweep(now time.Time) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.sweepAsksLocked(now)
	p.sweepKeysLocked(now)
}

// randomHex returns n bytes from crypto/rand, hex encoded; its Read never
// fails — the runtime crashes the program instead.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
