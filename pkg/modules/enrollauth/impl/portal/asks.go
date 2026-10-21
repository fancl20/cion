package portal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// The asks' windows and bound: an approval stands long enough for the
// joiner's next retry, a rejection a day — a joiner retrying every few
// seconds does not return to the list on every window — and a pending ask
// whose joiner stopped asking leaves the list after the approval's window.
// The table holds a bounded number of asks; past it, the ask seen least
// recently leaves.
const (
	approveWindow = 10 * time.Minute
	rejectWindow  = 24 * time.Hour
	idleWindow    = 10 * time.Minute
	maxAsks       = 256
)

// The notes the registry records beside an approved host.
const (
	operatorNote   = "portal operator"
	authKeyNotePre = "portal auth key "
)

// askKey names one identity: the boundary asking, the exchange's claim, and
// a digest of the identity's stable key, so two strangers claiming one name
// ask twice and the operator admits at most one.
type askKey struct {
	boundary enrollauth.Boundary
	claim    addr.IA
	digest   [sha256.Size / 2]byte
}

// ask is one identity's request as the method keeps it: the latest facts
// it presented, how often and since when it asked, and the operator's
// standing decision.
type ask struct {
	facts      enrollauth.AdmissionFacts
	credential bool
	firstSeen  time.Time
	lastSeen   time.Time
	attempts   int
	verdict    enrollauth.AdmissionVerdict
	decided    time.Time
	// admitted marks an approval its joiner's retry has consumed; the ask
	// stands for the rest of its window but leaves the list.
	admitted bool
}

// keyOf names the identity the facts present: the registration's machine
// key — the one fact that survives a client's retries, each presenting a
// fresh node key until one completes — the enrollment's subject key, and
// the voting submission's added keys.
func keyOf(f enrollauth.AdmissionFacts) askKey {
	identity := strings.Join(f.Keys, ",")
	if f.Boundary == enrollauth.BoundaryRegistration {
		identity = f.Keys[0]
	}
	sum := sha256.Sum256([]byte(identity))
	k := askKey{boundary: f.Boundary, claim: f.Claim}
	copy(k.digest[:], sum[:])
	return k
}

// id renders the identity as the operator's console names it: the
// boundary, the claim, and the digest, hex encoded.
func (k askKey) id() string {
	b := make([]byte, 0, 1+8+len(k.digest))
	b = append(b, byte(k.boundary))
	b = binary.BigEndian.AppendUint64(b, uint64(k.claim))
	return hex.EncodeToString(append(b, k.digest[:]...))
}

// parseAskID decodes an identity the console names.
func parseAskID(s string) (askKey, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 1+8+sha256.Size/2 {
		return askKey{}, false
	}
	boundary := enrollauth.Boundary(b[0])
	switch boundary {
	case enrollauth.BoundaryEnrollment, enrollauth.BoundaryRegistration,
		enrollauth.BoundaryVoting:
	default:
		return askKey{}, false
	}
	k := askKey{boundary: boundary, claim: addr.IA(binary.BigEndian.Uint64(b[1:9]))}
	copy(k.digest[:], b[9:])
	return k, true
}

// lapsed reports whether the ask stopped standing: a decision past its
// window, a pending ask its joiner stopped asking.
func (a *ask) lapsed(now time.Time) bool {
	switch a.verdict {
	case enrollauth.AdmissionAllow:
		return !now.Before(a.decided.Add(approveWindow))
	case enrollauth.AdmissionDeny:
		return !now.Before(a.decided.Add(rejectWindow))
	default:
		return !now.Before(a.lastSeen.Add(idleWindow))
	}
}

// until is when the ask's decision lapses; zero while it pends.
func (a *ask) until() time.Time {
	switch a.verdict {
	case enrollauth.AdmissionAllow:
		return a.decided.Add(approveWindow)
	case enrollauth.AdmissionDeny:
		return a.decided.Add(rejectWindow)
	default:
		return time.Time{}
	}
}

// Authorize answers one admission exchange: facts presenting no keys are
// denied; a registration presenting an auth key that stands for its
// identity is admitted on the key; an identity the operator decided
// answers the standing decision; any other pends, listed for the operator
// with the facts it presented. A credential matching no standing key falls
// through to the operator, a stale key failing toward the human rather
// than closed.
func (p *Portal) Authorize(
	_ context.Context,
	f enrollauth.AdmissionFacts,
) enrollauth.AdmissionAnswer {

	if len(f.Keys) == 0 {
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	}
	now := time.Now()
	key := keyOf(f)
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if f.Boundary == enrollauth.BoundaryRegistration && f.Credential != "" {
		if id, ok := p.spendLocked(f.Credential, key.id(), now); ok {
			return enrollauth.AdmissionAnswer{
				Admission: enrollauth.AdmissionAllow,
				Note:      authKeyNotePre + id,
			}
		}
	}
	a := p.asks[key]
	if a != nil && a.lapsed(now) {
		delete(p.asks, key)
		a = nil
	}
	if a == nil {
		p.evictLocked()
		a = &ask{firstSeen: now, verdict: enrollauth.AdmissionPending}
		p.asks[key] = a
	}
	a.facts = f
	a.facts.Credential = ""
	a.credential = f.Credential != ""
	a.lastSeen = now
	a.attempts++
	switch a.verdict {
	case enrollauth.AdmissionAllow:
		a.admitted = true
		return enrollauth.AdmissionAnswer{
			Admission: enrollauth.AdmissionAllow,
			Note:      operatorNote,
		}
	case enrollauth.AdmissionDeny:
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	default:
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionPending}
	}
}

// evictLocked makes room for one ask: past the bound, the ask seen least
// recently leaves.
func (p *Portal) evictLocked() {
	if len(p.asks) < maxAsks {
		return
	}
	var oldest askKey
	var at time.Time
	for key, a := range p.asks {
		if at.IsZero() || a.lastSeen.Before(at) {
			oldest, at = key, a.lastSeen
		}
	}
	delete(p.asks, oldest)
}

// Decide records the operator's decision on the ask the ID names,
// reporting whether one stood to decide: an ask its joiner's retry already
// admitted is settled. Approving a rejected ask replaces the rejection.
func (p *Portal) Decide(id string, approve bool) bool {
	key, ok := parseAskID(id)
	if !ok {
		return false
	}
	now := time.Now()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	a := p.asks[key]
	if a == nil || a.admitted || a.lapsed(now) {
		return false
	}
	a.verdict = enrollauth.AdmissionDeny
	if approve {
		a.verdict = enrollauth.AdmissionAllow
	}
	a.decided = now
	a.admitted = false
	slog.Info("Admission decided in the portal", "boundary", key.boundary,
		"claim", key.claim, "keys", a.facts.Keys, "approved", approve)
	return true
}

// Asks lists the standing asks of the boundaries, oldest first: the
// pending, the approved its joiner has not yet consumed, and the rejected.
func (p *Portal) Asks(boundaries ...enrollauth.Boundary) []enrollauth.Ask {
	now := time.Now()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	var asks []enrollauth.Ask
	for key, a := range p.asks {
		if a.admitted || a.lapsed(now) || !slices.Contains(boundaries, key.boundary) {
			continue
		}
		asks = append(asks, enrollauth.Ask{
			ID:         key.id(),
			Boundary:   key.boundary,
			Claim:      key.claim,
			Keys:       a.facts.Keys,
			Label:      a.facts.Label,
			Source:     a.facts.Source,
			Credential: a.credential,
			FirstSeen:  a.firstSeen,
			LastSeen:   a.lastSeen,
			Attempts:   a.attempts,
			Verdict:    a.verdict,
			Until:      a.until(),
		})
	}
	slices.SortFunc(asks, func(a, b enrollauth.Ask) int { return a.FirstSeen.Compare(b.FirstSeen) })
	return asks
}

// sweepAsksLocked drops the asks that stopped standing.
func (p *Portal) sweepAsksLocked(now time.Time) {
	for key, a := range p.asks {
		if a.lapsed(now) {
			delete(p.asks, key)
		}
	}
}
