package enrollauth

import (
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// An auth key's lifetime bounds, in days after its minting.
const (
	MinKeyDays = 1
	MaxKeyDays = 90
)

// Operator is the surface an operator's console decides through: the asks
// a method holds pending — node enrollments and the founder's votes — the
// decisions on them, and the auth keys the method mints and retires, each
// the whole admission of a host. A method that pends for an operator
// implements it beside AdmissionAuthorizer, and its console reaches it
// through the authorizer the operator selected — never through the
// implementation.
type Operator interface {
	// Asks lists the standing asks at the boundaries, oldest first: the
	// pending, the approved whose joiner has not yet returned, and the
	// rejected.
	Asks(boundaries ...Boundary) []Ask
	// Decide records the operator's decision on the ask the ID names,
	// reporting whether one stood to decide.
	Decide(id string, approve bool) bool
	// MintKey mints an auth key and answers the key itself — the one time
	// it leaves the method — beside its record.
	MintKey(req KeyRequest) (string, AuthKey, error)
	// Keys lists the minted keys, newest first.
	Keys() []AuthKey
	// RevokeKey retires the key the ID names, reporting whether it named
	// one.
	RevokeKey(id string) (bool, error)
}

// Ask is one identity's request as the operator reads it: the latest facts
// it presented, how often and since when it asked, and the standing
// decision.
type Ask struct {
	// ID names the ask to Decide.
	ID string
	// Boundary, Claim, Keys, and Source are the latest facts the identity
	// presented.
	Boundary Boundary
	Claim    addr.IA
	Keys     []string
	Source   netip.AddrPort
	// FirstSeen, LastSeen, and Attempts count the identity's asking.
	FirstSeen time.Time
	LastSeen  time.Time
	Attempts  int
	// Verdict is the standing decision, AdmissionPending while undecided;
	// Until is when a decision lapses, zero while it pends.
	Verdict AdmissionVerdict
	Until   time.Time
}

// KeyRequest is what the operator asks of a new auth key: its description,
// whether it admits more than one host, its lifetime, between MinKeyDays
// and MaxKeyDays, and the node its hosts land on — the zero IA naming the
// founding core.
type KeyRequest struct {
	Description string
	Reusable    bool
	Days        int
	Node        addr.IA
}

// KeyState is an auth key's standing.
type KeyState string

// The standings a key is listed in.
const (
	KeyActive  KeyState = "active"
	KeySpent   KeyState = "spent"
	KeyRevoked KeyState = "revoked"
	KeyExpired KeyState = "expired"
)

// AuthKey is one minted key as the operator reads it, never the key itself:
// Node is the node its hosts land on, the zero IA naming the founding core.
type AuthKey struct {
	ID          string
	Description string
	Reusable    bool
	Created     time.Time
	Expires     time.Time
	Uses        int
	State       KeyState
	Node        addr.IA
}
