package portal

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/authtest"
)

func mustIA(s string) addr.IA { return addr.MustParseIA(s) }

// TestContract runs the shared contract: the facts the portal cannot decide
// are the ones presenting no keys, for an identity is what an ask names.
func TestContract(t *testing.T) {
	authtest.Run(t, authtest.Suite{
		New: func(t *testing.T) enrollauth.AdmissionAuthorizer { return newPortal(t) },
		Facts: func(*testing.T) enrollauth.AdmissionFacts {
			return enrollauth.AdmissionFacts{
				Boundary: enrollauth.BoundaryRegistration,
				Source:   netip.MustParseAddrPort("192.0.2.7:41641"),
			}
		},
	})
}

// verdict asks the portal and answers the verdict alone.
func verdict(p *Portal, f enrollauth.AdmissionFacts) enrollauth.AdmissionVerdict {
	return p.Authorize(context.Background(), f).Admission
}

// TestAsksWindows checks the asks' lifecycle on the clock: an ask pends and
// refreshes on every retry; an approval admits the next retry with the
// operator's note and leaves the list, and lapses unconsumed past its
// window; a rejection denies for a day and lapses back to an ask; approving
// a rejected ask admits; and an ask its joiner stopped asking leaves the
// list.
func TestAsksWindows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPortal(t)
		joiner := enrollment("1-ff00:0:110", "aa01")
		for range 3 {
			if got := verdict(p, joiner); got != enrollauth.AdmissionPending {
				t.Fatalf("an undecided ask answered %d, want pending", got)
			}
		}
		asks := p.Asks(enrollauth.BoundaryEnrollment)
		if len(asks) != 1 || asks[0].Attempts != 3 || asks[0].Verdict != enrollauth.AdmissionPending ||
			asks[0].Claim != mustIA("1-ff00:0:110") {
			t.Fatalf("the listed asks = %+v, want the one pending after 3 attempts", asks)
		}

		// An approval admits the next retry, which consumes it from the list.
		if !p.Decide(asks[0].ID, true) {
			t.Fatal("approving the listed ask found none")
		}
		answer := p.Authorize(context.Background(), joiner)
		if answer.Admission != enrollauth.AdmissionAllow || answer.Note != operatorNote {
			t.Fatalf("the approved retry answered %+v, want allow by the operator", answer)
		}
		if got := p.Asks(enrollauth.BoundaryEnrollment); len(got) != 0 {
			t.Errorf("a consumed approval stays listed: %+v", got)
		}

		// An approval nobody consumes lapses with its window.
		other := enrollment("1-ff00:0:111", "aa02")
		verdict(p, other)
		p.Decide(p.Asks(enrollauth.BoundaryEnrollment)[0].ID, true)
		time.Sleep(approveWindow)
		if got := verdict(p, other); got != enrollauth.AdmissionPending {
			t.Errorf("a lapsed approval answered %d, want a fresh pending ask", got)
		}

		// A rejection denies for a day, listed with when it lapses, and an
		// approval replaces it.
		stranger := enrollment("1-ff00:0:112", "aa03")
		verdict(p, stranger)
		id := askID(t, p, "1-ff00:0:112")
		p.Decide(id, false)
		time.Sleep(rejectWindow - time.Minute)
		if got := verdict(p, stranger); got != enrollauth.AdmissionDeny {
			t.Errorf("a standing rejection answered %d, want deny", got)
		}
		if state := askState(t, p, "1-ff00:0:112"); state.Verdict != enrollauth.AdmissionDeny ||
			!state.Until.Equal(time.Now().Add(time.Minute)) {
			t.Errorf("the rejected ask lists %+v, want rejected until its day ends", state)
		}
		time.Sleep(time.Minute)
		if got := verdict(p, stranger); got != enrollauth.AdmissionPending {
			t.Errorf("a lapsed rejection answered %d, want a fresh pending ask", got)
		}
		p.Decide(askID(t, p, "1-ff00:0:112"), false)
		p.Decide(askID(t, p, "1-ff00:0:112"), true)
		if got := verdict(p, stranger); got != enrollauth.AdmissionAllow {
			t.Errorf("an approved rejection answered %d, want allow", got)
		}

		// An ask whose joiner stopped asking leaves the list.
		quiet := enrollment("1-ff00:0:113", "aa04")
		verdict(p, quiet)
		time.Sleep(idleWindow)
		p.sweep(time.Now())
		for _, a := range p.Asks(enrollauth.BoundaryEnrollment) {
			if a.Claim == mustIA("1-ff00:0:113") {
				t.Errorf("an idle ask stays listed: %+v", a)
			}
		}
	})
}

// askState finds the listed ask of the claim.
func askState(t *testing.T, p *Portal, claim string) enrollauth.Ask {
	t.Helper()
	for _, a := range p.Asks(enrollauth.BoundaryEnrollment, enrollauth.BoundaryVoting) {
		if a.Claim == mustIA(claim) {
			return a
		}
	}
	t.Fatalf("no ask of %s is listed", claim)
	return enrollauth.Ask{}
}

// askID finds the listed ask of the claim and answers its ID.
func askID(t *testing.T, p *Portal, claim string) string {
	t.Helper()
	return askState(t, p, claim).ID
}

// TestAsksIdentity checks what an ask names: an enrollment's claim and key
// together, so two strangers claiming one name ask twice; and that a bare
// registration asks nothing at all, denied without a listing.
func TestAsksIdentity(t *testing.T) {
	p := newPortal(t)
	verdict(p, enrollment("1-ff00:0:110", "aa01"))
	verdict(p, enrollment("1-ff00:0:110", "bb02"))
	if nodes := p.Asks(enrollauth.BoundaryEnrollment); len(nodes) != 2 {
		t.Errorf("two keys claiming one name list %d asks, want 2", len(nodes))
	}
	if got := verdict(p, registration("mkey:01", "nodekey:01", "")); got != enrollauth.AdmissionDeny {
		t.Errorf("a bare registration answered %d, want deny", got)
	}
	if hosts := p.Asks(enrollauth.BoundaryRegistration); len(hosts) != 0 {
		t.Errorf("a bare registration listed %+v, want no ask", hosts)
	}
	if p.Decide("not-an-id", true) {
		t.Error("a malformed ask ID decided")
	}
}

// TestAsksEvictLeastRecent checks the table's bound: past it, the ask seen
// least recently leaves for the new one.
func TestAsksEvictLeastRecent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPortal(t)
		first := enrollment("1-ff00:0:1", "00")
		verdict(p, first)
		for i := range maxAsks - 1 {
			time.Sleep(time.Millisecond)
			verdict(p, enrollment("1-ff00:0:2", string(rune('a'+i%26))+string(rune('a'+i/26))))
		}
		time.Sleep(time.Millisecond)
		verdict(p, enrollment("1-ff00:0:3", "zz"))
		asks := p.Asks(enrollauth.BoundaryEnrollment)
		if len(asks) != maxAsks {
			t.Fatalf("the table holds %d asks, want the bound %d", len(asks), maxAsks)
		}
		for _, a := range asks {
			if a.Claim == mustIA("1-ff00:0:1") {
				t.Error("the least recently seen ask stayed past the bound")
			}
		}
	})
}
