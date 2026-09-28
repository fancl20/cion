// Package authtest implements the shared contract tests for enrollment
// authorizer implementations, the databases' impl/dbtest pattern: an
// implementation has at least one test that runs this suite.
package authtest

import (
	"context"
	"testing"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// Suite describes one implementation's run of the contract tests.
type Suite struct {
	// New builds the authorizer under test.
	New func(t *testing.T) enrollauth.AdmissionAuthorizer
	// Facts builds the facts the implementation cannot decide — a request
	// carrying no address for the CIDR authorizer, a prompt the Telegram
	// one cannot send — the fail-closed rule's input.
	Facts func(t *testing.T) enrollauth.AdmissionFacts
}

// Run tests one implementation of the enrollauth.AdmissionAuthorizer
// contract: the verdict vocabulary, and the fail-closed rule — a gate that
// cannot reach its signal denies.
func Run(t *testing.T, s Suite) {
	t.Run("contract: the zero answer denies", func(t *testing.T) {
		// The vocabulary's own rule: an uninitialized verdict must not
		// admit, so a caller that forgets to ask fails closed.
		var ans enrollauth.AdmissionAnswer
		if ans.Admission != enrollauth.AdmissionDeny {
			t.Errorf("the zero answer's verdict = %d, want deny",
				ans.Admission)
		}
	})
	t.Run("contract: a signal the gate cannot reach denies", func(t *testing.T) {
		auth := s.New(t)
		ans := auth.Authorize(context.Background(), s.Facts(t))
		switch ans.Admission {
		case enrollauth.AdmissionDeny:
		case enrollauth.AdmissionAllow, enrollauth.AdmissionPending:
			t.Errorf("undecidable facts answered %d, want deny", ans.Admission)
		default:
			t.Errorf("verdict %d is outside the vocabulary", ans.Admission)
		}
	})
}
