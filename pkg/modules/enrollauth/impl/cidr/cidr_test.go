package cidr

import (
	"context"
	"net/netip"
	"testing"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/authtest"
)

func TestCIDRParse(t *testing.T) {
	cidrs, err := New("192.0.2.0/24, 2001:db8::/32")
	if err != nil {
		t.Fatalf("parsing a prefix list: %v", err)
	}
	if len(cidrs.prefixes) != 2 {
		t.Errorf("parsed prefixes = %d, want 2", len(cidrs.prefixes))
	}
	// A malformed prefix fails the parse, not the admission.
	for _, spec := range []string{"", "192.0.2.0/24,nope", "nope"} {
		if _, err := New(spec); err == nil {
			t.Errorf("parsing %q succeeded, want refusal", spec)
		}
	}
}

// TestCIDRAuthorize checks the posture at both boundaries: the one prefix
// list answers enrollment and registration alike by source, failing closed
// when the fact is missing.
func TestCIDRAuthorize(t *testing.T) {
	cidrs, err := New("192.0.2.0/24,198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	addr := func(boundary enrollauth.Boundary, s string) enrollauth.AdmissionFacts {
		facts := enrollauth.AdmissionFacts{Boundary: boundary}
		if s != "" {
			facts.Source = netip.MustParseAddrPort(s)
		}
		return facts
	}
	cases := map[string]struct {
		facts enrollauth.AdmissionFacts
		want  enrollauth.AdmissionVerdict
	}{
		"enrollment from a match among several prefixes": {
			addr(enrollauth.BoundaryEnrollment, "198.51.100.7:41234"),
			enrollauth.AdmissionAllow,
		},
		"registration from a match": {
			addr(enrollauth.BoundaryRegistration, "192.0.2.7:41234"),
			enrollauth.AdmissionAllow,
		},
		"registration miss": {
			addr(enrollauth.BoundaryRegistration, "203.0.113.7:41234"),
			enrollauth.AdmissionDeny,
		},
		"enrollment miss": {
			addr(enrollauth.BoundaryEnrollment, "203.0.113.7:41234"),
			enrollauth.AdmissionDeny,
		},
		"no address": {
			addr(enrollauth.BoundaryEnrollment, ""), enrollauth.AdmissionDeny,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := cidrs.Authorize(context.Background(), tc.facts).Admission
			if got != tc.want {
				t.Errorf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestContract runs the module's shared contract suite: the fail-closed
// input is a request carrying no address, for a gate that opens when its
// signal is missing is no gate.
func TestContract(t *testing.T) {
	authtest.Run(t, authtest.Suite{
		New: func(t *testing.T) enrollauth.AdmissionAuthorizer {
			auth, err := New("192.0.2.0/24")
			if err != nil {
				t.Fatal(err)
			}
			return auth
		},
		Facts: func(t *testing.T) enrollauth.AdmissionFacts {
			return enrollauth.AdmissionFacts{Boundary: enrollauth.BoundaryEnrollment}
		},
	})
}
