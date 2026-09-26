package enrollauth

import (
	"context"
	"net/netip"
	"testing"

	"github.com/fancl20/cion/pkg/controlplane"
)

func TestCIDRParse(t *testing.T) {
	cidrs, err := NewCIDR("192.0.2.0/24, 2001:db8::/32")
	if err != nil {
		t.Fatalf("parsing a prefix list: %v", err)
	}
	if len(cidrs.prefixes) != 2 {
		t.Errorf("parsed prefixes = %d, want 2", len(cidrs.prefixes))
	}
	// A malformed prefix fails the parse, not the admission.
	for _, spec := range []string{"", "192.0.2.0/24,nope", "nope"} {
		if _, err := NewCIDR(spec); err == nil {
			t.Errorf("parsing %q succeeded, want refusal", spec)
		}
	}
}

// TestCIDRAuthorize checks the posture at both boundaries: the one prefix
// list answers enrollment and registration alike by source, failing closed
// when the fact is missing.
func TestCIDRAuthorize(t *testing.T) {
	cidrs, err := NewCIDR("192.0.2.0/24,198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	addr := func(boundary controlplane.Boundary, s string) controlplane.AdmissionFacts {
		facts := controlplane.AdmissionFacts{Boundary: boundary}
		if s != "" {
			facts.Source = netip.MustParseAddrPort(s)
		}
		return facts
	}
	cases := map[string]struct {
		facts controlplane.AdmissionFacts
		want  controlplane.AdmissionVerdict
	}{
		"enrollment from a match among several prefixes": {
			addr(controlplane.BoundaryEnrollment, "198.51.100.7:41234"),
			controlplane.AdmissionAllow,
		},
		"registration from a match": {
			addr(controlplane.BoundaryRegistration, "192.0.2.7:41234"),
			controlplane.AdmissionAllow,
		},
		"registration miss": {
			addr(controlplane.BoundaryRegistration, "203.0.113.7:41234"),
			controlplane.AdmissionDeny,
		},
		"enrollment miss": {
			addr(controlplane.BoundaryEnrollment, "203.0.113.7:41234"),
			controlplane.AdmissionDeny,
		},
		"no address": {
			addr(controlplane.BoundaryEnrollment, ""), controlplane.AdmissionDeny,
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
