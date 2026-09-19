package enrollauth

import (
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
	// A malformed prefix fails the parse, not the enrollment.
	for _, spec := range []string{"", "192.0.2.0/24,nope", "nope"} {
		if _, err := NewCIDR(spec); err == nil {
			t.Errorf("parsing %q succeeded, want refusal", spec)
		}
	}
}

func TestCIDRAuthorize(t *testing.T) {
	cidrs, err := NewCIDR("192.0.2.0/24,198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	addr := func(s string) controlplane.EnrollmentFacts {
		return controlplane.EnrollmentFacts{Addr: netip.MustParseAddrPort(s)}
	}
	cases := map[string]struct {
		facts controlplane.EnrollmentFacts
		want  controlplane.EnrollmentVerdict
	}{
		"a match among several prefixes": {
			addr("198.51.100.7:41234"), controlplane.EnrollmentAllow,
		},
		"a miss": {
			addr("203.0.113.7:41234"), controlplane.EnrollmentDeny,
		},
		"no address": {
			controlplane.EnrollmentFacts{}, controlplane.EnrollmentDeny,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := cidrs.Authorize(nil, tc.facts); got != tc.want {
				t.Errorf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}
