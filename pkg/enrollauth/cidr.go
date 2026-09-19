package enrollauth

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/fancl20/cion/pkg/controlplane"
)

// CIDR is the enrollment authorizer of addressing (ADR-0010): it admits a
// first issuance whose SCION source address falls in one of the listed
// prefixes and denies everything else — a request carrying no address among
// them, for a gate that opens when its signal is missing is no gate. The
// address is self-claimed but return-routable: a joiner behind translation
// presents its private address, and a private-range entry is what admits
// such joiners; a fabricated address inside an allowed prefix completes no
// enrollment at all. The check is stateless and instant, and its denials are
// as quiet as its admissions: the trust service's log line is the whole of
// the record.
type CIDR struct {
	prefixes []netip.Prefix
}

// NewCIDR parses a comma-separated prefix list — the cidrs spec of
// --enroll-auth — once, so a malformed entry fails the boot, not the first
// joiner.
func NewCIDR(spec string) (*CIDR, error) {
	parts := strings.Split(spec, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, s := range parts {
		s = strings.TrimSpace(s)
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("parsing prefix %q: %w", s, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return &CIDR{prefixes: prefixes}, nil
}

// Authorize allows exactly a request whose source address a listed prefix
// contains.
func (c *CIDR) Authorize(
	_ context.Context,
	f controlplane.EnrollmentFacts,
) controlplane.EnrollmentVerdict {

	if !f.Addr.IsValid() {
		return controlplane.EnrollmentDeny
	}
	for _, prefix := range c.prefixes {
		if prefix.Contains(f.Addr.Addr()) {
			return controlplane.EnrollmentAllow
		}
	}
	return controlplane.EnrollmentDeny
}
