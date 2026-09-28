package cidr

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// Authorizer is the admission authorizer of addressing: it admits an exchange
// whose source address falls in one of the listed prefixes and denies
// everything else — a request carrying no address among them, for a gate that
// opens when its signal is missing is no gate. The address is self-claimed but
// return-routable: a joiner behind translation presents its private address,
// and a private-range entry is what admits such joiners; a fabricated address
// inside an allowed prefix completes no exchange at all. The posture answers
// both boundaries alike — joiner nodes by SCION source, joiner hosts by the
// internet address their TLS connection named — the one prefix list standing
// for the one network's addressing. The check is stateless and instant, and
// its denials are as quiet as its admissions: the caller's log line is the
// whole of the record.
type Authorizer struct {
	prefixes []netip.Prefix
}

// New parses a comma-separated prefix list — the cidrs spec of
// --trust.enroll-auth — once, so a malformed entry fails the boot, not the first
// joiner.
func New(spec string) (*Authorizer, error) {
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
	return &Authorizer{prefixes: prefixes}, nil
}

// Authorize allows exactly an exchange whose source address a listed prefix
// contains.
func (c *Authorizer) Authorize(
	_ context.Context,
	f enrollauth.AdmissionFacts,
) enrollauth.AdmissionAnswer {

	if !f.Source.IsValid() {
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
	}
	for _, prefix := range c.prefixes {
		if prefix.Contains(f.Source.Addr()) {
			return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}
		}
	}
	return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionDeny}
}
