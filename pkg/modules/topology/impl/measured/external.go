package measured

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// The founding core's domain lookups: the next comes domainSuccessTTL after
// an answer and domainFailureTTL after a failure.
const (
	domainSuccessTTL = time.Minute
	domainFailureTTL = 30 * time.Second
	// domainLookupTimeout bounds one lookup.
	domainLookupTimeout = 2 * time.Second
)

// holds reports whether the host is one of the node's own addresses: one a
// socket of the source binds. A bind refused with EADDRNOTAVAIL names a host
// the node does not hold, a NAT's; any other refusal is the error.
func holds(sockets underlay.Sockets, host netip.Addr) (bool, error) {
	conn, err := sockets.NewUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)), netip.AddrPort{})
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("binding the published host %s: %w", host, err)
	}
	_ = conn.Close()
	return true, nil
}

// domainHost resolves the founding core's own identity to the address its
// entry publishes: an address literal directly, a domain through the
// resolver, the mapping a provider holds the core behind; a domain's answer
// must share the bind host's family, the sockets binding it receiving what
// the published address draws — unless the bind is the wildcard, which names
// none, and the resolver's first answer publishes.
type domainHost struct {
	domain string
	// bind is the control host the node's sockets bind; its family alone
	// picks the resolver's answer.
	bind netip.Addr
	// literal is the identity's own address, valid when the identity is an
	// address: the one fact resolution needs then, a value that cannot
	// change.
	literal netip.Addr

	// lookup resolves a name: the socket source's resolver.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// newDomainHost builds the founder's host resolution, parsing the identity's
// grammar once: an address needs no lookup.
func newDomainHost(
	domain string, bind netip.Addr,
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error),
) *domainHost {

	d := &domainHost{domain: domain, bind: bind, lookup: lookup}
	if addr, err := netip.ParseAddr(domain); err == nil {
		d.literal = addr.Unmap()
	}
	return d
}

// lookupAddr resolves the domain, keeping the addresses of the bind host's
// family alone; a wildcard bind names none, and the resolver's first answer
// publishes.
func (d *domainHost) lookupAddr(ctx context.Context) (netip.Addr, bool) {
	ctx, cancel := context.WithTimeout(ctx, domainLookupTimeout)
	defer cancel()
	addrs, err := d.lookup(ctx, "ip", d.domain)
	if err != nil {
		return netip.Addr{}, false
	}
	wildcard := d.bind.IsUnspecified()
	for _, a := range addrs {
		if a = a.Unmap(); a.IsValid() && (wildcard || a.BitLen() == d.bind.BitLen()) {
			return a, true
		}
	}
	return netip.Addr{}, false
}
