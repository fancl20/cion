package measured

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fancl20/cion/pkg/libs/statefile"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// ExternalHostFile holds the learned external host in the state directory's
// root, beside the identity. The rendezvous dial is the host's only carrier,
// and a node whose neighbors are all established sends none, so the host
// persists for a restart to republish.
const ExternalHostFile = "external-host"

// The domain resolution's memo windows: an answer holds for the publication
// cadence, a failure for longer — a name the resolver cannot answer must not
// burden the loop it resolves for.
const (
	domainSuccessTTL = NodePublishInterval
	domainFailureTTL = 30 * time.Second
	// domainLookupTimeout bounds one resolution attempt.
	domainLookupTimeout = 2 * time.Second
)

// loadExternalHost returns the learned external host a previous run
// persisted, the zero one when none is persisted yet.
func loadExternalHost(stateDir string) (netip.Addr, error) {
	if stateDir == "" {
		return netip.Addr{}, nil
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, ExternalHostFile))
	if errors.Is(err, os.ErrNotExist) {
		return netip.Addr{}, nil
	}
	if err != nil {
		return netip.Addr{}, err
	}
	host, err := netip.ParseAddr(strings.TrimSpace(string(raw)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing %s: %w", ExternalHostFile, err)
	}
	return host, nil
}

// externalHost is the node's learned external host: what the network
// observed its dials leave from, latest observation winning, persisted on
// change beside the identity. An empty path keeps the host in memory alone.
type externalHost struct {
	path string

	mtx sync.Mutex
	// current is the latest observation, zero when none landed yet.
	current netip.Addr
}

// observe records an observation, persisting it when it changes the host.
// An invalid address — a reply that echoes none — observes nothing.
func (h *externalHost) observe(host netip.Addr) error {
	if !host.IsValid() {
		return nil
	}
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.current == host {
		return nil
	}
	if h.path != "" {
		if err := statefile.Write(h.path, []byte(host.String()+"\n")); err != nil {
			return err
		}
	}
	h.current = host
	return nil
}

// host returns the learned host, zero when none is recorded.
func (h *externalHost) host() netip.Addr {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.current
}

// holds reports whether the host is one of the node's own addresses: one a
// socket of the source binds. A bind refused with EADDRNOTAVAIL names a host
// the node does not hold, a translator's; any other refusal is the error.
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
// resolver, the mapping a provider holds the core behind; a domain's
// answer must share the bind host's family, the sockets binding it
// receiving what the published address draws — unless the bind is the
// wildcard, which names none, and the resolver's first answer publishes.
// Only an answer the resolver vouched for publishes: a failed re-resolution
// holds the last good one, and before any has landed the zero address,
// which publishes nothing.
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

	mtx sync.Mutex
	// at and ok memoize the last attempt — its moment and its outcome —
	// and host the last good answer, held through a failure.
	at   time.Time
	host netip.Addr
	ok   bool
}

// newDomainHost builds the founder's host resolution, parsing the identity's
// grammar once: an address needs no lookup and no memoization.
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

// resolve returns the identity's address: the literal itself when the
// identity is one, else the domain's — the last good answer held through a
// failed resolution, the zero address before any has landed.
func (d *domainHost) resolve(ctx context.Context) netip.Addr {
	if d.literal.IsValid() {
		return d.literal
	}
	d.mtx.Lock()
	defer d.mtx.Unlock()
	ttl := domainFailureTTL
	if d.ok {
		ttl = domainSuccessTTL
	}
	if d.at.IsZero() || time.Since(d.at) >= ttl {
		d.at = time.Now()
		if host, ok := d.lookupAddr(ctx); ok {
			d.host, d.ok = host, true
		} else {
			d.ok = false
		}
	}
	return d.host
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
