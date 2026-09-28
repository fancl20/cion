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
	"time"
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
		if err := os.WriteFile(h.path, []byte(host.String()+"\n"), 0o600); err != nil {
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

// domainHost resolves the founding core's own domain to the address its
// entry publishes — the name its certificate machinery stands behind, which
// the mapping a provider holds the core behind already resolves to it. The
// answer must share the control host's family: the published address is one
// the node's sockets bind. The fallback is the control host itself.
type domainHost struct {
	domain   string
	fallback netip.Addr

	// lookup resolves a name; nil uses the system resolver. The field is
	// the tests' seam.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)

	mtx sync.Mutex
	// at, host, and ok memoize the last resolution.
	at   time.Time
	host netip.Addr
	ok   bool
}

// resolve returns the domain's address, the fallback when the name fails to
// resolve or carries no address of the control host's family.
func (d *domainHost) resolve(ctx context.Context) netip.Addr {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	ttl := domainFailureTTL
	if d.ok {
		ttl = domainSuccessTTL
	}
	if !d.at.IsZero() && time.Since(d.at) < ttl {
		if d.ok {
			return d.host
		}
		return d.fallback
	}
	d.at = time.Now()
	d.host, d.ok = d.lookupAddr(ctx)
	if !d.ok {
		return d.fallback
	}
	return d.host
}

// lookupAddr resolves the domain, keeping the addresses of the control
// host's family alone.
func (d *domainHost) lookupAddr(ctx context.Context) (netip.Addr, bool) {
	lookup := d.lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	ctx, cancel := context.WithTimeout(ctx, domainLookupTimeout)
	defer cancel()
	addrs, err := lookup(ctx, "ip", d.domain)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		if a.IsValid() && a.BitLen() == d.fallback.BitLen() {
			return a, true
		}
	}
	return netip.Addr{}, false
}
