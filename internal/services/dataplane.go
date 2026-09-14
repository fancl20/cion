package services

import (
	"fmt"
	"runtime"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
)

// buffer sizes of the underlay sockets. They are fixed, not run flags: the
// OS caps them (net.core.rmem_max and friends), so a flag would promise a
// knob the kernel quietly ignores.
const (
	receiveBufferSize = 1 << 20
	sendBufferSize    = 1 << 20
)

// DataplaneOptions carries the run command's data-plane tuning; BootApp
// uses the defaults. The fields map one to one onto the data plane's
// RunConfig and the per-link queue depth.
type DataplaneOptions struct {
	Processors int // RunConfig.NumProcessors
	BatchSize  int // RunConfig.BatchSize and the UDP provider's batch
	QueueSize  int // internal and external link queue depth
}

// DefaultDataplaneOptions returns the data-plane tuning the daemon and the
// ping application run with unless the run command overrides it.
func DefaultDataplaneOptions() DataplaneOptions {
	return DataplaneOptions{
		Processors: max(1, runtime.NumCPU()/2),
		BatchSize:  64,
		QueueSize:  64,
	}
}

// setupDataPlane assembles the underlay: metrics, the UDP provider, the
// internal link, the external links from the configuration, the data plane,
// and discovery registered on the provider so the internal link routes
// CS-addressed packets to it.
func (n *node) setupDataPlane() error {
	metrics, err := dataplane.NewMetrics()
	if err != nil {
		return fmt.Errorf("creating metrics: %w", err)
	}
	n.metrics = metrics
	provider := dataplane.NewUDPProvider(n.opts.BatchSize, receiveBufferSize, sendBufferSize)
	n.udp = provider

	links := make([]dataplane.Link, 0, len(n.cfg.Interfaces)+1)
	internalLink, err := provider.NewInternalLink(
		n.cfg.Internal, n.opts.QueueSize, metrics.NewInterfaceMetrics(0, n.ident.ia, 0),
	)
	if err != nil {
		return fmt.Errorf("creating internal link: %w", err)
	}
	links = append(links, internalLink)
	neighborLinks := make(map[uint16]addr.IA, len(n.cfg.Interfaces))
	for _, iface := range n.cfg.Interfaces {
		link, err := provider.NewExternalLink(
			n.opts.QueueSize, nil, iface.Local, iface.Remote, iface.ID,
			metrics.NewInterfaceMetrics(iface.ID, n.ident.ia, 0),
		)
		if err != nil {
			return fmt.Errorf("creating interface %d: %w", iface.ID, err)
		}
		links = append(links, link)
		neighborIA, err := addr.ParseIA(iface.NeighborIA)
		if err != nil {
			return fmt.Errorf("parsing neighbor IA of interface %d: %w", iface.ID, err)
		}
		neighborLinks[iface.ID] = neighborIA
	}
	n.links = neighborLinks

	d, err := dataplane.NewDataPlane(n.ident.ia, n.ident.localHost, n.ident.key, provider, links)
	if err != nil {
		return err
	}
	d.RunConfig = dataplane.RunConfig{
		NumProcessors:         n.opts.Processors,
		NumSlowPathProcessors: 1,
		BatchSize:             n.opts.BatchSize,
		ReceiveBufferSize:     receiveBufferSize,
		SendBufferSize:        sendBufferSize,
	}
	n.dp = d

	discovery, err := controlplane.NewDiscovery(controlplane.DiscoveryConfig{
		IA:           n.ident.ia,
		ControlAddr:  n.cfg.Control,
		MACKey:       n.ident.key,
		InternalAddr: n.cfg.Internal,
		Links:        neighborLinks,
	})
	if err != nil {
		return err
	}
	if err := discovery.Register(provider); err != nil {
		return fmt.Errorf("registering control service: %w", err)
	}
	n.discovery = discovery
	return nil
}
