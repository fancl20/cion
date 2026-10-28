package services

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/modules/links"
)

// nudgeLinkState wakes the link state loop: the store's write signal, a
// verdict's flip, an observation's move, and a generation swap each run it.
// A burst coalesces in the one-slot channel, and the nudge never blocks.
func (n *node) nudgeLinkState() {
	select {
	case n.linkNudges <- struct{}{}:
	default:
	}
}

// serveLinkState is the link state loop: on each nudge it publishes the
// node's link state afresh, so one publish stands for every change since
// the last.
func (n *node) serveLinkState(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-n.linkNudges:
			if err := n.publishLinkState(ctx); err != nil {
				return err
			}
		}
	}
}

// publishLinkState publishes the link state the store's live entries, the
// monitor's verdicts, and the serving links' observations make up.
func (n *node) publishLinkState(ctx context.Context) error {
	entries, err := n.linkStore.All(ctx)
	if err != nil {
		return fmt.Errorf("reading the link store: %w", err)
	}
	n.bus.Links().Publish(linkStateOf(entries, n.monitor.Verdicts(), n.observedSource))
	return nil
}

// linkStateOf returns the link state of the store's live entries: each
// link's verdict down where the monitor holds it down — an interface the
// monitor runs no session for is up — and its observed source.
func linkStateOf(
	entries []*links.Link, verdicts map[uint16]bool, observed func(ifID uint16) netip.AddrPort,
) bus.LinkState {

	ls := make([]bus.Link, 0, len(entries))
	for _, e := range entries {
		if !e.Live() {
			continue
		}
		up, ok := verdicts[e.IfID]
		ls = append(ls, bus.Link{
			Entry:    *e,
			Down:     ok && !up,
			Observed: observed(e.IfID),
		})
	}
	return bus.NewLinkState(ls...)
}
