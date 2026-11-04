// Package ping is CION's SCMP-echo application, the network's probe. Its
// resident prober measures the paths the node's picks and leases ask it to,
// and publishes their records on the node bus; its pinger, the client behind
// `cion ping`, rides a destination's lease, sends a count of requests, and
// reports per-reply RTT, the reply's path hops, and a loss summary. The
// responder that answers both is the node's own, part of the core.
package ping

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// Paths is the node's path resolution the pinger calls: the destination's
// lease.
type Paths interface {
	Lease(dst addr.IA) *scion.Lease
}

// Config configures one ping run.
type Config struct {
	// Conn is the pinger's socket; its port becomes the echo identifier the
	// replies return to.
	Conn *scion.Conn
	// Paths leases the path to the destination.
	Paths Paths
	// Dst is the destination ISD-AS.
	Dst addr.IA
	// DstHost is the destination's underlay host address, which the
	// responder's socket is bound to.
	DstHost netip.Addr
	// Count is the number of requests to send.
	Count int
	// Interval is the time between requests.
	Interval time.Duration
	// Wait bounds the wait for each reply before it counts as lost.
	Wait time.Duration
	// Ready bounds the wait for the network to serve before the counted
	// run: the wait for the lease's first path is retried within it and
	// uncounted warm-up requests leave until one is answered. Zero waits once
	// and counts at once; a destination no path composes for, within the
	// bound when set, is an error either way, never a hang.
	Ready time.Duration
	// Log receives a line per reply and the summary; nil discards them.
	Log func(string, ...any)
}

// ReplyStat is one matched reply.
type ReplyStat struct {
	// Seq is the reply's sequence number.
	Seq uint16
	// RTT is the time from sending the request to reading the reply.
	RTT time.Duration
	// Hops is the number of hop fields of the reply's arrival path — the
	// reversed road the reply came by; a one-hop arrival counts one hop.
	Hops int
	// Segments is the number of segments of the arrival path.
	Segments int
}

// Report summarizes a ping run.
type Report struct {
	// Sent is the number of requests sent.
	Sent int
	// Received is the number of requests answered.
	Received int
	// Replies holds one statistic per received reply.
	Replies []ReplyStat
}

// Loss returns the number of unanswered requests.
func (r *Report) Loss() int { return r.Sent - r.Received }

// Run sends Count echo requests at Interval, matching replies by identifier
// and sequence, each over the path the destination's lease holds then, and
// reports each counted reply to the lease as a delivery and each request it
// waited out as a loss; a router's interface-down signal ends a request's wait
// and reports nothing. Ready bounds the wait for a network still converging —
// the wait for the lease's first path retried within it, uncounted warm-up
// requests leaving until one is answered — so the counted run reports the
// network, not its bring-up. A destination no path composes for, within
// Ready when set, is an error, not a hang.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.Count < 1 {
		return nil, errors.New("ping count must be positive")
	}
	lease := cfg.Paths.Lease(cfg.Dst)
	// A cold boot serves no path at once — the beaconer's first propagation
	// pass waits out its interval — so the first wait retries within the
	// readiness bound; zero bounds nothing and the failure stands.
	deadline := time.Now().Add(cfg.Ready)
	_, err := lease.Await(ctx)
	for err != nil && time.Now().Before(deadline) {
		if !loops.Sleep(ctx, cfg.Interval) {
			return nil, ctx.Err()
		}
		_, err = lease.Await(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving a path to %s: %w", cfg.Dst, err)
	}
	// echo sends one request over the lease's path and awaits its reply,
	// reporting the outcome to the lease when counted; a request that fails
	// to leave is lost.
	echo := func(seq uint16, counted bool) (ReplyStat, bool, error) {
		leased, err := lease.Path()
		if err != nil {
			return ReplyStat{}, false, fmt.Errorf("resolving a path to %s: %w", cfg.Dst, err)
		}
		dst := &scion.Addr{
			IA:   cfg.Dst,
			Addr: netip.AddrPortFrom(cfg.DstHost, underlay.EndhostPort),
			Path: leased.Path,
		}
		sent := time.Now()
		if err := cfg.Conn.WriteEchoRequestTo(dst, seq, nil); err != nil {
			return ReplyStat{}, false, nil
		}
		reply, err := awaitReply(cfg, sent, seq)
		switch {
		case !counted:
		case err == nil:
			lease.Delivered(leased.ID)
		case errors.Is(err, os.ErrDeadlineExceeded):
			lease.Lost(leased.ID)
		}
		return reply, err == nil, nil
	}
	// The warm-up sends uncounted requests, their sequence numbers drawn
	// from the top so no late reply matches a counted one, until the first
	// answer or the bound: a warm restart's peer holds its verdict down
	// until the BFD handshake re-completes, refusing the first replies'
	// egress — losses the counted run would report as its own.
	for seq := uint16(0xffff); cfg.Ready > 0 && time.Now().Before(deadline); seq-- {
		if _, ok, err := echo(seq, false); ok || err != nil {
			break // the counted run reports a failure to resolve
		}
		if !loops.Sleep(ctx, cfg.Interval) {
			return nil, ctx.Err()
		}
	}

	report := &Report{}
	for seq := 0; seq < cfg.Count; seq++ {
		if seq > 0 && !loops.Sleep(ctx, cfg.Interval) {
			return report, ctx.Err()
		}
		reply, ok, err := echo(uint16(seq), true)
		if err != nil {
			return report, err
		}
		report.Sent++
		if ok {
			report.Received++
			report.Replies = append(report.Replies, reply)
			if cfg.Log != nil {
				cfg.Log("scmp_echo seq=%d rtt=%s hops=%d segments=%d",
					reply.Seq, reply.RTT.Round(time.Microsecond), reply.Hops, reply.Segments)
			}
		}
	}
	if cfg.Log != nil {
		cfg.Log("%d packets transmitted, %d received, %d lost",
			report.Sent, report.Received, report.Loss())
	}
	return report, nil
}

// awaitReply reads the reply matching the sequence; the wait elapsing, or a
// router refusing the request with an interface-down signal, fails it.
func awaitReply(cfg Config, sent time.Time, seq uint16) (ReplyStat, error) {
	if err := cfg.Conn.SetReadDeadline(sent.Add(cfg.Wait)); err != nil {
		return ReplyStat{}, err
	}
	_, from, err := cfg.Conn.ReadEchoReply(seq)
	if err != nil {
		return ReplyStat{}, err
	}
	stat := ReplyStat{Seq: seq, RTT: time.Since(sent), Hops: 1, Segments: 1}
	if from.Path != nil {
		stat.Hops = len(from.Path.HopFields)
		stat.Segments = len(from.Path.InfoFields)
	}
	return stat, nil
}
