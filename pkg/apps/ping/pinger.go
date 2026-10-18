// Package ping is CION's SCMP-echo application: the network's health probe and
// the first resident of the pkg/apps namespace — a consumer of the path
// library (pkg/libs/scion) beside the control plane. A pinger resolves the
// freshest path to a destination, sends a count of requests, and reports
// per-reply RTT, the reply's path hops, and a loss summary; the responder that
// answers them is the node's own, part of the core, so the pinger is the
// application's whole surface.
package ping

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// Paths is the node's path resolution the pinger calls: a path to the
// destination.
type Paths interface {
	Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error)
}

// Config configures one ping run.
type Config struct {
	// Conn is the pinger's socket; its port becomes the echo identifier the
	// replies return to.
	Conn *scion.Conn
	// Paths resolves paths to the destination.
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
	// run: the first path resolution is retried within it and uncounted
	// warm-up requests leave until one is answered. Zero resolves once and
	// counts at once; a destination no path resolves for, within the bound
	// when set, is an error either way, never a hang.
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
	// Reresolves is the number of path resolutions beyond the first: expiry
	// or send errors re-resolved mid-run.
	Reresolves int
}

// Loss returns the number of unanswered requests.
func (r *Report) Loss() int { return r.Sent - r.Received }

// Run sends Count echo requests at Interval, matching replies by identifier
// and sequence. The path is resolved once and re-resolved whenever it
// expired or a send failed; the run continues either way. Ready bounds the
// wait for a network still converging — the first resolution retried within
// it, uncounted warm-up requests leaving until one is answered — so the
// counted run reports the network, not its bring-up. A destination no path
// resolves for, within Ready when set, is an error, not a hang.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.Count < 1 {
		return nil, errors.New("ping count must be positive")
	}
	var path *spath.Decoded
	resolve := func() error {
		p, err := cfg.Paths.Path(ctx, cfg.Dst)
		if err != nil {
			return fmt.Errorf("resolving a path to %s: %w", cfg.Dst, err)
		}
		path = p
		return nil
	}
	// A cold boot serves no path at once — the beaconer's first propagation
	// pass waits out its interval — so the first resolution retries within
	// the readiness bound; zero bounds nothing and the failure stands.
	deadline := time.Now().Add(cfg.Ready)
	err := resolve()
	for err != nil && time.Now().Before(deadline) {
		if !loops.Sleep(ctx, cfg.Interval) {
			return nil, ctx.Err()
		}
		err = resolve()
	}
	if err != nil {
		return nil, err
	}
	// The warm-up sends uncounted requests, their sequence numbers drawn
	// from the top so no late reply matches a counted one, until the first
	// answer or the bound: a warm restart's peer holds its verdict down
	// until the BFD handshake re-completes, refusing the first replies'
	// egress — losses the counted run would report as its own.
	for seq := uint16(0xffff); cfg.Ready > 0 && time.Now().Before(deadline); seq-- {
		if path == nil || !scion.PathExpiry(path).After(time.Now()) {
			if err := resolve(); err != nil {
				break // the counted run re-resolves and reports the failure
			}
		}
		dst := &scion.Addr{
			IA:   cfg.Dst,
			Addr: netip.AddrPortFrom(cfg.DstHost, underlay.EndhostPort),
			Path: path,
		}
		sent := time.Now()
		if err := cfg.Conn.WriteEchoRequestTo(dst, seq, nil); err != nil {
			path = nil // re-resolved on the next warm-up request
		} else if _, ok := awaitReply(cfg, sent, seq); ok {
			break
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
		// A path that expired since the last send — or failed to leave — is
		// re-resolved; the run continues.
		if path == nil || !scion.PathExpiry(path).After(time.Now()) {
			report.Reresolves++
			if err := resolve(); err != nil {
				return report, err
			}
		}
		dst := &scion.Addr{
			IA:   cfg.Dst,
			Addr: netip.AddrPortFrom(cfg.DstHost, underlay.EndhostPort),
			Path: path,
		}
		sent := time.Now()
		if err := cfg.Conn.WriteEchoRequestTo(dst, uint16(seq), nil); err != nil {
			path = nil // re-resolved on the next request
			report.Sent++
			continue
		}
		report.Sent++
		if reply, ok := awaitReply(cfg, sent, uint16(seq)); ok {
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

// awaitReply reads the reply matching the sequence; the wait elapsing or a
// router refusing the request with an interface-down signal loses it.
func awaitReply(cfg Config, sent time.Time, seq uint16) (ReplyStat, bool) {
	if err := cfg.Conn.SetReadDeadline(sent.Add(cfg.Wait)); err != nil {
		return ReplyStat{}, false
	}
	_, from, err := cfg.Conn.ReadEchoReply(seq)
	if err != nil {
		return ReplyStat{}, false
	}
	stat := ReplyStat{Seq: seq, RTT: time.Since(sent), Hops: 1, Segments: 1}
	if from.Path != nil {
		stat.Hops = len(from.Path.HopFields)
		stat.Segments = len(from.Path.InfoFields)
	}
	return stat, true
}
