package ping

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/scion"
)

// Config configures one ping run.
type Config struct {
	// Conn is the pinger's socket; its port becomes the echo identifier the
	// replies return to.
	Conn *scion.Conn
	// Provider resolves paths to the destination.
	Provider *scion.PathProvider
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
// expired or a send failed; the run continues either way. A destination no
// path resolves for is an error, not a hang.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.Count < 1 {
		return nil, errors.New("ping count must be positive")
	}
	var path *spath.Decoded
	resolve := func() error {
		p, err := cfg.Provider.Path(ctx, cfg.Dst)
		if err != nil {
			return fmt.Errorf("resolving a path to %s: %w", cfg.Dst, err)
		}
		path = p
		return nil
	}
	if err := resolve(); err != nil {
		return nil, err
	}

	report := &Report{}
	for seq := 0; seq < cfg.Count; seq++ {
		if seq > 0 {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			case <-time.After(cfg.Interval):
			}
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
			Addr: netip.AddrPortFrom(cfg.DstHost, dataplane.EndhostPort),
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

// awaitReply reads echo messages until the one matching the sequence arrives
// or the wait elapses.
func awaitReply(cfg Config, sent time.Time, seq uint16) (ReplyStat, bool) {
	if err := cfg.Conn.SetReadDeadline(sent.Add(cfg.Wait)); err != nil {
		return ReplyStat{}, false
	}
	for {
		echo, from, err := cfg.Conn.ReadEchoFrom()
		if err != nil {
			return ReplyStat{}, false // the wait elapsed: lost
		}
		if !echo.Reply || echo.Identifier != cfg.Conn.LocalPort() || echo.Seq != seq {
			continue
		}
		stat := ReplyStat{Seq: seq, RTT: time.Since(sent), Hops: 1, Segments: 1}
		if from.Path != nil {
			stat.Hops = len(from.Path.HopFields)
			stat.Segments = len(from.Path.InfoFields)
		}
		return stat, true
	}
}
