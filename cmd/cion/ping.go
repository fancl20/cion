package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/spf13/cobra"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps/ping"
)

// pingOptions carries the ping command's request tuning flags.
type pingOptions struct {
	count    int
	interval time.Duration
	wait     time.Duration
	ready    time.Duration
}

// newPingCommand builds `cion ping`: the SCION echo application, printing
// one line per reply and a loss summary. It assembles a local node from the
// state directory and the same node arguments as `cion run local`, not from
// a file.
func newPingCommand() *cobra.Command {
	opts := &services.NodeConfig{}
	pingOpts := &pingOptions{}
	cmd := &cobra.Command{
		Use:   "ping isd-as,host",
		Short: "Ping a destination ISD-AS over the node's own data and control plane",
		Long: "Ping a destination ISD-AS over the node's own assembled data and control plane: " +
			"boots a local node in place of serving from the state directory and the " +
			"same node arguments as 'cion run local', prints one line per reply plus a " +
			"loss summary, and exits. It refuses a state directory a running node holds.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPing(cmd.Context(), *opts, args[0], pingOpts)
		},
	}
	cmd.Flags().SortFlags = false
	addSharedNodeFlags(cmd.Flags(), opts)
	addLocalNodeFlags(cmd.Flags(), opts)
	addApplicationFlags(cmd.Flags(), opts)
	cmd.Flags().IntVar(&pingOpts.count, "count", 4, "number of requests")
	cmd.Flags().DurationVar(&pingOpts.interval, "interval", time.Second, "time between requests")
	cmd.Flags().DurationVar(&pingOpts.wait, "wait", 2*time.Second, "wait per reply")
	cmd.Flags().DurationVar(&pingOpts.ready, "ready", 15*time.Second,
		"wait for a path and a first reply before counting; 0 counts at once")
	return cmd
}

// runPing boots the full node in place of serving: the pinger's packets cross
// the data plane and its paths come from the node's own beaconing, so the node
// serves underneath the run. The run waits, within --ready, for the first
// resolution and the first reply before it counts — a freshly booted node's
// beaconing and a peer's BFD handshake land seconds in. A ping that succeeds
// returns how the node stopped.
func runPing(ctx context.Context, cfg services.NodeConfig, target string, opts *pingOptions) (err error) {
	dst, host, err := parsePingTarget(target)
	if err != nil {
		return err
	}
	app, err := services.BootApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := app.Close(); err == nil {
			err = cerr
		}
	}()
	conn, err := app.Conn(0)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	fmt.Printf("cion ping %s,%s\n", dst, host)
	report, err := ping.Run(ctx, ping.Config{
		Conn:     conn,
		Paths:    app.Provider(),
		Dst:      dst,
		DstHost:  host,
		Count:    opts.count,
		Interval: opts.interval,
		Wait:     opts.wait,
		Ready:    opts.ready,
		Log:      func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
	})
	if err != nil {
		return err
	}
	if report.Loss() > 0 {
		return fmt.Errorf("%d of %d requests lost", report.Loss(), report.Sent)
	}
	return nil
}

// parsePingTarget splits a "20-ff00:0:2,192.0.2.10" destination into the
// ISD-AS and the underlay host the destination's responder is bound to.
func parsePingTarget(s string) (dst addr.IA, host netip.Addr, err error) {
	iaStr, hostStr, ok := strings.Cut(s, ",")
	if !ok {
		return dst, host, fmt.Errorf("destination %q must be isd-as,host", s)
	}
	dst, err = addr.ParseIA(iaStr)
	if err != nil {
		return dst, host, fmt.Errorf("parsing ISD-AS: %w", err)
	}
	host, err = netip.ParseAddr(hostStr)
	if err != nil {
		return dst, host, fmt.Errorf("parsing host address: %w", err)
	}
	return dst, host, nil
}
