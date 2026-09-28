package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// addSharedNodeFlags registers the node arguments every assembling command
// takes — the arguments the retiring configuration file carried, with
// defaults so a restart needs none of them.
func addSharedNodeFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	flags.StringVar(&opts.LinkSet, "link-set", "",
		"path to a JSON link-set file naming the static topology: "+
			"neighbor ISD-ASes with each link's two underlay addresses")
	flags.StringVar(&opts.State, "state", services.DefaultState,
		"the state directory, where the first start generates the identity")
	flags.StringVar(&opts.Internal, "internal", services.DefaultInternal,
		"the UDP address the router listens on for hosts in the local AS")
	flags.StringVar(&opts.Control, "control", services.DefaultControl,
		"the UDP address of the control service; its host carries the control, "+
			"rendezvous, and directory sockets")
	flags.Uint16Var(&opts.HostPort, "host-port", services.DefaultHostPort,
		"the shared host-facing UDP port every host dials; the directory assigns "+
			"the node's slice of the tailnet range at its first publication "+
			"(zero runs no WireGuard or SOCKS application)")
}

// runOptions carries the run commands' data-plane tuning flags.
type runOptions struct {
	processors int
	batchSize  int
	queueSize  int
}

// addTuningFlags registers the data-plane tuning flags the run commands
// carry, from the dataplane defaults.
func addTuningFlags(flags *pflag.FlagSet, tuning *runOptions) {
	defaults := services.DefaultDataplaneOptions()
	flags.IntVar(&tuning.processors, "processors", defaults.Processors,
		"number of fast-path packet processors")
	flags.IntVar(&tuning.batchSize, "batch-size", defaults.BatchSize,
		"receive batch size per underlay socket")
	flags.IntVar(&tuning.queueSize, "queue-size", defaults.QueueSize,
		"queue depth of the internal and external links")
}

// runDaemon is the body both run commands share: the tuning sanity checks
// and the services.Run call over the node configuration the command
// assembled, so the two differ in their arguments and nothing else.
func runDaemon(ctx context.Context, cfg services.NodeConfig, tuning *runOptions) error {
	// A zero processor count or batch size would panic deep inside
	// Serve, which divides by them; fail at the flag instead.
	for _, check := range []struct {
		name  string
		value int
	}{
		{"processors", tuning.processors},
		{"batch-size", tuning.batchSize},
		{"queue-size", tuning.queueSize},
	} {
		if check.value < 1 {
			return fmt.Errorf("--%s must be at least 1", check.name)
		}
	}
	return services.Run(ctx, cfg, services.DataplaneOptions{
		Processors: tuning.processors,
		BatchSize:  tuning.batchSize,
		QueueSize:  tuning.queueSize,
	})
}

// newRunCommand builds `cion run`: the daemon's two roles as subcommands.
// The parent has no run function, so a bare invocation prints the roles the
// way a bare `cion` prints the commands.
func newRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the CION daemon",
		Long: "Run the CION daemon: data plane, control plane, the loaded topology provider, " +
			"and enabled applications in one process. Identity and links come from the " +
			"state directory.\n\nRun 'cion run core' to found a network; 'cion run local' " +
			"to join one.",
	}
	cmd.AddCommand(newRunCoreCommand(), newRunLocalCommand())
	return cmd
}
