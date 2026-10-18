package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps"
)

// addSharedNodeFlags registers the node arguments every assembling command
// takes: the bare three that place the daemon, the static topology
// provider's selection, and the composition's list — the arguments the
// retiring configuration file carried, with defaults so a restart needs
// none of them. The link-set and the list override working defaults — the
// measured provider, the inference — so they hide from the help while
// staying settable.
func addSharedNodeFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	flags.StringVar(&opts.State, "state", services.DefaultState,
		"the state directory, where the first start generates the identity")
	flags.StringVar(&opts.Internal, "internal", services.DefaultInternal,
		"the UDP address the router listens on for hosts in the local AS; "+
			"a bare host names the default port")
	flags.StringVar(&opts.Control, "control", services.DefaultControl,
		"the UDP address of the control service; its host carries the control, "+
			"rendezvous, and directory sockets at the ports the underlay block "+
			"fixes, so a bare host names the host alone — the default wildcard "+
			"binding every interface of its family")
	flags.StringVar(&opts.LinkSet, "topology.link-set", "",
		"path to a JSON link-set file naming the static topology: "+
			"neighbor ISD-ASes with each link's two underlay addresses")
	_ = flags.MarkHidden("topology.link-set")
	flags.StringSliceVar(&opts.Applications, "applications", nil,
		"the resident applications the node runs, comma-separated and "+
			"repeatable: unset loads what the arguments imply, the empty value "+
			"loads none — the deliberate core — and a list loads exactly the "+
			"named ("+applicationNames()+")")
	_ = flags.MarkHidden("applications")
}

// applicationNames lists the resident applications' names in table order,
// comma-separated.
func applicationNames() string {
	names := make([]string, 0, len(apps.Table))
	for _, entry := range apps.Table {
		names = append(names, entry.Name)
	}
	return strings.Join(names, ", ")
}

// addApplicationFlags registers the resident applications' own run
// arguments by walking the table: each entry's block in table order,
// after the composition's list.
func addApplicationFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	apps.RegisterFlags(flags, &opts.AppArguments)
}

// addTuningFlags registers the data-plane tuning flags the run commands
// carry, from the dataplane defaults. The defaults carry the production
// values, so the trio hides from the help while staying settable.
func addTuningFlags(flags *pflag.FlagSet, tuning *services.DataplaneOptions) {
	defaults := services.DefaultDataplaneOptions()
	flags.IntVar(&tuning.Processors, "dataplane.processors", defaults.Processors,
		"number of fast-path packet processors")
	_ = flags.MarkHidden("dataplane.processors")
	flags.IntVar(&tuning.BatchSize, "dataplane.batch-size", defaults.BatchSize,
		"receive batch size per underlay socket")
	_ = flags.MarkHidden("dataplane.batch-size")
	flags.IntVar(&tuning.QueueSize, "dataplane.queue-size", defaults.QueueSize,
		"queue depth of the internal and external links")
	_ = flags.MarkHidden("dataplane.queue-size")
}

// runDaemon is the body both run commands share: the sanity checks over
// the assembled arguments and the services.Run call over them, so the two
// differ in their arguments and nothing else.
func runDaemon(ctx context.Context, cfg services.NodeConfig, tuning services.DataplaneOptions) error {
	// A zero processor count or batch size would panic deep inside
	// Serve, which divides by them; fail at the flag instead.
	for _, check := range []struct {
		name  string
		value int
	}{
		{"dataplane.processors", tuning.Processors},
		{"dataplane.batch-size", tuning.BatchSize},
		{"dataplane.queue-size", tuning.QueueSize},
	} {
		if check.value < 1 {
			return fmt.Errorf("--%s must be at least 1", check.name)
		}
	}
	// The founding core — the core flag without a neighbor — must name an
	// enrollment policy: unset, the gate would run enrollment and
	// registration open. A joining core carries no gate, for only the
	// founding core issues chains.
	if cfg.Core && len(cfg.Neighbors) == 0 && cfg.EnrollAuth == "" {
		return fmt.Errorf("--trust.enroll-auth is required on the founding core: " +
			"cidrs=<comma-separated prefix list> or telegram=<chat>:<token>")
	}
	return services.Run(ctx, cfg, tuning)
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
