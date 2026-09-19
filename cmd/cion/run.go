package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// addNodeFlags registers the node's run arguments on a command that assembles
// one — the arguments the retiring configuration file carried, with defaults
// so a restart needs none of them (ADR-0008).
func addNodeFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	flags.BoolVar(&opts.Core, "core", false,
		"mark the founding core: TRC genesis, issuer, self-enrollment (takes no --neighbor)")
	flags.StringVar(&opts.Domain, "domain", "",
		"the core's domain: the core's own with --core, the network's core domain otherwise "+
			"(required)")
	flags.StringVar(&opts.AcmeEmail, "acme-email", "",
		"the ACME account email for the core's certificate (core only, optional)")
	flags.StringVar(&opts.CertFile, "cert-file", "",
		"the core's TLS certificate file, the offline fallback to ACME (core only)")
	flags.StringVar(&opts.KeyFile, "key-file", "",
		"the core's TLS key file, the offline fallback to ACME (core only)")
	flags.StringSliceVar(&opts.Neighbors, "neighbor", nil,
		"an existing node's rendezvous underlay address; repeatable")
	flags.StringVar(&opts.LinkSet, "link-set", "",
		"path to a JSON link-set file naming the static topology (refuses --neighbor): "+
			"neighbor ISD-ASes with each link's two underlay addresses")
	flags.StringVar(&opts.State, "state", services.DefaultState,
		"the state directory, where the first start generates the identity")
	flags.StringVar(&opts.Internal, "internal", services.DefaultInternal,
		"the UDP address the router listens on for hosts in the local AS")
	flags.StringVar(&opts.Control, "control", services.DefaultControl,
		"the UDP address of the control service; its host carries the control, "+
			"rendezvous, and directory sockets")
	flags.StringSliceVar(&opts.AllowIA, "allow-ia", nil,
		"restrict the loaded provider's link admission to the listed ISD-ASes; "+
			"open when unset")
	flags.BoolVar(&opts.BehindNAT, "behind-nat", false,
		"publish the node's reachability class as private: joinable by no one")
	flags.StringVar(&opts.WireguardConfig, "wireguard-config", "",
		"path to the WireGuard application's own JSON configuration file")
}

// runOptions carries the run command's data-plane tuning flags.
type runOptions struct {
	processors int
	batchSize  int
	queueSize  int
}

// newRunCommand builds `cion run`: the daemon of proposals 0003-0011 — data
// plane, control plane, the loaded topology provider, and the resident
// applications in one process — from the run arguments and the state
// directory.
func newRunCommand() *cobra.Command {
	opts := &services.NodeConfig{}
	tuning := &runOptions{}
	defaults := services.DefaultDataplaneOptions()
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the CION daemon",
		Long: "Run the CION daemon: data plane, control plane, the loaded topology provider, " +
			"and enabled applications in one process (proposals 0003-0011). Identity and links " +
			"come from the state directory; a non-core's first start needs a bootstrap " +
			"--neighbor — or a --link-set file under the static provider — and the core's " +
			"--domain.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			return services.Run(cmd.Context(), *opts, services.DataplaneOptions{
				Processors: tuning.processors,
				BatchSize:  tuning.batchSize,
				QueueSize:  tuning.queueSize,
			})
		},
	}
	addNodeFlags(cmd.Flags(), opts)
	cmd.Flags().IntVar(&tuning.processors, "processors", defaults.Processors,
		"number of fast-path packet processors")
	cmd.Flags().IntVar(&tuning.batchSize, "batch-size", defaults.BatchSize,
		"receive batch size per underlay socket")
	cmd.Flags().IntVar(&tuning.queueSize, "queue-size", defaults.QueueSize,
		"queue depth of the internal and external links")
	return cmd
}
