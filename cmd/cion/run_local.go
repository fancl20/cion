package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// addLocalNodeFlags registers the joining node's arguments: the network's
// core domain, the bootstrap neighbor, and the reachability class the node
// advertises. The local role is the configuration's zero value.
func addLocalNodeFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	flags.StringVar(&opts.Domain, "domain", "",
		"the network's core domain, the WebPKI identity of the enrollment and TRC fetch "+
			"(required)")
	flags.StringSliceVar(&opts.Neighbors, "neighbor", nil,
		"an existing node's rendezvous underlay address; repeatable")
	flags.BoolVar(&opts.BehindNAT, "behind-nat", false,
		"publish the node's reachability class as private: joinable by no one")
}

// newRunLocalCommand builds `cion run local`: a node joining an existing
// network through its core.
func newRunLocalCommand() *cobra.Command {
	opts := &services.NodeConfig{}
	tuning := &runOptions{}
	cmd := &cobra.Command{
		Use:   "local",
		Short: "Run a local node, joining an existing network through its core",
		Long: "Run a local node, joining an existing network through its core: enrollment " +
			"and the measured join. Identity and links come from the state directory; " +
			"a first start needs a bootstrap --neighbor — or a --link-set file under " +
			"the static provider — and the network's core --domain.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd.Context(), *opts, tuning)
		},
	}
	addSharedNodeFlags(cmd.Flags(), opts)
	addLocalNodeFlags(cmd.Flags(), opts)
	addTuningFlags(cmd.Flags(), tuning)
	return cmd
}
