package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// addCoreNodeFlags registers the core role's arguments — its own domain
// when it founds, the network's when it joins, and the issuance surface
// beside them — presetting the role in the configuration they build.
func addCoreNodeFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	opts.Core = true
	flags.StringSliceVar(&opts.Neighbors, "topology.neighbor", nil,
		"an existing node's rendezvous underlay address; set, the core joins the "+
			"neighbor's ISD as an authoritative core instead of founding its own")
	flags.StringVar(&opts.Domain, "trust.domain", "",
		"the founding core's own domain without a neighbor, else the network's core "+
			"domain — the WebPKI identity of the enrollment and TRC fetch (required)")
	flags.StringVar(&opts.AcmeEmail, "trust.acme-email", "",
		"the ACME account email for the founding core's certificate (optional)")
	flags.StringVar(&opts.CertFile, "trust.cert-file", "",
		"the founding core's TLS certificate file, the offline fallback to ACME")
	flags.StringVar(&opts.KeyFile, "trust.key-file", "",
		"the founding core's TLS key file, the offline fallback to ACME")
	flags.StringVar(&opts.EnrollAuth, "trust.enroll-auth", "",
		"gate first issuance with a policy: "+
			"cidrs=<comma-separated prefix list> admits by source address, "+
			"telegram=<chat>:<token> prompts the chat per joiner; open when unset")
}

// newRunCoreCommand builds `cion run core`: the founding core without a
// neighbor — TRC genesis, the issuer every node's chain descends from, and
// self-enrollment, serving its own domain — and, with a neighbor, the
// authoritative core joining it.
func newRunCoreCommand() *cobra.Command {
	opts := &services.NodeConfig{}
	tuning := &runOptions{}
	cmd := &cobra.Command{
		Use:   "core",
		Short: "Run a core: founding without a neighbor, joining as an authoritative core with one",
		Long: "Run a core: without a --topology.neighbor, the founding core — TRC genesis, " +
			"the issuer every node's chain descends from, and self-enrollment, serving " +
			"its own domain; with one, an authoritative core joining the neighbor's ISD — " +
			"enrolling like any node until the founder's sensitive update onboards it. " +
			"Identity and links come from the state directory; a first start needs the " +
			"core's --trust.domain and, to join, a bootstrap neighbor.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd.Context(), *opts, tuning)
		},
	}
	cmd.Flags().SortFlags = false
	addSharedNodeFlags(cmd.Flags(), opts)
	addCoreNodeFlags(cmd.Flags(), opts)
	addApplicationFlags(cmd.Flags(), opts)
	addTuningFlags(cmd.Flags(), tuning)
	return cmd
}
