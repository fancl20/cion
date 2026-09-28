package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// addCoreNodeFlags registers the founding core's arguments — its own domain
// and the issuance surface beside it — presetting the role in the
// configuration they build.
func addCoreNodeFlags(flags *pflag.FlagSet, opts *services.NodeConfig) {
	opts.Core = true
	flags.StringVar(&opts.Domain, "trust.domain", "",
		"the core's own domain, the WebPKI identity of its certificate (required)")
	flags.StringVar(&opts.AcmeEmail, "trust.acme-email", "",
		"the ACME account email for the core's certificate (optional)")
	flags.StringVar(&opts.CertFile, "trust.cert-file", "",
		"the core's TLS certificate file, the offline fallback to ACME")
	flags.StringVar(&opts.KeyFile, "trust.key-file", "",
		"the core's TLS key file, the offline fallback to ACME")
	flags.StringVar(&opts.EnrollAuth, "trust.enroll-auth", "",
		"gate first issuance with a policy: "+
			"cidrs=<comma-separated prefix list> admits by source address, "+
			"telegram=<chat>:<token> prompts the chat per joiner; open when unset")
}

// newRunCoreCommand builds `cion run core`: the founding core — TRC
// genesis, the issuer every node's chain descends from, and
// self-enrollment, serving its own domain.
func newRunCoreCommand() *cobra.Command {
	opts := &services.NodeConfig{}
	tuning := &runOptions{}
	cmd := &cobra.Command{
		Use:   "core",
		Short: "Run the founding core: TRC genesis, issuer, self-enrollment",
		Long: "Run the founding core: TRC genesis, the issuer every node's chain descends " +
			"from, and self-enrollment, serving its own domain. Identity and links come " +
			"from the state directory; the first start needs the core's --trust.domain.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd.Context(), *opts, tuning)
		},
	}
	cmd.Flags().SortFlags = false
	addSharedNodeFlags(cmd.Flags(), opts)
	addCoreNodeFlags(cmd.Flags(), opts)
	addWireguardFlags(cmd.Flags(), opts)
	addTuningFlags(cmd.Flags(), tuning)
	return cmd
}
