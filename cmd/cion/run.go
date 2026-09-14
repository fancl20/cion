package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fancl20/cion/internal/services"
)

// runOptions carries the run command's data-plane tuning flags.
type runOptions struct {
	processors int
	batchSize  int
	queueSize  int
}

// newRunCommand builds `cion run`: the daemon of proposals 0003-0005 —
// data plane, control plane, and the resident applications in one process —
// with the data-plane tuning flags.
func newRunCommand() *cobra.Command {
	opts := &runOptions{}
	defaults := services.DefaultDataplaneOptions()
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the CION daemon",
		Long: "Run the CION daemon: data plane, control plane, and enabled applications in one " +
			"process (proposals 0003-0005).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := services.LoadConfig(configPath)
			if err != nil {
				return err
			}
			// A zero processor count or batch size would panic deep inside
			// Serve, which divides by them; fail at the flag instead.
			for _, check := range []struct {
				name  string
				value int
			}{
				{"processors", opts.processors},
				{"batch-size", opts.batchSize},
				{"queue-size", opts.queueSize},
			} {
				if check.value < 1 {
					return fmt.Errorf("--%s must be at least 1", check.name)
				}
			}
			return services.Run(cmd.Context(), cfg, services.DataplaneOptions{
				Processors: opts.processors,
				BatchSize:  opts.batchSize,
				QueueSize:  opts.queueSize,
			})
		},
	}
	cmd.Flags().IntVar(&opts.processors, "processors", defaults.Processors,
		"number of fast-path packet processors")
	cmd.Flags().IntVar(&opts.batchSize, "batch-size", defaults.BatchSize,
		"receive batch size per underlay socket")
	cmd.Flags().IntVar(&opts.queueSize, "queue-size", defaults.QueueSize,
		"queue depth of the internal and external links")
	return cmd
}
