// Command cion runs a CION node: a SCION router with a collapsed data plane
// for a one-node AS. The command tree lives here; the node assembly it
// drives lives in internal/services.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// configPath is the node configuration file given with the persistent
// --config flag; every command that assembles a node requires it.
var configPath string

// newRootCommand builds the cion command tree: the run daemon and the ping
// application. The root itself has no run function, so a bare invocation
// prints the usage instead of starting a node by accident.
func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "cion",
		Short: "Run a CION node: a SCION router with a collapsed data plane for a one-node AS",
		Long: "CION runs a one-node SCION AS: data plane, control plane, and applications " +
			"in one process.\n\nRun 'cion run' to start the daemon; 'cion ping' to probe a " +
			"destination over the node's own assembly.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().StringVar(&configPath, "config", "",
		"path to the JSON configuration file (required)")
	root.AddCommand(newRunCommand(), newPingCommand())
	return root
}

// main runs the cion command line. It prints failures the way the flag-era
// binary did — one slog error, exit code 1 — so logs and scripts survive
// the refactor; usage lives in --help, not in error output. The signal
// context turns an interrupt into the services' shutdown path.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		slog.Error("CION terminated", "err", err)
		os.Exit(1)
	}
}
