package main

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// parseRunArgs parses the node's run arguments the way the run command
// registers them, reporting the options they built.
func parseRunArgs(t *testing.T, args ...string) (*services.NodeConfig, error) {
	t.Helper()
	opts := &services.NodeConfig{}
	flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
	addNodeFlags(flags, opts)
	err := flags.Parse(args)
	return opts, err
}

// TestRunArgumentsParse checks the run arguments' own surface (proposal
// 0024): --slice and --host-port parse into the node configuration, and
// --wireguard-config — retired with the file it named — is refused as an
// unknown flag, the parse performing the retirement's bookkeeping.
func TestRunArgumentsParse(t *testing.T) {
	opts, err := parseRunArgs(t,
		"--slice", "100.64.1.0/24",
		"--host-port", "51820",
	)
	if err != nil {
		t.Fatalf("parsing the slice and port: %v", err)
	}
	if opts.Slice != "100.64.1.0/24" {
		t.Errorf("--slice = %q", opts.Slice)
	}
	if opts.HostPort != 51820 {
		t.Errorf("--host-port = %d", opts.HostPort)
	}

	if _, err := parseRunArgs(t,
		"--wireguard-config", "/tmp/wireguard.json",
	); err == nil {
		t.Fatal("--wireguard-config parsed, want the unknown-flag refusal")
	} else if !strings.Contains(err.Error(), "wireguard-config") {
		t.Errorf("the refusal = %v, want it to name the retired flag", err)
	}
}

// TestRunArgumentsValidate checks the arguments' validation through the
// node configuration they build: a slice the tailnet range contains and a
// usable port, the grammar the retired file's loader checked.
func TestRunArgumentsValidate(t *testing.T) {
	base := services.NodeConfig{
		Core:     true,
		Domain:   "core.example.org",
		State:    "/var/lib/cion",
		Internal: "127.0.0.1:30042",
		Control:  "127.0.0.1:30044",
	}
	valid := base
	valid.Slice = "100.64.1.0/24"
	valid.HostPort = 51820
	if err := valid.Validate(); err != nil {
		t.Fatalf("the valid slice and port: %v", err)
	}
}
