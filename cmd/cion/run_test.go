package main

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/fancl20/cion/internal/services"
)

// parseNodeArgs parses one run command's arguments the way the command
// registers them, reporting the node configuration they build.
func parseNodeArgs(t *testing.T, use string, args ...string) (*services.NodeConfig, error) {
	t.Helper()
	opts := &services.NodeConfig{}
	tuning := &runOptions{}
	flags := pflag.NewFlagSet(use, pflag.ContinueOnError)
	addSharedNodeFlags(flags, opts)
	if use == "core" {
		addCoreNodeFlags(flags, opts)
	} else {
		addLocalNodeFlags(flags, opts)
	}
	addTuningFlags(flags, tuning)
	err := flags.Parse(args)
	return opts, err
}

// TestRunArgumentsParse checks the run commands' surfaces: the shared
// arguments parse on both, the role's arguments on theirs, the role arrives
// preset in the configuration the core's registration builds, and the
// commands themselves register the partitions.
func TestRunArgumentsParse(t *testing.T) {
	opts, err := parseNodeArgs(t, "core",
		"--domain", "core.example.org",
		"--acme-email", "admin@example.org",
		"--cert-file", "/tmp/cert.pem",
		"--key-file", "/tmp/key.pem",
		"--enroll-auth", "cidrs=192.0.2.0/24",
		"--slice", "100.64.1.0/24",
		"--host-port", "51820",
		"--processors", "2",
	)
	if err != nil {
		t.Fatalf("parsing the core's arguments: %v", err)
	}
	if !opts.Core {
		t.Error("the core's registration left the role unset")
	}
	if opts.Domain != "core.example.org" {
		t.Errorf("--domain = %q", opts.Domain)
	}
	if opts.AcmeEmail != "admin@example.org" {
		t.Errorf("--acme-email = %q", opts.AcmeEmail)
	}
	if opts.CertFile != "/tmp/cert.pem" || opts.KeyFile != "/tmp/key.pem" {
		t.Errorf("the certificate pair = %q, %q", opts.CertFile, opts.KeyFile)
	}
	if opts.EnrollAuth != "cidrs=192.0.2.0/24" {
		t.Errorf("--enroll-auth = %q", opts.EnrollAuth)
	}
	if opts.Slice != "100.64.1.0/24" {
		t.Errorf("--slice = %q", opts.Slice)
	}
	if opts.HostPort != 51820 {
		t.Errorf("--host-port = %d", opts.HostPort)
	}
	if opts.State != services.DefaultState {
		t.Errorf("--state = %q, want the default %q", opts.State, services.DefaultState)
	}

	opts, err = parseNodeArgs(t, "local",
		"--domain", "core.example.org",
		"--neighbor", "192.0.2.7:30045",
		"--state", "/var/lib/cion2",
	)
	if err != nil {
		t.Fatalf("parsing the local command's arguments: %v", err)
	}
	if opts.Core {
		t.Error("the local registration preset the core role")
	}
	if opts.Domain != "core.example.org" {
		t.Errorf("--domain = %q", opts.Domain)
	}
	if len(opts.Neighbors) != 1 || opts.Neighbors[0] != "192.0.2.7:30045" {
		t.Errorf("--neighbor = %v", opts.Neighbors)
	}
	if opts.State != "/var/lib/cion2" {
		t.Errorf("--state = %q", opts.State)
	}

	// The commands themselves carry their role's partition.
	if err := newRunCoreCommand().Flags().Parse([]string{
		"--domain", "core.example.org",
		"--enroll-auth", "cidrs=192.0.2.0/24",
	}); err != nil {
		t.Errorf("parsing run core's own surface: %v", err)
	}
	if err := newRunLocalCommand().Flags().Parse([]string{
		"--domain", "core.example.org",
		"--neighbor", "192.0.2.7:30045",
	}); err != nil {
		t.Errorf("parsing run local's own surface: %v", err)
	}
}

// refuse asserts the flag set rejects the flag as an unknown flag naming it.
func refuse(t *testing.T, command, flag string, flags *pflag.FlagSet) {
	t.Helper()
	err := flags.Parse([]string{flag, "x"})
	if err == nil {
		t.Errorf("%s parsed %s, want the unknown-flag refusal", command, flag)
		return
	}
	if name := strings.TrimPrefix(flag, "--"); !strings.Contains(err.Error(), name) {
		t.Errorf("%s's refusal of %s = %v, want it to name the flag", command, flag, err)
	}
}

// TestRunCommandsRefuseForeignArguments checks the partition's bookkeeping
// the parse performs: each command refuses the other role's arguments as
// unknown flags naming the argument, and the retired --core,
// --wireguard-config, and --behind-nat are refused everywhere.
func TestRunCommandsRefuseForeignArguments(t *testing.T) {
	for _, command := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"run core", newRunCoreCommand()},
		{"run local", newRunLocalCommand()},
		{"ping", newPingCommand()},
	} {
		for _, flag := range []string{"--core", "--wireguard-config", "--behind-nat"} {
			refuse(t, command.name, flag, command.cmd.Flags())
		}
	}
	for _, flag := range []string{"--neighbor"} {
		refuse(t, "run core", flag, newRunCoreCommand().Flags())
	}
	for _, flag := range []string{"--acme-email", "--cert-file", "--key-file", "--enroll-auth"} {
		refuse(t, "run local", flag, newRunLocalCommand().Flags())
	}
}

// TestRunCommandsPresetRole checks the role each command presets in the
// node configuration it assembles: run bare of a domain, each fails on its
// role's missing-domain meaning — the core's own on the core, the network's
// core domain on the local node.
func TestRunCommandsPresetRole(t *testing.T) {
	for _, tc := range []struct {
		cmd  *cobra.Command
		want string
	}{
		{newRunCoreCommand(), "the core's own"},
		{newRunLocalCommand(), "the network's core domain"},
	} {
		tc.cmd.SilenceUsage = true
		tc.cmd.SilenceErrors = true
		tc.cmd.SetArgs([]string{})
		err := tc.cmd.ExecuteContext(context.Background())
		if err == nil {
			t.Errorf("bare %s ran, want the missing-domain refusal", tc.cmd.Name())
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s's missing-domain error = %q, want the meaning %q",
				tc.cmd.Name(), err, tc.want)
		}
	}
}

// TestRunArgumentsValidate checks the arguments' validation through the
// node configuration they build: a slice the tailnet range contains and a
// usable port.
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
