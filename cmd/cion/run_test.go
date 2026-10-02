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
	addApplicationFlags(flags, opts)
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
		"--trust.domain", "core.example.org",
		"--trust.acme-email", "admin@example.org",
		"--trust.cert-file", "/tmp/cert.pem",
		"--trust.key-file", "/tmp/key.pem",
		"--trust.enroll-auth", "cidrs=192.0.2.0/24",
		"--wireguard.host-port", "51820",
		"--dataplane.processors", "2",
	)
	if err != nil {
		t.Fatalf("parsing the core's arguments: %v", err)
	}
	if !opts.Core {
		t.Error("the core's registration left the role unset")
	}
	if opts.Domain != "core.example.org" {
		t.Errorf("--trust.domain = %q", opts.Domain)
	}
	if opts.AcmeEmail != "admin@example.org" {
		t.Errorf("--trust.acme-email = %q", opts.AcmeEmail)
	}
	if opts.CertFile != "/tmp/cert.pem" || opts.KeyFile != "/tmp/key.pem" {
		t.Errorf("the certificate pair = %q, %q", opts.CertFile, opts.KeyFile)
	}
	if opts.EnrollAuth != "cidrs=192.0.2.0/24" {
		t.Errorf("--trust.enroll-auth = %q", opts.EnrollAuth)
	}
	if opts.AppArguments.Wireguard.HostPort != 51820 {
		t.Errorf("--wireguard.host-port = %d",
			opts.AppArguments.Wireguard.HostPort)
	}
	if opts.State != services.DefaultState {
		t.Errorf("--state = %q, want the default %q", opts.State, services.DefaultState)
	}
	if len(opts.Neighbors) != 0 {
		t.Errorf("the core's --topology.neighbor = %v, want none passed", opts.Neighbors)
	}

	opts, err = parseNodeArgs(t, "local",
		"--trust.domain", "core.example.org",
		"--topology.neighbor", "192.0.2.7:30043",
		"--state", "/var/lib/cion2",
	)
	if err != nil {
		t.Fatalf("parsing the local command's arguments: %v", err)
	}
	if opts.Core {
		t.Error("the local registration preset the core role")
	}
	if opts.Domain != "core.example.org" {
		t.Errorf("--trust.domain = %q", opts.Domain)
	}
	if len(opts.Neighbors) != 1 || opts.Neighbors[0] != "192.0.2.7:30043" {
		t.Errorf("--topology.neighbor = %v", opts.Neighbors)
	}
	if opts.State != "/var/lib/cion2" {
		t.Errorf("--state = %q", opts.State)
	}
	// The unpassed arguments hold their defaults: the host port's 51820, the
	// addresses the swapped block's.
	if opts.AppArguments.Wireguard.HostPort != 51820 {
		t.Errorf("the host port's default = %d, want 51820",
			opts.AppArguments.Wireguard.HostPort)
	}
	if opts.Internal != services.DefaultInternal || opts.Control != services.DefaultControl {
		t.Errorf("the address defaults = %q, %q", opts.Internal, opts.Control)
	}

	// The commands themselves carry their role's partition.
	if err := newRunCoreCommand().Flags().Parse([]string{
		"--trust.domain", "core.example.org",
		"--trust.enroll-auth", "cidrs=192.0.2.0/24",
	}); err != nil {
		t.Errorf("parsing run core's own surface: %v", err)
	}
	if err := newRunLocalCommand().Flags().Parse([]string{
		"--trust.domain", "core.example.org",
		"--topology.neighbor", "192.0.2.7:30043",
	}); err != nil {
		t.Errorf("parsing run local's own surface: %v", err)
	}
}

// TestRunCommandsHelpReadsInParts checks the surface each command's help
// reads: the placement flags print first, then each part's block, in the
// registration order the commands compose.
func TestRunCommandsHelpReadsInParts(t *testing.T) {
	for _, command := range []struct {
		name string
		cmd  *cobra.Command
		want []string
	}{
		{"run core", newRunCoreCommand(), []string{
			"--state", "--internal", "--control",
			"--topology.link-set",
			"--applications",
			"--topology.neighbor",
			"--trust.domain", "--trust.acme-email", "--trust.cert-file",
			"--trust.key-file", "--trust.enroll-auth",
			"--wireguard.host-port",
			"--dataplane.processors", "--dataplane.batch-size",
			"--dataplane.queue-size",
		}},
		{"run local", newRunLocalCommand(), []string{
			"--state", "--internal", "--control",
			"--topology.link-set",
			"--applications",
			"--topology.neighbor",
			"--trust.domain",
			"--wireguard.host-port",
			"--dataplane.processors", "--dataplane.batch-size",
			"--dataplane.queue-size",
		}},
		{"ping", newPingCommand(), []string{
			"--state", "--internal", "--control",
			"--topology.link-set",
			"--applications",
			"--topology.neighbor",
			"--trust.domain",
			"--wireguard.host-port",
		}},
	} {
		rest := command.cmd.Flags().FlagUsages()
		for _, flag := range command.want {
			i := strings.Index(rest, flag)
			if i < 0 {
				t.Errorf("%s's help omits %s", command.name, flag)
				break
			}
			rest = rest[i:]
		}
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
// unknown flags naming the argument, the unprefixed spelling of every
// renamed argument beside the retired --core, --wireguard-config,
// --behind-nat, and --slice.
func TestRunCommandsRefuseForeignArguments(t *testing.T) {
	for _, command := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"run core", newRunCoreCommand()},
		{"run local", newRunLocalCommand()},
		{"ping", newPingCommand()},
	} {
		for _, flag := range []string{
			"--core", "--wireguard-config", "--behind-nat", "--slice",
			"--link-set", "--neighbor", "--domain", "--acme-email",
			"--cert-file", "--key-file", "--enroll-auth", "--host-port",
			"--processors", "--batch-size", "--queue-size",
		} {
			refuse(t, command.name, flag, command.cmd.Flags())
		}
	}
	for _, flag := range []string{
		"--trust.acme-email", "--trust.cert-file",
		"--trust.key-file", "--trust.enroll-auth",
	} {
		refuse(t, "run local", flag, newRunLocalCommand().Flags())
	}
}

// TestRunCommandsPresetRole checks the role each command presets in the
// node configuration it assembles: run bare of a domain, each fails on its
// role's missing-domain refusal — the core's own on the core, the network's
// core domain on the local node.
func TestRunCommandsPresetRole(t *testing.T) {
	for _, tc := range []struct {
		cmd  *cobra.Command
		want string
	}{
		{newRunCoreCommand(), "--trust.domain is required: the founding core's own"},
		{newRunLocalCommand(), "--trust.domain is required: the network's core domain"},
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
			t.Errorf("%s's missing-domain error = %q, want the refusal %q",
				tc.cmd.Name(), err, tc.want)
		}
	}
}

// TestRunCommandsRefuseTheProviderMixture checks the exclusivity the
// namespace carries: one topology provider per process, the refusal naming
// both namespaced forms.
func TestRunCommandsRefuseTheProviderMixture(t *testing.T) {
	cmd := newRunLocalCommand()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{
		"--trust.domain", "core.example.org",
		"--topology.link-set", "/tmp/link-set.json",
		"--topology.neighbor", "192.0.2.7:30043",
	})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(),
		"--topology.link-set refuses --topology.neighbor") {
		t.Errorf("the provider mixture's refusal = %v, want both namespaced forms", err)
	}
}

// TestRunTuningChecksNameTheSurface checks the tuning sanity checks' error
// texts: each names the namespaced spelling it refuses, before any assembly
// runs.
func TestRunTuningChecksNameTheSurface(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{"--dataplane.processors=0", "--dataplane.processors must be at least 1"},
		{"--dataplane.batch-size=0", "--dataplane.batch-size must be at least 1"},
		{"--dataplane.queue-size=0", "--dataplane.queue-size must be at least 1"},
	} {
		cmd := newRunLocalCommand()
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs([]string{tc.value})
		err := cmd.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("the tuning check's refusal of %s = %v, want %q", tc.value, err, tc.want)
		}
	}
}

// TestApplicationsArgumentParses checks the composition's list on every
// assembling command: nil is the inference, the empty value the deliberate
// none — the distinction the flag's documentation carries — and a list
// parses repeatable and comma-separated.
func TestApplicationsArgumentParses(t *testing.T) {
	parse := func(t *testing.T, flags *pflag.FlagSet, args ...string) []string {
		t.Helper()
		opts := &services.NodeConfig{}
		addSharedNodeFlags(flags, opts)
		if err := flags.Parse(args); err != nil {
			t.Fatalf("parsing %v: %v", args, err)
		}
		return opts.Applications
	}
	t.Run("run core", func(t *testing.T) {
		if got := parse(t, pflag.NewFlagSet("core", pflag.ContinueOnError)); got != nil {
			t.Errorf("the unpassed list = %v, want nil", got)
		}
	})
	t.Run("run local", func(t *testing.T) {
		got := parse(t, pflag.NewFlagSet("local", pflag.ContinueOnError),
			"--applications=")
		if got == nil || len(got) != 0 {
			t.Errorf("the empty list = %v, want the deliberate none", got)
		}
	})
	t.Run("ping", func(t *testing.T) {
		got := parse(t, pflag.NewFlagSet("ping", pflag.ContinueOnError),
			"--applications", "socks,wireguard", "--applications", "coordination")
		if len(got) != 3 || got[0] != "socks" || got[1] != "wireguard" ||
			got[2] != "coordination" {

			t.Errorf("the repeated list = %v, want the spelled order kept", got)
		}
	})
}
