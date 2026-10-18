package main

import "testing"

// TestSetLogLevel checks the level flag's parse: the four slog levels apply
// to the default handler, anything else is the flag's refusal.
func TestSetLogLevel(t *testing.T) {
	t.Cleanup(func() {
		if err := setLogLevel("info"); err != nil {
			t.Fatal(err)
		}
	})
	for _, s := range []string{"debug", "info", "warn", "error"} {
		if err := setLogLevel(s); err != nil {
			t.Errorf("setLogLevel(%q): %v", s, err)
		}
	}
	if err := setLogLevel("loud"); err == nil {
		t.Error(`setLogLevel("loud") succeeded, want error`)
	}
}

// TestRootArgumentsParse checks the root's own surface: the log level
// parses. The subcommands' surfaces are their own tests'.
func TestRootArgumentsParse(t *testing.T) {
	cmd := newRootCommand()
	if err := cmd.PersistentFlags().Parse([]string{"--log.level", "debug"}); err != nil {
		t.Fatalf("parsing the root surface: %v", err)
	}
}
