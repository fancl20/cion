package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigMissing(t *testing.T) {
	if _, err := LoadConfig(""); err == nil {
		t.Error("loading without --config succeeded, want the configuration error")
	}
	if _, err := LoadConfig(t.TempDir() + "/absent.json"); err == nil {
		t.Error("loading an absent file succeeded, want the configuration error")
	}
}

// TestLoadConfigWireguardSection checks the section's decoding beside the
// rename's operator-visible edge (proposal 0009): a wireguard section
// parses, and a stale gateway section is refused rather than silently
// ignored.
func TestLoadConfigWireguardSection(t *testing.T) {
	write := func(t *testing.T, section string) string {
		t.Helper()
		body := `{
			"ia": "20-ff00:0:1",
			"asType": "normal",
			"state": "` + t.TempDir() + `",
			"internal": "127.0.0.1:30042",
			"key": "000102030405060708090a0b0c0d0e0f"
			` + section + `
		}`
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	cfg, err := LoadConfig(write(t, `,"wireguard": {
		"subnet": "10.64.1.0/24",
		"listenPort": 51820
	}`))
	if err != nil {
		t.Fatalf("loading the wireguard section: %v", err)
	}
	if cfg.Wireguard == nil || cfg.Wireguard.ListenPort != 51820 {
		t.Errorf("wireguard section = %+v, want the configured one", cfg.Wireguard)
	}

	if _, err := LoadConfig(write(t, `,"gateway": {
		"subnet": "10.64.1.0/24",
		"listenPort": 51820
	}`)); err == nil {
		t.Error("a stale gateway section was accepted, want the configuration refused")
	}
}
