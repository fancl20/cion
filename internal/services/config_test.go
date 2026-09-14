package services

import "testing"

func TestLoadConfigMissing(t *testing.T) {
	if _, err := LoadConfig(""); err == nil {
		t.Error("loading without --config succeeded, want the configuration error")
	}
	if _, err := LoadConfig(t.TempDir() + "/absent.json"); err == nil {
		t.Error("loading an absent file succeeded, want the configuration error")
	}
}
