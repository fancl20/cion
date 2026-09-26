package coordination

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"tailscale.com/types/key"
)

// The persisted key files, beside the WireGuard application's own in the
// core's state: the noise channel's machine key authenticates the control
// conversations, and the DERP server's node key names the relay's clients.
const (
	// machineKeyFile holds the noise machine key, load-or-create on first
	// start.
	machineKeyFile = "machine.key"
	// derpKeyFile holds the DERP server's node key.
	derpKeyFile = "derp.key"
)

// LoadOrCreateMachineKey returns the noise machine key persisted in the
// application's state directory, generating and persisting one when no file
// exists. The key is the server's half of every client's noise channel: a
// client that re-dials must meet the same key its registration trusted.
func LoadOrCreateMachineKey(stateDir string) (key.MachinePrivate, error) {
	var k key.MachinePrivate
	if err := loadOrCreate(stateDir, machineKeyFile, &k,
		func() { k = key.NewMachine() }); err != nil {
		return key.MachinePrivate{}, err
	}
	return k, nil
}

// LoadOrCreateDERPKey returns the DERP server's node key persisted in the
// application's state directory, generating and persisting one when no file
// exists. The key names the relay on the wire; its stability is what keeps
// connected clients connected across restarts.
func LoadOrCreateDERPKey(stateDir string) (key.NodePrivate, error) {
	var k key.NodePrivate
	if err := loadOrCreate(stateDir, derpKeyFile, &k,
		func() { k = key.NewNode() }); err != nil {
		return key.NodePrivate{}, err
	}
	return k, nil
}

// loadOrCreate is the LoadOrCreateKey pattern over a tailscale private key:
// the file holds the key's text form, private to its owner, generated and
// persisted on first start.
func loadOrCreate(
	stateDir, name string,
	k interface {
		MarshalText() ([]byte, error)
		UnmarshalText([]byte) error
	},
	generate func(),
) error {
	path := filepath.Join(stateDir, name)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := k.UnmarshalText(bytes.TrimSpace(raw)); err != nil {
			return fmt.Errorf("parsing %s: %w", name, err)
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		generate()
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return fmt.Errorf("creating the coordination state: %w", err)
		}
		text, err := k.MarshalText()
		if err != nil {
			return fmt.Errorf("encoding %s: %w", name, err)
		}
		if err := os.WriteFile(path, append(text, '\n'), 0o600); err != nil {
			return fmt.Errorf("persisting %s: %w", name, err)
		}
		return nil
	default:
		return fmt.Errorf("reading %s: %w", name, err)
	}
}
