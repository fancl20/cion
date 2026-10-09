package coordination

import (
	"bytes"
	"fmt"
	"path/filepath"

	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/statefile"
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
	return loadOrCreate(stateDir, machineKeyFile, key.NewMachine)
}

// LoadOrCreateDERPKey returns the DERP server's node key persisted in the
// application's state directory, generating and persisting one when no file
// exists. The key names the relay on the wire; its stability is what keeps
// connected clients connected across restarts.
func LoadOrCreateDERPKey(stateDir string) (key.NodePrivate, error) {
	return loadOrCreate(stateDir, derpKeyFile, key.NewNode)
}

// loadOrCreate loads or creates a tailscale private key: the file holds the
// key's text form, private to its owner, generated and persisted on first
// start.
func loadOrCreate[K any, PK interface {
	*K
	MarshalText() ([]byte, error)
	UnmarshalText([]byte) error
}](stateDir, name string, generate func() K) (K, error) {

	return statefile.LoadOrCreate(filepath.Join(stateDir, name),
		func(raw []byte) (K, error) {
			var k K
			err := PK(&k).UnmarshalText(bytes.TrimSpace(raw))
			return k, err
		},
		func() (K, []byte, error) {
			k := generate()
			text, err := PK(&k).MarshalText()
			if err != nil {
				return k, nil, fmt.Errorf("encoding %s: %w", name, err)
			}
			return k, append(text, '\n'), nil
		})
}
