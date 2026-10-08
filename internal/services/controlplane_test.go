package services

import (
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"

	"go.etcd.io/bbolt"
)

// TestOpenStateRefusesHeldDatabase checks a database another process holds
// fails the boot at the lock's bound, the state directory named in use,
// rather than waiting on the lock — for each of the node's databases, the
// first to open and the ones after it.
func TestOpenStateRefusesHeldDatabase(t *testing.T) {
	for _, name := range []string{"trust.db", "path.db", "links.db"} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			held, err := bbolt.Open(filepath.Join(state, name), 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Close() }()
			synctest.Test(t, func(t *testing.T) {
				n := &node{cfg: NodeConfig{State: state}}
				defer n.Close()
				err := n.openState(t.Context())
				if err == nil {
					t.Fatal("the held state directory opened")
				}
				want := "the state directory " + state + " is in use: another process holds " + name
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal = %q, want it to carry %q", err, want)
				}
			})
		})
	}
}
