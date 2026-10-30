package services

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"
	"go.etcd.io/bbolt"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/libs/scion"
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
				group, _ := supervise.New(t.Context())
				defer func() { _ = group.Stop() }()
				n := &node{cfg: resolvedConfig{NodeConfig: NodeConfig{State: state}}, group: group}
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

// TestOrderIssuerRoutes checks the order a renewal asks the issuers in: the
// issuers a usable link reaches first, by ISD-AS, over the link — a
// neighbor that issues nothing passed over — then the others by the
// freshness of their up segments over the composed path, an issuer no path
// reaches left out.
func TestOrderIssuerRoutes(t *testing.T) {
	ia := func(as addr.AS) addr.IA { return addr.MustIAFrom(20, as) }
	issuers := map[addr.IA]bool{ia(1): true, ia(2): true, ia(3): true, ia(4): true, ia(5): true}
	usable := map[uint16]addr.IA{7: ia(3), 8: ia(9), 9: ia(1)}
	composed := &spath.Decoded{}
	localPath := func(dst addr.IA) (*spath.Decoded, error) {
		if dst == ia(5) {
			return nil, errors.New("no path")
		}
		return composed, nil
	}

	got := orderIssuerRoutes(issuers, usable, []addr.IA{ia(4), ia(3), ia(5), ia(2)}, localPath)
	want := []*scion.Addr{
		{IA: ia(1), Service: addr.SvcCS, IfID: 9},
		{IA: ia(3), Service: addr.SvcCS, IfID: 7},
		{IA: ia(4), Service: addr.SvcCS, Path: composed},
		{IA: ia(2), Service: addr.SvcCS, Path: composed},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
		t.Errorf("the issuer routes (-want +got):\n%s", diff)
	}
}
