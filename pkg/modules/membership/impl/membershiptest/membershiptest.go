// Package membershiptest is the membership module's contract suite: what
// every method keeps. A chain the founder issued is admitted at every
// boundary, what a node presents beside its chain passes a peer of its
// method, the method keeps what it admits and what the founding core issues
// and lists them, and its loop returns once its context ends. Each method's
// refusals are its own tests'.
// The suite opens no trust database itself: the caller passes the opener,
// for no library imports a module's implementation.
package membershiptest

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/modules/membership"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// NewMethod builds the method under test over an environment.
type NewMethod func(membership.Env) membership.Method

// OpenDB opens a fresh trust database, closed when the test ends.
type OpenDB func(t *testing.T) trustdb.DB

// The suite's ISD-ASes: the founder's, and the nodes it enrolls.
var (
	founderIA = addr.MustIAFrom(20, 0xff0000000001)
	nodeIA    = addr.MustIAFrom(20, 0xff0000000011)
	peerIA    = addr.MustIAFrom(20, 0xff0000000012)
	otherIA   = addr.MustIAFrom(20, 0xff0000000013)
)

// Run runs the contract suite against the method newMethod builds, over
// trust databases openDB opens.
func Run(t *testing.T, newMethod NewMethod, openDB OpenDB) {
	t.Run("admits a chain the founder issued", func(t *testing.T) {
		f := trusttest.NewFounder(t, openDB(t), founderIA)
		f.Enroll(t, nodeIA)
		_, peer := f.Enroll(t, peerIA)
		m := newMethod(Env(f.DB, nodeIA, false))
		for name, b := range map[string]membership.Boundary{
			"handshake": membership.BoundaryHandshake,
			"renewal":   membership.BoundaryRenewal,
		} {
			if err := m.Admit(t.Context(), membership.Facts{Boundary: b, Chain: peer}); err != nil {
				t.Errorf("%s: refused a chain the founder issued: %v", name, err)
			}
		}
	})

	t.Run("what a node presents passes its peer", func(t *testing.T) {
		f := trusttest.NewFounder(t, openDB(t), founderIA)
		_, chain := f.Enroll(t, nodeIA)
		f.Enroll(t, peerIA)
		node := newMethod(Env(f.DB, nodeIA, false))
		peer := newMethod(Env(f.DB, peerIA, false))
		presented, err := node.Present(t.Context(), chain)
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.Admit(t.Context(), membership.Facts{
			Boundary:  membership.BoundaryHandshake,
			Chain:     chain,
			Presented: presented,
		}); err != nil {
			t.Errorf("the peer refused what the node presents: %v", err)
		}
	})

	t.Run("keeps and lists what it admits and the founder issues", func(t *testing.T) {
		f := trusttest.NewFounder(t, openDB(t), founderIA)
		_, admitted := f.Enroll(t, peerIA)
		_, issued := f.Enroll(t, otherIA)
		m := newMethod(Env(f.DB, founderIA, true))
		if err := m.Admit(t.Context(), membership.Facts{
			Boundary: membership.BoundaryHandshake,
			Chain:    admitted,
		}); err != nil {
			t.Fatal(err)
		}
		if err := m.Issued(t.Context(), issued); err != nil {
			t.Fatal(err)
		}
		list, err := m.List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []struct {
			ia    addr.IA
			chain []*x509.Certificate
		}{{peerIA, admitted}, {otherIA, issued}} {
			if !listed(list, want.ia, want.chain[0].SubjectKeyId) {
				t.Errorf("the listing %v holds no membership of %s under its key", list, want.ia)
			}
		}
	})

	t.Run("the store holds what it admits", func(t *testing.T) {
		f := trusttest.NewFounder(t, openDB(t), founderIA)
		f.Enroll(t, nodeIA)
		_, peer := f.Enroll(t, peerIA)
		env := Env(f.DB, nodeIA, false)
		if err := newMethod(env).Admit(t.Context(), membership.Facts{
			Boundary: membership.BoundaryHandshake,
			Chain:    peer,
		}); err != nil {
			t.Fatal(err)
		}
		if held := env.Store.Get(peerIA); held == nil || !held[0].Equal(peer[0]) {
			t.Error("the store holds no membership of the admitted peer")
		}
	})

	t.Run("run returns once its context ends", func(t *testing.T) {
		f := trusttest.NewFounder(t, openDB(t), founderIA)
		f.Enroll(t, nodeIA)
		m := newMethod(Env(f.DB, nodeIA, false))
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			done := make(chan struct{})
			go func() {
				m.Run(ctx)
				close(done)
			}()
			synctest.Wait()
			select {
			case <-done:
			default:
				t.Error("Run did not return once its context ended")
			}
		})
	})
}

// Env returns an environment over db for ia: a fresh store, and a renewal
// that fails.
func Env(db trustdb.DB, ia addr.IA, founding bool) membership.Env {
	return membership.Env{
		IA:       ia,
		Founding: founding,
		Store:    membership.NewStore(),
		DB:       db,
		Renew: func(context.Context) ([]*x509.Certificate, error) {
			return nil, errors.New("the suite renews nothing")
		},
	}
}

// listed reports whether the listing holds a membership of ia under key.
func listed(list []membership.Membership, ia addr.IA, key []byte) bool {
	for _, m := range list {
		if m.IA.Equal(ia) && bytes.Equal(m.Key, key) {
			return true
		}
	}
	return false
}
