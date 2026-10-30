package trust_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust"
)

// TestBindHeldNames checks the founder's boot binding of the names it issued
// before it kept bindings: every name holding a chain valid now is bound to
// the chain's key, a name whose chain expired is left free, and a name bound
// already keeps its binding. The expiry is walked in a fake-time bubble.
func TestBindHeldNames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFounder(t)
		ctx := context.Background()
		lapsed := addr.MustIAFrom(coreIATest.ISD(), 0xff00000000a1)
		held := addr.MustIAFrom(coreIATest.ISD(), 0xff00000000a2)
		bound := addr.MustIAFrom(coreIATest.ISD(), 0xff00000000a3)

		f.Enroll(t, lapsed)
		time.Sleep(trust.ASValidity + time.Hour)
		_, heldChain := f.Enroll(t, held)
		f.Enroll(t, bound)
		if err := f.DB.BindKey(ctx, bound, []byte("the earlier binding")); err != nil {
			t.Fatal(err)
		}

		if err := trust.BindHeldNames(ctx, f.DB); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			ia   addr.IA
			want string
		}{
			{lapsed, ""},
			{held, string(heldChain[0].SubjectKeyId)},
			{bound, "the earlier binding"},
		} {
			got, err := f.DB.BoundKey(ctx, tc.ia)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("binding of %s = %x, want %x", tc.ia, got, tc.want)
			}
		}
	})
}
