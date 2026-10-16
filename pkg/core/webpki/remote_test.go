package webpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// TestCoreBaseURLBracketsTheLiteral checks the base URL the client's
// requests carry: an IPv6 literal takes RFC 3986's brackets, and an IPv4
// literal and a domain stand as given — the URL carries the identity, which
// the verifier names bare whatever its grammar.
func TestCoreBaseURLBracketsTheLiteral(t *testing.T) {
	for _, tc := range []struct{ identity, want string }{
		{"2001:db8::1", "https://[2001:db8::1]"},
		{"::ffff:192.0.2.10", "https://[::ffff:192.0.2.10]"},
		{"192.0.2.10", "https://192.0.2.10"},
		{webpkitest.Domain, "https://" + webpkitest.Domain},
	} {
		if got := coreBaseURL(tc.identity); got != tc.want {
			t.Errorf("coreBaseURL(%q) = %q, want %q", tc.identity, got, tc.want)
		}
	}
}

// TestCoreClientConsultsItsLocatorOncePerRequest checks that each request
// reads the core's locator once, in its dial: a locator that takes turns
// among cores, as the bootstrap core does, then hands every dial the turn it
// advanced. The service resolution refuses, so each request ends in its dial.
func TestCoreClientConsultsItsLocatorOncePerRequest(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000002)
	calls := 0
	refused := errors.New("no resolution response")
	c, err := NewCoreClient(CoreClientConfig{
		Domain: webpkitest.Domain,
		Locator: func() *scion.Addr {
			calls++
			return &scion.Addr{IA: addr.MustIAFrom(20, 0xff0000000001), Service: addr.SvcCS}
		},
		ResolveService: func(context.Context, *scion.Addr) (netip.AddrPort, error) {
			return netip.AddrPort{}, refused
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for _, request := range []struct {
		name string
		do   func() error
	}{
		{"TRC", func() error {
			_, err := c.TRC(ctx, cppki.TRCID{ISD: ia.ISD()})
			return err
		}},
		{"Chains", func() error {
			_, err := c.Chains(ctx, trustdb.ChainQuery{IA: ia})
			return err
		}},
		{"RenewChain", func() error {
			_, err := c.RenewChain(ctx, csr, key)
			return err
		}},
	} {
		calls = 0
		if err := request.do(); !errors.Is(err, refused) {
			t.Errorf("%s error = %v, want the refused resolution", request.name, err)
		}
		if calls != 1 {
			t.Errorf("%s consulted the locator %d times, want once", request.name, calls)
		}
	}
}
