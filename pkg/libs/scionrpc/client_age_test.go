package scionrpc

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// countingPool answers every request with an empty response and counts the
// sweeps asked of it.
type countingPool struct {
	requests, sweeps int
}

func (p *countingPool) RoundTrip(*http.Request) (*http.Response, error) {
	p.requests++
	return httptest.NewRecorder().Result(), nil
}

func (p *countingPool) CloseIdleConnections() { p.sweeps++ }

// TestAgedTransportSweepsOncePerAge checks the age cap's cadence: requests
// within an age of the last sweep sweep nothing, the first request an age
// past it sweeps once before it rides the pool, and the next age runs from
// that sweep. The ages pass as fake-time sleeps in the bubble.
func TestAgedTransportSweepsOncePerAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := &countingPool{}
		aged := newAgedTransport(pool, time.Minute)
		for i, step := range []struct {
			wait   time.Duration
			sweeps int
		}{
			{0, 0},
			{time.Minute - time.Nanosecond, 0},
			{time.Nanosecond, 1},
			{0, 1},
			{time.Minute - time.Nanosecond, 1},
			{time.Nanosecond, 2},
		} {
			time.Sleep(step.wait)
			resp, err := aged.RoundTrip(httptest.NewRequest(http.MethodGet, "https://peer/", nil))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if pool.sweeps != step.sweeps {
				t.Errorf("sweeps after request %d = %d, want %d", i, pool.sweeps, step.sweeps)
			}
		}
		if pool.requests != 6 {
			t.Errorf("requests the pool carried = %d, want every one of 6", pool.requests)
		}
	})
}

// ageFixture is an endpoint served on one node and a client of it on the
// other over resolved paths, every request past the age cap and every dial
// counted. The endpoint answers /hold once release closes.
type ageFixture struct {
	ctx   context.Context
	hclt  *http.Client
	url   string
	dials atomic.Int32

	// entered closes once the held request reaches its handler, and closing
	// release lets the handler answer.
	entered, release chan struct{}
}

func newAgeFixture(t *testing.T) *ageFixture {
	t.Helper()
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	fx := &ageFixture{ctx: ctx, entered: make(chan struct{}), release: make(chan struct{})}

	enter := sync.OnceFunc(func() { close(fx.entered) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			enter()
			select {
			case <-fx.release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	endpoint := core.newConn(t, 0)
	served := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-served:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("ServeHTTP3 returned (%v), want the closed socket's error", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the endpoint did not stop with the test's context")
		}
	})
	go func() {
		served <- ServeHTTP3(t.Context(), endpoint, handler,
			EndpointTLS(EndpointTLSConfig{Credentials: f.engine, Key: f.engine.Key}))
	}()

	conn := peer.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	fx.hclt = NewSCIONClient(PeerClientConfig{
		Credentials: f.peer,
		Key:         f.peer.Key,
		Conn:        conn,
		PathTo: func(addr.IA) *spath.Decoded {
			fx.dials.Add(1)
			p, err := pathToCore(peer.MACKey, time.Now())
			if err != nil {
				t.Error(err)
				return nil
			}
			return p
		},
	}, qclt, true)
	fx.hclt.Transport.(*chainTransport).pool.(*agedTransport).maxAge = 0
	server := &scion.Addr{IA: nodeIATest, Addr: netip.AddrPortFrom(core.ControlIP, endpoint.LocalPort())}
	fx.url = "https://" + PeerAuthority(server)
	return fx
}

// pathToCore returns the client node's path to the endpoint's node over
// their link: the reversed two-AS segment the endpoint's node originated at
// origin, each hop MACed with the forwarding key the test nodes share.
func pathToCore(key []byte, origin time.Time) (*spath.Decoded, error) {
	pcb, err := segment.PCBWithID(origin, 0x444)
	if err != nil {
		return nil, err
	}
	mac := func() hash.Hash {
		h, _ := scrypto.InitMac(key)
		return h
	}
	if _, err := pcb.AppendRouteHop(nodeIATest,
		segment.EntryOptions{EgressIfID: dataplanetest.IfID}, mac); err != nil {
		return nil, err
	}
	if _, err := pcb.AppendRouteHop(iaLineC,
		segment.EntryOptions{IngressIfID: dataplanetest.IfID}, mac); err != nil {
		return nil, err
	}
	return pcb.ReversePathTo(0)
}

// fetch requests the endpoint's target and returns an error unless it
// answers.
func (fx *ageFixture) fetch(target string) error {
	req, err := http.NewRequestWithContext(fx.ctx, http.MethodGet, fx.url+target, nil)
	if err != nil {
		return err
	}
	resp, err := fx.hclt.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if string(body) != "ok" {
		return fmt.Errorf("the response = %q, want %q", body, "ok")
	}
	return nil
}

// TestSCIONClientRedialsPastTheAgeCap checks the age cap on a client over
// resolved paths: a request past the cap sweeps the idle connection the pool
// holds and rides a fresh dial over the path the provider resolves then.
func TestSCIONClientRedialsPastTheAgeCap(t *testing.T) {
	fx := newAgeFixture(t)
	for i := range 2 {
		if err := fx.fetch("/"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := fx.dials.Load(); got != 2 {
		t.Errorf("dials = %d, want 2: the second request's sweep retired the first's connection", got)
	}
}

// TestSCIONClientSweepSparesARequestInFlight checks the cap's grace: a sweep
// closes no connection a request rides — the held request completes, and
// the request beside it rides the same connection rather than a fresh dial.
func TestSCIONClientSweepSparesARequestInFlight(t *testing.T) {
	fx := newAgeFixture(t)
	held := make(chan error, 1)
	go func() { held <- fx.fetch("/hold") }()
	select {
	case <-fx.entered:
	case <-fx.ctx.Done():
		t.Fatalf("the held request reaching its handler: %v", fx.ctx.Err())
	}
	if err := fx.fetch("/"); err != nil {
		t.Fatalf("the request beside the held one: %v", err)
	}
	if got := fx.dials.Load(); got != 1 {
		t.Errorf("dials = %d, want 1: the sweep spared the connection the held request rides", got)
	}
	close(fx.release)
	if err := <-held; err != nil {
		t.Errorf("the held request across the sweep: %v", err)
	}
}
