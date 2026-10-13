package controlplane

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/webpki"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// TestServeHTTP3JoinsItsHandlers checks the endpoint's stop: the context's
// end closes the socket, ending every connection and canceling its
// requests' contexts, and ServeHTTP3 returns only once each handler has
// returned — the node's releases follow the serving loop's return, so a
// handler still running would meet the stores they close — with the socket
// released for the next bind of the port.
func TestServeHTTP3JoinsItsHandlers(t *testing.T) {
	iaCore := addr.MustIAFrom(20, 0xff0000000001)
	iaNode := addr.MustIAFrom(20, 0xff0000000002)
	wpki := webpkitest.New(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, iaCore, iaNode, extA, extB)
	node := startTestNode(t, iaNode, iaCore, extB, extA)
	certMgr, err := webpki.PrepareTLSCert(webpki.TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: wpki.CertFile,
		KeyFile:  wpki.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The handler holds its request past the context's end until the test
	// releases it.
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	enter := sync.OnceFunc(func() { close(entered) })
	seeCancel := sync.OnceFunc(func() { close(canceled) })
	releaseHandler := sync.OnceFunc(func() { close(release) })
	defer releaseHandler()
	var returned atomic.Bool
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		enter()
		<-r.Context().Done()
		seeCancel()
		<-release
		returned.Store(true)
	})
	serveCtx, stopServe := context.WithCancel(t.Context())
	defer stopServe()
	endpoint := core.newConn(t, EndpointPort)
	served := make(chan error, 1)
	go func() { served <- ServeHTTP3(serveCtx, endpoint, handler, certMgr.TLSConfig()) }()

	client, err := webpki.NewCoreClient(webpki.CoreClientConfig{
		Domain:  webpkitest.Domain,
		Conn:    node.newConn(t, 0),
		RootCAs: wpki.Pool,
		Locator: func() *scion.Addr {
			return &scion.Addr{IA: iaCore, Addr: netip.AddrPortFrom(core.controlIP, EndpointPort)}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx := t.Context()
	go func() { _, _ = client.TRC(ctx, cppki.TRCID{ISD: iaCore.ISD(), Base: 1, Serial: 1}) }()
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("the request never reached the handler")
	}

	stopServe()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the request's context did not end with the serve's")
	}
	// The socket's close ends the listener before the connections, so a
	// server that leaves its handlers unjoined returns inside the window.
	select {
	case err := <-served:
		t.Fatalf("ServeHTTP3 returned (%v) while its handler ran", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseHandler()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP3 did not return once its handler had")
	}
	if !returned.Load() {
		t.Error("ServeHTTP3 returned before its handler")
	}
	// The endpoint's port binds again: the serve released its socket.
	core.newConn(t, EndpointPort)
}
