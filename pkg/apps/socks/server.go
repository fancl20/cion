package socks

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sync"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// Owner is the WireGuard application's surface the SOCKS application
// borrows: the assigned slice its serving waits for and the router the
// netstack rides.
type Owner interface {
	// Subnet returns the node's assigned slice of the tailnet range,
	// waiting for the directory's answer.
	Subnet(ctx context.Context) (netip.Prefix, error)
	// Router returns the overlay routing the application borrows.
	Router() wireguard.Router
}

// Server is the SOCKS application's serving form: the wait for the
// directory's assignment — the publication's answer — and, once it
// arrives, the application that claims the slice's first address. The
// construction is a publication's answer, not a boot's fact: the
// application assembles one publication later than the WireGuard
// application's own, and a node that serves no hosts serves no one.
type Server struct {
	owner Owner

	mtx sync.Mutex
	// app is the assembled application, set once the assignment arrived.
	app *App
}

// NewServer stands the serving form beside the WireGuard application
// whose router and assigned slice it borrows.
func NewServer(owner Owner) *Server {
	return &Server{owner: owner}
}

// Run waits for the directory's assignment and serves the application it
// assembles on the slice's first address — the node's own, which the
// allocator never issues — until the context ends.
func (s *Server) Run(ctx context.Context) error {
	subnet, err := s.owner.Subnet(ctx)
	if err != nil {
		// The node's cancellation ended the wait; nothing assembled.
		return nil
	}
	app, err := New(Config{Subnet: subnet, Router: s.owner.Router()})
	if err != nil {
		return fmt.Errorf("assembling the SOCKS application: %w", err)
	}
	s.mtx.Lock()
	s.app = app
	s.mtx.Unlock()
	return app.Run(ctx)
}

// Close retires the assembled application whenever it stands; before the
// assignment arrives nothing assembled, and nothing releases.
func (s *Server) Close() {
	s.mtx.Lock()
	app := s.app
	s.app = nil
	s.mtx.Unlock()
	if app != nil {
		app.Close()
	}
}

// HTTPSHandler is nil: the application's serving surface is its own
// listener on the overlay, and it mounts nothing on the node's HTTPS
// server.
func (s *Server) HTTPSHandler() http.Handler { return nil }
