// Package mihomo is the mihomo application: the mihomo proxy provider a node
// serves its hosts at its own address, listing one tailnet client instance
// per exit the tailnet topic names — each node with a slice, the node's own
// among them — so a host's mihomo chooses its exit per flow. Its listener is
// borrowed at the node's own address alone, so the provider answers on the
// tailnet and nowhere else.
package mihomo

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fancl20/cion/pkg/libs/bus"
)

// port is the provider's port at the node's own address.
const port = 80

// readHeaderTimeout bounds how long a connection may take to send its
// request's header.
const readHeaderTimeout = 10 * time.Second

// Config configures the application.
type Config struct {
	// Listen borrows a listener at the node's own address and the port,
	// waiting for the address until ctx ends: the egress's.
	Listen func(ctx context.Context, port uint16) (net.Listener, error)
	// Tailnet is the WireGuard application's tailnet topic; each request
	// reads its last event.
	Tailnet *bus.Topic[bus.TailnetState]
	// ControlURL is the coordination server every instance logs in against.
	ControlURL string
}

// App is the mihomo application.
type App struct {
	cfg Config
}

// New assembles the application; Run borrows its listener.
func New(cfg Config) *App {
	return &App{cfg: cfg}
}

// Run borrows the listener and serves the provider on it until the context
// is canceled. A context ending while the listener waits for the node's own
// address ends Run with nothing served.
func (a *App) Run(ctx context.Context) error {
	ln, err := a.cfg.Listen(ctx, port)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("borrowing the provider's listener: %w", err)
	}
	srv := &http.Server{
		Handler:           a.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	release := sync.OnceValue(srv.Close)
	stop := context.AfterFunc(ctx, func() { _ = release() })
	defer func() {
		stop()
		_ = release()
	}()
	slog.Info("Serving the mihomo provider", "addr", ln.Addr().String())
	err = srv.Serve(ln)
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("serving the provider: %w", err)
}

// Close releases nothing: Run releases the listener it borrowed before it
// returns.
func (a *App) Close() {}

// handler serves GET /mihomo: the provider of the exits the tailnet topic's
// last event names.
func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mihomo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, a.provider(a.cfg.Tailnet.Latest()))
	})
	return mux
}

// provider is the document GET /mihomo answers: a mihomo proxy provider,
// JSON that a YAML reader reads as YAML.
type provider struct {
	Proxies []proxy `json:"proxies"`
}

// proxy is one tailnet client instance, its exit one node.
type proxy struct {
	// Name is the exit's ISD-AS.
	Name       string `json:"name"`
	Type       string `json:"type"`
	ControlURL string `json:"control-url"`
	// ExitNode is the exit's serving address, the first of its slice.
	ExitNode string `json:"exit-node"`
	// StateDir is derived from the exit's ISD-AS, so a refetch keeps each
	// instance's login.
	StateDir  string `json:"state-dir"`
	UDP       bool   `json:"udp"`
	IPVersion string `json:"ip-version"`
}

// provider lists one instance per node of the view holding a slice, in the
// view's order.
func (a *App) provider(view bus.TailnetState) provider {
	proxies := make([]proxy, 0, len(view.Nodes))
	for _, node := range view.Nodes {
		if !node.Slice.IsValid() {
			continue
		}
		ia := node.IA.String()
		proxies = append(proxies, proxy{
			Name:       ia,
			Type:       "tailscale",
			ControlURL: a.cfg.ControlURL,
			ExitNode:   node.Slice.Masked().Addr().Next().String(),
			StateDir:   "cion/" + strings.ReplaceAll(ia, ":", "_"),
			UDP:        true,
			IPVersion:  "ipv4",
		})
	}
	return provider{Proxies: proxies}
}
