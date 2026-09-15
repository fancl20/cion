package wireguard

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/scion"
	gatewayv1 "github.com/fancl20/cion/proto/gateway/v1"
	gatewayv1connect "github.com/fancl20/cion/proto/gateway/v1/gatewayv1connect"
)

// rpcDirectoryClient publishes and fetches over the application's own mTLS
// channel — the control endpoint's machinery consumed as a library,
// presenting the node's certificate chain and verifying the core's against
// the pinned TRC — so the core's verified chain identifies the publisher.
type rpcDirectoryClient struct {
	conn      *scion.Conn
	engine    *Engine
	provider  *scion.PathProvider
	coreRoute func() *scion.Addr

	// qclt is the one QUIC transport every dial rides.
	qclt *quic.Transport

	mtx sync.Mutex
	// clt serves the current core endpoint; the authority it is keyed by
	// replaces it when the core's route moves.
	clt       gatewayv1connect.DirectoryServiceClient
	authority string
}

// newRPCDirectoryClient builds the client toward the core's directory
// endpoint.
func newRPCDirectoryClient(
	conn *scion.Conn,
	coreRoute func() *scion.Addr,
	engine *Engine,
	provider *scion.PathProvider,
) *rpcDirectoryClient {
	return &rpcDirectoryClient{
		conn:      conn,
		engine:    engine,
		provider:  provider,
		coreRoute: coreRoute,
		qclt:      &quic.Transport{Conn: conn},
	}
}

// Close releases the transport.
func (c *rpcDirectoryClient) Close() error { return c.qclt.Close() }

// client returns the ConnectRPC client for the core's directory endpoint,
// building it — or rebuilding it when the core's route moved — on demand.
func (c *rpcDirectoryClient) client() (gatewayv1connect.DirectoryServiceClient, error) {
	core := c.coreRoute()
	if core == nil {
		return nil, errors.New("no route to the core's directory yet")
	}
	authority := controlplane.PeerAuthority(core)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.clt != nil && c.authority == authority {
		return c.clt, nil
	}
	hclt := controlplane.NewSCIONClient(controlplane.PeerClientConfig{
		Engine: c.engine,
		Conn:   c.conn,
		PathTo: func(dst addr.IA) *spath.Decoded {
			path, err := c.provider.LocalPath(dst)
			if err != nil {
				return nil
			}
			return path
		},
	}, c.qclt, true)
	c.clt = gatewayv1connect.NewDirectoryServiceClient(hclt, "https://"+authority)
	c.authority = authority
	return c.clt, nil
}

// Publish records the node's entry with the core.
func (c *rpcDirectoryClient) Publish(ctx context.Context, entry Entry) error {
	clt, err := c.client()
	if err != nil {
		return err
	}
	_, err = clt.Publish(ctx, connect.NewRequest(&gatewayv1.PublishRequest{
		Entry: entry.pb(),
	}))
	return err
}

// List fetches the directory from the core.
func (c *rpcDirectoryClient) List(ctx context.Context) ([]Entry, error) {
	clt, err := c.client()
	if err != nil {
		return nil, err
	}
	resp, err := clt.List(ctx, connect.NewRequest(&gatewayv1.ListRequest{}))
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(resp.Msg.Entries))
	for _, pb := range resp.Msg.Entries {
		entry, err := entryFromPB(pb)
		if err != nil {
			return nil, fmt.Errorf("decoding an entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
