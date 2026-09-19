// Package webpki is ADR-0003's bootstrap channel as a shared library: the
// ACME certificate management of the core's endpoint and the WebPKI-verified
// client of the core's control endpoint, serving the enrollment lifecycle
// from outside the drafts' subset. The enrollment lifecycle keeps driving it
// — the shared libraries exist to be imported by core and apps alike, and
// the dependency direction stays one-way: this package imports the SCION
// library and the trust material, never the control plane.
package webpki

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// client is the ConnectRPC client of the trust services the channel reaches:
// the drafts' RPC machinery consumed as a library, the form the control
// endpoint's own client takes beside the services this one does not ride.
type client struct {
	control_planeconnect.TrustMaterialServiceClient
	control_planeconnect.ChainRenewalServiceClient
}

// newClient builds the trust client over the HTTP client at the base URL.
func newClient(clt connect.HTTPClient, baseURL string) *client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &client{
		TrustMaterialServiceClient: control_planeconnect.NewTrustMaterialServiceClient(clt, baseURL),
		ChainRenewalServiceClient:  control_planeconnect.NewChainRenewalServiceClient(clt, baseURL),
	}
}

// CoreClient resolves trust material from the core's control endpoint:
// ConnectRPC over HTTP/3 (QUIC) riding the SCION network, TLS-verified
// end-to-end against the core's domain. The domain is a TLS identity, not a
// locator; the locator supplies the SCION route — the core's control service
// as a service destination on the one-hop path, or the reversed up segment
// the path provider composes.
type CoreClient struct {
	conn    *scion.Conn
	qclt    *quic.Transport
	clt     *client
	locator func() *scion.Addr
	// resolve maps a service-destined locator to the QUIC transport address
	// the drafts' service resolution returns; nil dials the locator as named.
	resolve func(ctx context.Context, peer *scion.Addr) (netip.AddrPort, error)

	mtx  sync.Mutex
	core *scion.Addr
}

// CoreClientConfig configures a CoreClient.
type CoreClientConfig struct {
	// Domain is the core's DNS domain, verified as the TLS server name.
	Domain string
	// Conn is the SCION connection QUIC rides to the core.
	Conn *scion.Conn
	// RootCAs anchors the TLS verification; nil means the system roots.
	RootCAs *x509.CertPool
	// Locator resolves the core's SCION address: its IA, the destination —
	// the core's control service as a service destination, or an underlay
	// address — and path — the one-hop path when the core is a neighbor,
	// else the reversed freshest up segment (proposal 0004). It is
	// consulted at dial time, so later dials pick up fresh paths. Nil falls
	// back to SetCore.
	Locator func() *scion.Addr
	// ResolveService resolves a service-destined locator through the drafts'
	// service discovery (control plane draft, Section 5): the request the
	// control plane's own exchange answers with the service's QUIC
	// transport address, which the dial then uses. Nil dials a
	// service-destined locator as named, the receiving router delivering to
	// the registered service.
	ResolveService func(ctx context.Context, peer *scion.Addr) (netip.AddrPort, error)
}

// NewCoreClient dials the core's control endpoint. The client fails on use,
// not on creation: until the locator names a reachable core, requests fail
// fast and are retried by the caller.
func NewCoreClient(cfg CoreClientConfig) (*CoreClient, error) {
	c := &CoreClient{conn: cfg.Conn, locator: cfg.Locator, resolve: cfg.ResolveService}
	c.qclt = &quic.Transport{Conn: cfg.Conn}

	// QUIC datagrams are capped so a datagram wrapped in a SCION header
	// still fits a standard 1500-byte MTU.
	quicConf := &quic.Config{InitialPacketSize: 1200}
	tlsConf := &tls.Config{
		ServerName: cfg.Domain,
		RootCAs:    cfg.RootCAs,
		MinVersion: tls.VersionTLS13,
	}
	h3t := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		// The request URL carries the domain, a TLS identity; the dialer
		// routes to the SCION locator of the core.
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config,
			cfg *quic.Config) (*quic.Conn, error) {

			peer := c.coreAddr()
			if peer == nil {
				return nil, errors.New("core locator unknown")
			}
			if peer.Service != 0 && c.resolve != nil {
				// The drafts' own step: the service resolution answers the
				// address the QUIC connection then uses (control plane
				// draft, Section 5).
				resolved, err := c.resolve(ctx, peer)
				if err != nil {
					return nil, fmt.Errorf("resolving the core's control service: %w", err)
				}
				peer = &scion.Addr{
					IA:      peer.IA,
					Addr:    resolved,
					IfID:    peer.IfID,
					Path:    peer.Path,
					Service: 0,
				}
			}
			return c.qclt.Dial(ctx, peer, tlsCfg, cfg)
		},
	}
	c.clt = newClient(&http.Client{Transport: h3t}, "https://"+cfg.Domain)
	return c, nil
}

// SetCore sets the SCION locator of the core: its IA and the underlay
// address of its control endpoint.
func (c *CoreClient) SetCore(ia addr.IA, addr netip.AddrPort) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.core = &scion.Addr{IA: ia, Addr: addr}
}

// SetLocator sets the locator resolving the core's SCION address at dial
// time; it overrides SetCore's address.
func (c *CoreClient) SetLocator(locator func() *scion.Addr) {
	c.locator = locator
}

// coreAddr resolves the core's current address: the locator when configured,
// else the address set with SetCore. Nil means the locator is unknown.
func (c *CoreClient) coreAddr() *scion.Addr {
	if c.locator != nil {
		return c.locator()
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.core
}

// Close releases the underlying QUIC transport.
func (c *CoreClient) Close() error {
	return c.qclt.Close()
}

// TRC fetches the signed TRC with the given ID.
func (c *CoreClient) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	if c.coreAddr() == nil {
		return cppki.SignedTRC{}, fmt.Errorf("core locator unknown")
	}
	resp, err := c.clt.TRC(ctx, connect.NewRequest(&cppb.TRCRequest{
		Isd:    uint32(id.ISD),
		Base:   uint64(id.Base),
		Serial: uint64(id.Serial),
	}))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(resp.Msg.Trc)
}

// Chains fetches the chains matching the query.
func (c *CoreClient) Chains(
	ctx context.Context,
	q trust.ChainQuery,
) ([][]*x509.Certificate, error) {

	if c.coreAddr() == nil {
		return nil, fmt.Errorf("core locator unknown")
	}
	req := &cppb.ChainsRequest{
		IsdAs:        uint64(q.IA),
		SubjectKeyId: q.SubjectKeyID,
	}
	if !q.Validity.NotBefore.IsZero() {
		req.AtLeastValidSince = timestamppb.New(q.Validity.NotBefore)
	}
	if !q.Validity.NotAfter.IsZero() {
		req.AtLeastValidUntil = timestamppb.New(q.Validity.NotAfter)
	}
	resp, err := c.clt.Chains(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	var out [][]*x509.Certificate
	for _, chain := range resp.Msg.Chains {
		asCert, err := x509.ParseCertificate(chain.AsCert)
		if err != nil {
			return nil, fmt.Errorf("parsing AS certificate: %w", err)
		}
		caCert, err := x509.ParseCertificate(chain.CaCert)
		if err != nil {
			return nil, fmt.Errorf("parsing CA certificate: %w", err)
		}
		out = append(out, []*x509.Certificate{asCert, caCert})
	}
	return out, nil
}

// RenewChain requests a chain for the CSR. The CMS wrapper is signed by the
// subject key itself, the proof of possession a first-issuance request
// offers.
func (c *CoreClient) RenewChain(
	ctx context.Context,
	csr *x509.CertificateRequest,
	key crypto.Signer,
) ([]*x509.Certificate, error) {

	if c.coreAddr() == nil {
		return nil, fmt.Errorf("core locator unknown")
	}
	cmsReq, err := trust.BuildRenewalRequest(csr, key)
	if err != nil {
		return nil, fmt.Errorf("building renewal request: %w", err)
	}
	resp, err := c.clt.ChainRenewal(ctx, connect.NewRequest(
		&cppb.ChainRenewalRequest{CmsSignedRequest: cmsReq}))
	if err != nil {
		return nil, err
	}
	return trust.ParseRenewalResponse(resp.Msg.CmsSignedResponse)
}
