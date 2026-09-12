package controlplane

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fancl20/cion/pkg/trust"
)

// CoreClient resolves trust material from the core's control endpoint:
// ConnectRPC over HTTP/3 (QUIC) riding the SCION network, TLS-verified
// end-to-end against the core's domain. The domain is a TLS identity, not a
// locator; SetCore supplies the SCION locator learned from neighbor
// discovery.
type CoreClient struct {
	conn *SCIONConn
	qclt *quic.Transport
	clt  *Client

	mtx  sync.Mutex
	core *Addr
}

// CoreClientConfig configures a CoreClient.
type CoreClientConfig struct {
	// Domain is the core's DNS domain, verified as the TLS server name.
	Domain string
	// Conn is the SCION connection QUIC rides to the core.
	Conn *SCIONConn
	// RootCAs anchors the TLS verification; nil means the system roots.
	RootCAs *x509.CertPool
}

// NewCoreClient dials the core's control endpoint. The client fails on use,
// not on creation: until SetCore names a reachable core, requests fail
// fast and are retried by the caller.
func NewCoreClient(cfg CoreClientConfig) (*CoreClient, error) {
	c := &CoreClient{conn: cfg.Conn}
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
		// routes to the SCION locator of the core set with SetCore.
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config,
			cfg *quic.Config) (*quic.Conn, error) {

			return c.qclt.Dial(ctx, c.coreAddr(), tlsCfg, cfg)
		},
	}
	c.clt = NewClient(&http.Client{Transport: h3t}, "https://"+cfg.Domain)
	return c, nil
}

// SetCore sets the SCION locator of the core: its IA and the underlay
// address of its control endpoint, the discovery greeting's control address
// with the endpoint port.
func (c *CoreClient) SetCore(ia addr.IA, addr netip.AddrPort) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.core = &Addr{IA: ia, Addr: addr}
}

func (c *CoreClient) coreAddr() net.Addr {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.core == nil {
		return nil
	}
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
