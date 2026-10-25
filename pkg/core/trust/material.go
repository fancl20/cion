package trust

import (
	"crypto/x509"
	"fmt"

	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// TRCRequest builds the drafts' request for the signed TRC with the given ID
// (control plane draft, Section 2.4); the numbers-less ID asks the ISD's
// newest.
func TRCRequest(id cppki.TRCID) *cppb.TRCRequest {
	return &cppb.TRCRequest{
		Isd:    uint32(id.ISD),
		Base:   uint64(id.Base),
		Serial: uint64(id.Serial),
	}
}

// ChainsRequest builds the drafts' request for the chains matching the
// query (Section 2.4); an unset validity bound leaves that side to the
// server, which reads it as valid now.
func ChainsRequest(q trustdb.ChainQuery) *cppb.ChainsRequest {
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
	return req
}

// ParseChains parses the chains a chains response carries, each an AS
// certificate and the CA certificate that issued it. Nothing about them is
// verified: the provider checks them against the anchor pool before it
// keeps any.
func ParseChains(resp *cppb.ChainsResponse) ([][]*x509.Certificate, error) {
	var out [][]*x509.Certificate
	for _, chain := range resp.Chains {
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
