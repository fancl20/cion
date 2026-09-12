package trust

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
)

// SignCMS wraps msg in a CMS SignedData signed by key, embedding chain[0] as
// the signer certificate.
func SignCMS(msg []byte, chain []*x509.Certificate, key crypto.Signer) ([]byte, error) {
	eci, err := protocol.NewDataEncapsulatedContentInfo(msg)
	if err != nil {
		return nil, err
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		return nil, err
	}
	if err := sd.AddSignerInfo(chain, key); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return sd.ContentInfoDER()
}

// CMSSigned is a parsed CMS SignedData whose signer infos are verified
// against the certificates embedded in the message.
type CMSSigned struct {
	// Payload is the encapsulated content.
	Payload []byte
	// SignerCerts are the certificates matching the signer infos, in order.
	SignerCerts []*x509.Certificate
	// Certificates are all certificates embedded in the SignedData.
	Certificates []*x509.Certificate
}

// SignedBy reports whether one of the signers holds the given public key.
func (s *CMSSigned) SignedBy(pub crypto.PublicKey) bool {
	want, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	for _, cert := range s.SignerCerts {
		if got, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil &&
			bytes.Equal(got, want) {
			return true
		}
	}
	return false
}

// ParseCMS parses der and verifies the signature of every signer info
// against the embedded certificates. Verification here proves the message
// was signed by the holder of the certificate's private key; whether that
// certificate is trusted is up to the caller.
func ParseCMS(der []byte) (*CMSSigned, error) {
	ci, err := protocol.ParseContentInfo(der)
	if err != nil {
		return nil, serrors.Wrap("parsing ContentInfo", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, serrors.Wrap("parsing SignedData", err)
	}
	certs, err := sd.X509Certificates()
	if err != nil {
		return nil, serrors.Wrap("reading embedded certificates", err)
	}
	payload, err := sd.EncapContentInfo.DataEContent()
	if err != nil {
		return nil, serrors.Wrap("reading payload", err)
	}
	var signers []*x509.Certificate
	for _, si := range sd.SignerInfos {
		cert, err := si.FindCertificate(certs)
		if err != nil {
			return nil, serrors.Wrap("finding signer certificate", err)
		}
		if err := verifySignerInfo(si, cert, payload); err != nil {
			return nil, err
		}
		signers = append(signers, cert)
	}
	if len(signers) == 0 {
		return nil, serrors.New("no signer info")
	}
	return &CMSSigned{Payload: payload, SignerCerts: signers, Certificates: certs}, nil
}

// verifySignerInfo checks the message digest attribute against the payload
// and the signature against the certificate matching the signer info.
func verifySignerInfo(si protocol.SignerInfo, cert *x509.Certificate, payload []byte) error {
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	attrDigest, err := si.GetMessageDigestAttribute()
	if err != nil {
		return err
	}
	actualDigest := hash.New()
	actualDigest.Write(payload)
	if !bytes.Equal(attrDigest, actualDigest.Sum(nil)) {
		return serrors.New("message digest does not match")
	}
	sigInput, err := si.SignedAttrs.MarshaledForVerifying()
	if err != nil {
		return err
	}
	if err := cert.CheckSignature(si.X509SignatureAlgorithm(), sigInput, si.Signature); err != nil {
		return serrors.Wrap("verifying signature", err)
	}
	return nil
}
