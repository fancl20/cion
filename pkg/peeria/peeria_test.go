package peeria

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// TestAuthenticateMiddleware checks the middleware peers the verified
// chain's ISD-AS into the request context for the handlers to read.
func TestAuthenticateMiddleware(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000141)
	var seen addr.IA
	h := Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = AuthenticatedIA(r.Context())
	}))
	r := httptest.NewRequest("POST", "/", nil)
	// A certificate whose subject names the ISD-AS the way SCION chains do.
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		iaSubjectCert(t, ia),
	}}
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !seen.Equal(ia) {
		t.Errorf("authenticated ISD-AS = %s, want %s", seen, ia)
	}
}

// iaSubjectCert builds a certificate whose subject names the ISD-AS the way
// SCION chains do: the IA in the subject's dedicated RDN.
func iaSubjectCert(t *testing.T, ia addr.IA) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			// Marshaling writes ExtraNames; Names is only populated on
			// parsing.
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: cppki.OIDNameIA, Value: ia.String()}},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
