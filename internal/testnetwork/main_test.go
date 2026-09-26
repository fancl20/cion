package testnetwork

import (
	"os"
	"testing"

	"tailscale.com/net/netns"
)

// packageWebPKI is the package's certificate authority, minted by TestMain
// before any test runs: the CA whose file SSL_CERT_FILE names, the one the
// vendored tailnet clients trust. The coordination suites' cores present
// its certificate.
var packageWebPKI *WebPKI

// TestMain mints the package's certificate authority before any test runs
// and points the process's TLS root store at it: the vendored tailnet
// clients the coordination suites run verify the core's certificate with
// the system roots, and the Go root store honors SSL_CERT_FILE at its
// first load — set here, before that. Tests that pass their own pools are
// unaffected.
func TestMain(m *testing.M) {
	// The vendored client engine's sockets ride the netns wrapper, which
	// binds non-localhost sockets to the default-route interface — on the
	// harness's loopback topology that sends the engine's UDP to 127.0.0.x
	// out the container's eth0 instead. A process embedding the client
	// disables the wrapper; the harness is one.
	netns.SetEnabled(false)
	dir, err := os.MkdirTemp("", "cion-test-ca")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	wpki, err := mintWebPKI(dir)
	if err != nil {
		panic(err)
	}
	packageWebPKI = wpki
	_ = os.Setenv("SSL_CERT_FILE", wpki.caFile)
	os.Exit(m.Run())
}
