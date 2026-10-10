package services

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// TestSetupNodeConsumesResolution checks the phases hold what resolve built
// once: the trust service, the TRC decision, and the applications'
// environment hold the one authorizer instance, and the applications that
// load are the entries resolve selected.
func TestSetupNodeConsumesResolution(t *testing.T) {
	certFile, keyFile := mintCertFiles(t)
	cfg := nodeConfig()
	cfg.State = t.TempDir()
	// A loopback host of the package's own: the founding core binds its
	// fixed endpoint and rendezvous ports on the control host.
	cfg.Internal = "127.0.0.124:30044"
	cfg.Control = "127.0.0.124:30042"
	cfg.CertFile, cfg.KeyFile = certFile, keyFile
	cfg.EnrollAuth = "cidrs=192.0.2.0/24"
	group, _ := supervise.New(t.Context())
	n, err := setupNode(t.Context(), group, cfg, DefaultDataplaneOptions())
	if err != nil {
		t.Fatal(errors.Join(err, group.Stop()))
	}
	t.Cleanup(func() {
		if err := group.Stop(); err != nil {
			t.Errorf("releasing the node: %v", err)
		}
	})

	auth := n.cfg.enrollAuth
	if auth == nil {
		t.Fatal("resolve built no authorizer")
	}
	trustService := n.services.TrustService
	for holder, got := range map[string]enrollauth.AdmissionAuthorizer{
		"the trust service":             trustService.Authorizer,
		"the TRC decision":              n.decider.Authorizer,
		"the applications' environment": n.appEnvironment().Authorizer,
	} {
		if got != auth {
			t.Errorf("%s holds %p, want resolve's %p", holder, got, auth)
		}
	}

	var selected, loaded []string
	for _, e := range n.cfg.apps {
		selected = append(selected, e.Name)
	}
	for _, l := range n.apps {
		loaded = append(loaded, l.Name)
	}
	if len(selected) == 0 {
		t.Fatal("resolve selected no application")
	}
	if diff := cmp.Diff(selected, loaded); diff != "" {
		t.Errorf("the loaded applications differ from resolve's entries "+
			"(-selected +loaded):\n%s", diff)
	}
}
