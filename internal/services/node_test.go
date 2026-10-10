package services

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// setupFounderNode assembles a founding core from the minimal run arguments
// with the mutation applied, its static-file identity minted, on a loopback
// host of the package's own: the founder binds its fixed endpoint and
// rendezvous ports on the control host. The group releases it at cleanup.
func setupFounderNode(t *testing.T, mutate func(*NodeConfig)) *node {
	t.Helper()
	certFile, keyFile := mintCertFiles(t)
	cfg := nodeConfig()
	cfg.State = t.TempDir()
	cfg.Internal = "127.0.0.124:30044"
	cfg.Control = "127.0.0.124:30042"
	cfg.CertFile, cfg.KeyFile = certFile, keyFile
	mutate(&cfg)
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
	return n
}

// roleLoopNames returns the names of the role's loops, in the order start
// hands them to the group.
func roleLoopNames(n *node) []string {
	var names []string
	for _, l := range n.roleLoops {
		names = append(names, l.name)
	}
	return names
}

// TestSetupNodeConsumesResolution checks the phases hold what resolve built
// once: the trust service, the TRC decision, and the applications'
// environment hold the one authorizer instance, and the applications that
// load are the entries resolve selected.
func TestSetupNodeConsumesResolution(t *testing.T) {
	n := setupFounderNode(t, func(c *NodeConfig) { c.EnrollAuth = "cidrs=192.0.2.0/24" })

	auth := n.cfg.enrollAuth
	if auth == nil {
		t.Fatal("resolve built no authorizer")
	}
	trustService := n.services.TrustService
	decider := n.trcDecision.(*controlplane.TRCDecider)
	for holder, got := range map[string]enrollauth.AdmissionAuthorizer{
		"the trust service":             trustService.Authorizer,
		"the TRC decision":              decider.Authorizer,
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

// TestSetupFounderBuildsItsParts checks the founder's case of the role
// switch: the products the later phases take — no engine remote, a true
// nil, and the issuer, the TRC decision, and the WebPKI identity — and the
// role's loops, enrollment and rotation alone for a static-file identity
// and an unset policy.
func TestSetupFounderBuildsItsParts(t *testing.T) {
	n := setupFounderNode(t, func(*NodeConfig) {})
	if n.remote != nil {
		t.Errorf("the founder's engine remote = %v, want none", n.remote)
	}
	if n.issuer == nil || n.trcDecision == nil || n.certMgr == nil || n.webPKI == nil {
		t.Errorf("the founder's products: issuer %v, decision %v, identity %v, TLS %v; "+
			"want every one", n.issuer, n.trcDecision, n.certMgr, n.webPKI)
	}
	if diff := cmp.Diff([]string{"enrollment", "rotation watch"}, roleLoopNames(n)); diff != "" {
		t.Errorf("the founder's loops (-want +got):\n%s", diff)
	}
}

// TestSetupFounderRunsTheAuthorizer checks the founder's loops under a
// selected method with loops of its own: the Telegram authorizer's poll
// joins them.
func TestSetupFounderRunsTheAuthorizer(t *testing.T) {
	n := setupFounderNode(t, func(c *NodeConfig) {
		c.EnrollAuth = "telegram=-1002147483647:7481532:AAFtoken"
	})
	want := []string{"enrollment", "rotation watch", "enrollment authorizer"}
	if diff := cmp.Diff(want, roleLoopNames(n)); diff != "" {
		t.Errorf("the founder's loops (-want +got):\n%s", diff)
	}
}
