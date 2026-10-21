package portal

import (
	"testing"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// newPortal builds a method over a fresh state directory.
func newPortal(t *testing.T) *Portal {
	t.Helper()
	return newPortalAt(t, t.TempDir())
}

// newPortalAt builds a method over the state directory.
func newPortalAt(t *testing.T, state string) *Portal {
	t.Helper()
	p, err := New(Config{State: state})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// enrollment is a node's first-issuance facts for the subject key.
func enrollment(claim, key string) enrollauth.AdmissionFacts {
	return enrollauth.AdmissionFacts{
		Boundary: enrollauth.BoundaryEnrollment,
		Keys:     []string{key},
		Claim:    mustIA(claim),
	}
}

// registration is a host's registration facts for the machine and node
// keys, carrying the credential.
func registration(machine, node, credential string) enrollauth.AdmissionFacts {
	return enrollauth.AdmissionFacts{
		Boundary:   enrollauth.BoundaryRegistration,
		Keys:       []string{machine, node},
		Credential: credential,
	}
}
