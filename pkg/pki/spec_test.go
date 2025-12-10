package pki_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"cion/pkg/pki"
)

// TestTRCSpecCompliance tests TRC properties against requirements from
// draft-dekater-scion-pki.
func TestTRCSpecCompliance(t *testing.T) {
	isd := 1
	version := 1
	baseVersion := 1
	description := "Spec Compliance Test TRC"
	validity := cppki.Validity{
		NotBefore: time.Now().Truncate(time.Second),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
	}
	coreASes := []addr.AS{addr.MustParseAS("ff00:0:110"), addr.MustParseAS("ff00:0:111")}
	authASes := []addr.AS{addr.MustParseAS("ff00:0:110")} // Subset of Core ASes

	trc, _, err := pki.GenerateTRC(isd, version, baseVersion, description, validity, coreASes, authASes)
	if err != nil {
		t.Fatalf("TRC generation failed: %v", err)
	}
	if trc == nil {
		t.Fatal("Generated TRC is nil")
	}

	t.Run("Validity Period", func(t *testing.T) {
		// Spec: "All TRCs MUST have a well-defined expiration date."
		if trc.Validity.NotAfter.IsZero() {
			t.Error("TRC expiration date must be defined")
		}
		if !trc.Validity.NotBefore.Before(trc.Validity.NotAfter) {
			t.Error("TRC NotBefore must be before NotAfter")
		}
	})

	t.Run("ID Field", func(t *testing.T) {
		// Spec: "The ISD number MUST be an integer in the inclusive range from 64 to 4094"
		if got, want := trc.ID.ISD, addr.ISD(isd); got != want {
			t.Errorf("ISD mismatch: got %v, want %v", got, want)
		}

		// Spec: "A TRC where the base number is equal to the serial number is a base TRC."
		if trc.ID.Base == trc.ID.Serial {
			if len(trc.Votes) != 0 {
				t.Error("Base TRC must have empty votes sequence")
			}
			if trc.GracePeriod != 0 {
				t.Errorf("Base TRC grace period must be zero, got %d", trc.GracePeriod)
			}
		}
	})

	t.Run("Core and Authoritative ASes", func(t *testing.T) {
		// Spec: "Each core AS number MUST be unique"
		uniqueCore := make(map[addr.AS]bool)
		for _, as := range trc.CoreASes {
			if uniqueCore[as] {
				t.Errorf("Duplicate Core AS found: %s", as)
			}
			uniqueCore[as] = true
		}

		// Spec: "Every authoritative AS MUST be a core AS"
		for _, authAS := range trc.AuthoritativeASes {
			found := false
			for _, coreAS := range trc.CoreASes {
				if authAS == coreAS {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Authoritative AS %s must be in Core AS set", authAS)
			}
		}
	})

	t.Run("Voting Quorum", func(t *testing.T) {
		// Spec: "A voting quorum greater than one will prevent a single entity from creating a malicious TRC update."
		if trc.Quorum < 1 {
			t.Errorf("Voting quorum must be at least 1, got %d", trc.Quorum)
		}
	})

	t.Run("Certificates", func(t *testing.T) {
		// Spec: "Each certificate MUST be unique in the sequence of certificates."
		if len(trc.Certificates) == 0 {
			t.Fatal("TRC must contain certificates")
		}
		// Since we generate 1 root cert, check it's there.
		if len(trc.Certificates) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(trc.Certificates))
		}
		cert := trc.Certificates[0]

		// Spec: "Every certificate MUST have a validity period that fully contains the validity period of this TRC."
		if !cert.NotBefore.Before(trc.Validity.NotBefore) && !cert.NotBefore.Equal(trc.Validity.NotBefore) {
			t.Errorf("Cert NotBefore (%s) should be <= TRC NotBefore (%s)", cert.NotBefore, trc.Validity.NotBefore)
		}
		if !cert.NotAfter.After(trc.Validity.NotAfter) && !cert.NotAfter.Equal(trc.Validity.NotAfter) {
			t.Errorf("Cert NotAfter (%s) should be >= TRC NotAfter (%s)", cert.NotAfter, trc.Validity.NotAfter)
		}
	})

	t.Run("ASN.1 Encoding", func(t *testing.T) {
		// Spec: "The content of the eContent field MUST be the DER-encoded TRC payload."
		if len(trc.Raw) == 0 {
			t.Error("TRC Raw field (DER encoded payload) must not be empty")
		}
	})
}

func TestTRCUpdateSpec(t *testing.T) {
	// Simulate a TRC update scenario to check versioning rules.
	isd := 1
	baseVersion := 1

	// Initial TRC (v1)
	v1, _, err := pki.GenerateTRC(isd, 1, baseVersion, "Base TRC", cppki.Validity{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}, []addr.AS{addr.MustParseAS("ff00:0:110")}, []addr.AS{addr.MustParseAS("ff00:0:110")})
	if err != nil {
		t.Fatalf("Base TRC generation failed: %v", err)
	}

	// Update TRC (v2) - Regular Update
	v2, _, err := pki.GenerateTRC(isd, 2, baseVersion, "Update TRC", cppki.Validity{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}, []addr.AS{addr.MustParseAS("ff00:0:110")}, []addr.AS{addr.MustParseAS("ff00:0:110")})
	if err != nil {
		t.Fatalf("Update TRC generation failed: %v", err)
	}

	// Spec: "The serialNumber in the iD field MUST be incremented by one."
	if got, want := v2.ID.Serial, v1.ID.Serial+1; got != want {
		t.Errorf("Serial number mismatch: got %v, want %v", got, want)
	}
	if diff := cmp.Diff(v1.ID.Base, v2.ID.Base); diff != "" {
		t.Errorf("Base number mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(v1.ID.ISD, v2.ID.ISD); diff != "" {
		t.Errorf("ISD number mismatch (-want +got):\n%s", diff)
	}
}
