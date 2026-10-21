package services

import (
	"testing"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// TestLoadEnrollAuth checks the selector: every method builds — the portal
// under its bare name and with an empty spec alike — the run function
// present exactly for the methods with loops of their own and the operator
// surface for the portal alone, and the malformed specs are refused here —
// at the boot, not the first joiner.
func TestLoadEnrollAuth(t *testing.T) {
	auth, run, err := loadEnrollAuth("cidrs=192.0.2.0/24", "", "")
	if err != nil {
		t.Fatalf("loading the cidrs method: %v", err)
	}
	if auth == nil {
		t.Error("the cidrs method built no authorizer")
	}
	if run != nil {
		t.Error("the cidrs method reported loops it does not have")
	}

	auth, run, err = loadEnrollAuth("telegram=-1002147483647:7481532:AAFtoken",
		"", t.TempDir())
	if err != nil {
		t.Fatalf("loading the telegram method: %v", err)
	}
	if auth == nil {
		t.Error("the telegram method built no authorizer")
	}
	if run == nil {
		t.Error("the telegram method built no poll loop")
	}

	for _, spec := range []string{"portal", "portal="} {
		auth, run, err = loadEnrollAuth(spec, "", t.TempDir())
		if err != nil {
			t.Fatalf("loading %q: %v", spec, err)
		}
		if _, ok := auth.(enrollauth.Operator); !ok {
			t.Errorf("%q built %T, want an operator surface", spec, auth)
		}
		if run == nil {
			t.Errorf("%q built no sweep loop", spec)
		}
	}

	for _, spec := range []string{
		"192.0.2.0/24",          // no method
		"carrier-pigeon=coop",   // unknown method
		"cidrs=",                // empty prefix list
		"cidrs=192.0.2.0/24,no", // unparsable prefix
		"telegram=chat:token",   // unparsable chat
		"telegram=-1002147483647",
		"telegram=-1002147483647:",
		"telegram=-1002147483647:token", // no state for the auth keys
		"portal=/admin",                 // the portal takes no spec
		"portals",                       // nor a near miss of its name
	} {
		if _, _, err := loadEnrollAuth(spec, "", ""); err == nil {
			t.Errorf("loading %q succeeded, want refusal", spec)
		}
	}
}

// TestAdmissionMethod checks the method a spec names for the pairing: the
// part before the first equals sign, the bare portal, and none for none.
func TestAdmissionMethod(t *testing.T) {
	for spec, want := range map[string]string{
		"":                        "",
		"portal":                  "portal",
		"cidrs=192.0.2.0/24":      "cidrs",
		"telegram=-1:7481532:AAF": "telegram",
	} {
		if got := admissionMethod(spec); got != want {
			t.Errorf("admissionMethod(%q) = %q, want %q", spec, got, want)
		}
	}
}
