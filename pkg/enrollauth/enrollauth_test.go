package enrollauth

import (
	"testing"
)

// TestLoad checks the selector: both methods build, the run function present
// exactly for the method with loops of its own, and the malformed specs are
// refused here — at the boot, not the first joiner.
func TestLoad(t *testing.T) {
	auth, run, err := Load("cidrs=192.0.2.0/24", LoadOptions{})
	if err != nil {
		t.Fatalf("loading the cidrs method: %v", err)
	}
	if auth == nil {
		t.Error("the cidrs method built no authorizer")
	}
	if run != nil {
		t.Error("the cidrs method reported loops it does not have")
	}

	auth, run, err = Load("telegram=-1002147483647:7481532:AAFtoken", LoadOptions{})
	if err != nil {
		t.Fatalf("loading the telegram method: %v", err)
	}
	if auth == nil {
		t.Error("the telegram method built no authorizer")
	}
	if run == nil {
		t.Error("the telegram method built no poll loop")
	}

	for _, spec := range []string{
		"192.0.2.0/24",          // no method
		"carrier-pigeon=coop",   // unknown method
		"cidrs=",                // empty prefix list
		"cidrs=192.0.2.0/24,no", // unparsable prefix
		"telegram=chat:token",   // unparsable chat
		"telegram=-1002147483647",
		"telegram=-1002147483647:",
	} {
		if _, _, err := Load(spec, LoadOptions{}); err == nil {
			t.Errorf("loading %q succeeded, want refusal", spec)
		}
	}
}
