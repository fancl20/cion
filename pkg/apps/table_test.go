package apps

import (
	"strings"
	"testing"
)

// namesOf lists the selected entries' names, in their order.
func namesOf(selected []Entry) []string {
	names := make([]string, 0, len(selected))
	for _, e := range selected {
		names = append(names, e.Name)
	}
	return names
}

// TestSelectInfers checks the unset regime, the zero-conf default: an
// entry loads whose role bounds hold, whose requirements load, whose
// required arguments are present, and whose paired method is the selected
// one — the port's default serving hosts, its zero refusal serving none,
// the portal method bringing its console.
func TestSelectInfers(t *testing.T) {
	serving := Arguments{Wireguard: WireguardArguments{HostPort: DefaultHostPort}}

	core, err := Select(nil, true, serving, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(namesOf(core), ","),
		"wireguard,coordination,egress,mihomo,voting,ping"; got != want {
		t.Errorf("the serving core's inference = %s, want %s", got, want)
	}

	leaf, err := Select(nil, false, serving, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(namesOf(leaf), ","),
		"wireguard,egress,mihomo,ping"; got != want {
		t.Errorf("the serving leaf's inference = %s, want %s", got, want)
	}

	refused, err := Select(nil, true, Arguments{}, "")
	if err != nil {
		t.Fatal(err)
	}
	// The refused host port refuses every application that needs it; the
	// voting application needs none, so the core still infers it — the
	// network onboards cores whatever it serves hosts.
	if got, want := strings.Join(namesOf(refused), ","), "voting,ping"; got != want {
		t.Errorf("the refused port's inference = %s, want %s alone", got, want)
	}

	for _, tc := range []struct {
		name      string
		args      Arguments
		admission string
		want      string
	}{
		{"the portal method", serving, "portal", "wireguard,coordination,egress,mihomo,voting,portal,ping"},
		{"the portal method serving no hosts", Arguments{}, "portal", "voting,portal,ping"},
		{"another method", serving, "cidrs", "wireguard,coordination,egress,mihomo,voting,ping"},
	} {
		selected, err := Select(nil, true, tc.args, tc.admission)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(namesOf(selected), ","); got != tc.want {
			t.Errorf("%s infers %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestSelectGiven checks the given regimes: the empty list loads none —
// the deliberate core — and a list loads exactly the named, in table
// order whatever order the list spells, a paired entry beside its method.
func TestSelectGiven(t *testing.T) {
	serving := Arguments{Wireguard: WireguardArguments{HostPort: DefaultHostPort}}

	none, err := Select([]string{}, true, Arguments{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("the empty list loaded %v, want the deliberate core", namesOf(none))
	}

	spelled, err := Select([]string{"mihomo", "egress", "wireguard"}, false, serving, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(namesOf(spelled), ","),
		"wireguard,egress,mihomo"; got != want {
		t.Errorf("the list %q selected %s, want table order %s",
			"mihomo,egress,wireguard", got, want)
	}

	core, err := Select([]string{"coordination", "wireguard"}, true, serving, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(namesOf(core), ","),
		"wireguard,coordination"; got != want {
		t.Errorf("the core's list selected %s, want %s", got, want)
	}

	console, err := Select([]string{"portal"}, true, Arguments{}, "portal")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(namesOf(console), ","), "portal"; got != want {
		t.Errorf("the portal method's list selected %s, want %s", got, want)
	}
}

// TestSelectRefuses checks the refusals, each naming the fix: an unknown
// name the residents, a role violation the role, a broken requirement the
// missing application, a named application whose required argument is
// refused the argument to give, and a paired entry without its method, or
// a method without its entry, the other half.
func TestSelectRefuses(t *testing.T) {
	serving := Arguments{Wireguard: WireguardArguments{HostPort: DefaultHostPort}}
	refusals := []struct {
		name      string
		list      []string
		core      bool
		args      Arguments
		admission string
		want      string
	}{
		{
			"an unknown name",
			[]string{"middlebox"}, true, serving, "",
			"the residents are wireguard, coordination, egress, mihomo, voting, portal",
		},
		{
			"the retired SOCKS application",
			[]string{"wireguard", "socks"}, true, serving, "",
			`unknown application "socks"`,
		},
		{
			"a role violation",
			[]string{"coordination", "wireguard"}, false, serving, "",
			"coordination, which requires the founding core",
		},
		{
			"voting on a leaf",
			[]string{"voting"}, false, serving, "",
			"voting, which requires the founding core",
		},
		{
			"the egress without its owner",
			[]string{"egress"}, true, serving, "",
			"egress, which requires wireguard beside it",
		},
		{
			"the mihomo application without the egress",
			[]string{"wireguard", "mihomo"}, true, serving, "",
			"mihomo, which requires egress beside it",
		},
		{
			"coordination without its owner",
			[]string{"coordination"}, true, serving, "",
			"requires wireguard beside it",
		},
		{
			"the named port refused",
			[]string{"wireguard"}, true, Arguments{}, "",
			"--wireguard.host-port is zero",
		},
		{
			"the console without its method",
			[]string{"portal"}, true, serving, "cidrs",
			"portal, which pairs with --trust.enroll-auth=portal",
		},
		{
			"the method without its console",
			[]string{"wireguard", "coordination"}, true, serving, "portal",
			"--trust.enroll-auth=portal pairs with the portal application",
		},
		{
			"the method on the deliberate core",
			[]string{}, true, serving, "portal",
			"--trust.enroll-auth=portal pairs with the portal application",
		},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select(tc.list, tc.core, tc.args, tc.admission)
			if err == nil {
				t.Fatal("the miscombination was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal = %q, want it to carry %q", err, tc.want)
			}
		})
	}
}
