package apps

import "testing"

// TestMihomoControlURL checks the coordination server the provider's instances
// log in against: the founding core's HTTPS origin, or the origin of the
// harness's relay placement where it stands — a leaf's HTTPS origin lacks
// the placement's port — and a placement URL that does not parse refuses.
func TestMihomoControlURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  Environment
		want string
	}{
		{
			name: "the founding core's origin",
			env:  Environment{HTTPSOrigin: "https://core.example.org"},
			want: "https://core.example.org",
		},
		{
			name: "the harness's placement",
			env: Environment{
				HTTPSOrigin: "https://core.example.org",
				Relay:       RelayPlacement{URL: "https://127.0.0.1:4430/derp", IPv4: "127.0.0.1"},
			},
			want: "https://127.0.0.1:4430",
		},
	} {
		got, err := mihomoControlURL(&tc.env)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: the control URL = %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := mihomoControlURL(&Environment{Relay: RelayPlacement{URL: "https://[::1"}}); err == nil {
		t.Error("a placement URL that does not parse was accepted")
	}
}
