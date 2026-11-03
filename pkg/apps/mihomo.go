package apps

import (
	"fmt"
	"net/url"

	"github.com/fancl20/cion/pkg/apps/egress"
	"github.com/fancl20/cion/pkg/apps/mihomo"
)

// mihomoEntry is the mihomo application: the mihomo proxy provider each node
// serves its hosts at its own address, one tailnet client instance per exit.
// Any node loads it beside the egress, whose listener it borrows.
var mihomoEntry = Entry{
	Name:     "mihomo",
	Requires: []string{"egress"},
	New:      newMihomo,
}

// newMihomo assembles the provider beside the egress whose listener it
// borrows, the exits read from the tailnet topic and every instance logging
// in against the founding core. The requirement's check has already made the
// missing egress a refused boot, and table order has already constructed it.
func newMihomo(env *Environment, loaded []Loaded) (Application, error) {
	eg := AppOf(loaded, "egress").(*egress.App)
	controlURL, err := mihomoControlURL(env)
	if err != nil {
		return nil, err
	}
	return mihomo.New(mihomo.Config{
		Listen:     eg.Listen,
		Tailnet:    env.Bus.Tailnet(),
		ControlURL: controlURL,
	}), nil
}

// mihomoControlURL returns the coordination server the instances log in
// against: the founding core's HTTPS origin, or the origin of the harness's
// relay placement where it stands, for a leaf's HTTPS origin lacks the port
// the placement binds.
func mihomoControlURL(env *Environment) (string, error) {
	if env.Relay.URL == "" {
		return env.HTTPSOrigin, nil
	}
	relay, err := url.Parse(env.Relay.URL)
	if err != nil {
		return "", fmt.Errorf("parsing the relay URL: %w", err)
	}
	return (&url.URL{Scheme: relay.Scheme, Host: relay.Host}).String(), nil
}
