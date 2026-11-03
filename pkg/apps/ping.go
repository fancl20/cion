package apps

import (
	"github.com/fancl20/cion/pkg/apps/ping"
)

// pingEntry is the ping application's place in the table: the network's
// probe, measuring the paths the node's picks ask it to over the node bus.
// Every node loads it, the zero-conf default; a node whose list leaves it
// out picks by the interface-down signals and declared delays alone.
var pingEntry = Entry{
	Name: "ping",
	New: func(env *Environment, _ []Loaded) (Application, error) {
		return ping.NewResident(ping.ResidentConfig{Bus: env.Bus, NewConn: env.NewConn})
	},
}
