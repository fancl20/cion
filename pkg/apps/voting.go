package apps

import (
	"github.com/fancl20/cion/pkg/apps/voting"
)

// votingEntry is the TRC voting application's place in the table: the
// founding core's surface for the cores of its ISD seeking voting power,
// every submission handed to the control plane's decision. The core role
// bounds it, and where the node's control plane decides nothing — every
// node but the founding core — its submissions are answered with the
// refusal.
var votingEntry = Entry{
	Name:     "voting",
	CoreOnly: true,
	New: func(env *Environment, _ []Loaded) (Application, error) {
		return voting.New(voting.Config{
			IA:                   env.IA,
			Decide:               env.TRCDecision,
			MountControlEndpoint: env.MountControlEndpoint,
		})
	},
}
