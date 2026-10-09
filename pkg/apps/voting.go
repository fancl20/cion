package apps

import (
	"github.com/fancl20/cion/pkg/apps/voting"
)

// votingEntry is the TRC voting application's place in the table: the
// founding core's surface for the TRC updates the cores of its ISD submit,
// every submission handed to the control plane's decision. The founding
// core alone loads it, the one node whose control plane decides.
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
