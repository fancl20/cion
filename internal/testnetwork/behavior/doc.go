// Package behavior holds the behavior labs: whole networks booted through
// the node's own assembly on the userspace fabric, run inside synctest
// bubbles at the daemon's own pacing, each asserting what the selection
// policy makes of the network across many windows — that a cut heals, that
// the link set settles. The labs run without the race detector: a replay of
// virtual minutes to hours repeats code the e2e labs of
// internal/testnetwork already run under the detector, at several times the
// wall time.
package behavior
