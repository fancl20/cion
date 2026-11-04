// Package behavior holds the behavior labs: whole networks booted through
// the node's own assembly on the userspace fabric, run inside synctest
// bubbles at the daemon's own pacing, each asserting what the selection
// policy makes of the network across many windows — that a cut heals, that
// the link set settles, that every pair then reaches over its chosen path,
// the path the source's lease of the destination holds. The labs run without
// the race detector: a replay of virtual minutes to hours repeats code the
// e2e labs of internal/testnetwork already run under the detector, at
// several times the wall time.
//
// Beside the labs, benchmarks grade the same networks by the paths they
// serve: every pair's chosen path against the shortest paths the fabric's
// delays allow, the segment records no chosen path joins, and the links a
// single cut would need, once settled and through the network's answer to
// a link cut and restored, a delay raised or lowered, and a link's loss
// swept up and back down. They are skipped unless CION_BENCH is set, and
// each prints benchmark result lines on standard output for benchstat:
//
//	CION_BENCH=1 go test -run Bench -count=10 -v ./internal/testnetwork/behavior/
package behavior
