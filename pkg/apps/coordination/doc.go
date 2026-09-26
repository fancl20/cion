// Package coordination is the coordination application (ADR-0011, proposal
// 0022): the network's headscale, minimal by decision, served by the core
// alone beside the WireGuard application. It speaks the tailnet client
// protocol from vendored packages — the noise channel inside WebPKI HTTPS on
// the core's domain, registration behind the generalized admission seam, the
// netmap holding one peer — the host's node — and the DERP relay a client
// expects as its fallback path. Hosts are logins, not configuration edits:
// admission allocates the next free address in the owning node's slice of the
// tailnet range and records one registry entry that distributes by the
// directory every node already fetches.
package coordination
