// Package controlplane implements the node core's control endpoint of
// ADR-0009: the drafts' services over HTTP/3 (QUIC) riding SCION paths —
// segment creation, registration, and lookup, trust material and chain
// renewal — and the drafts' service resolution beside them (control plane
// draft, Section 5), every protocol the core speaks the drafts' own. Peer
// control endpoints are named by service destination, resolved through the
// drafts' exchange wherever a stable underlay address is wanted; the SCION
// socket and path composition the endpoint and the peer clients ride live
// in the node's SCION library, pkg/scion, which this package consumes
// beside any application.
package controlplane

// EndpointPort is the SCION UDP port of the control endpoint — the socket
// registered as the control service, so a peer addressing the service
// destination reaches the endpoint beside whose services the drafts'
// resolution exchange answers.
const EndpointPort = 30044
