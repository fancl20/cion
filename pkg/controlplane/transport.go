// Package controlplane implements CION's control plane: discovery of directly
// connected neighbors, and the control endpoint that serves trust material
// RPCs over HTTP/3 (QUIC) riding the SCION network. The SCION socket and
// path resolution the endpoint and the peer clients ride live in the node's
// SCION library, pkg/scion, which this package consumes beside any
// application.
package controlplane

// EndpointPort is the SCION UDP port of the control endpoint. The port is
// fixed so that a node can reach a neighbor's endpoint knowing only the
// underlay address advertised in the discovery greeting.
const EndpointPort = 30044
