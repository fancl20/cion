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

// GatewayPort is the SCION UDP port every gateway's mesh transport listens
// on (proposal 0006), so a peer's directory entry — ISD-AS, public key,
// underlay, subnet — is all a node needs to reach it.
const GatewayPort = 30045

// DirectoryPort is the SCION UDP port the core node's gateway application
// serves the peer directory on (proposal 0006).
const DirectoryPort = 30046
