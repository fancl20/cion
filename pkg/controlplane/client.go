package controlplane

import (
	"strings"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
)

// Client implements the Interface by making RPC calls to a remote server.
type Client struct {
	control_planeconnect.SegmentCreationServiceClient
	control_planeconnect.TrustMaterialServiceClient
	control_planeconnect.SegmentRegistrationServiceClient
	control_planeconnect.SegmentLookupServiceClient
	control_planeconnect.ChainRenewalServiceClient
}

// NewClient creates a new control plane client.
func NewClient(clt connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		SegmentCreationServiceClient:     control_planeconnect.NewSegmentCreationServiceClient(clt, baseURL, opts...),
		TrustMaterialServiceClient:       control_planeconnect.NewTrustMaterialServiceClient(clt, baseURL, opts...),
		SegmentRegistrationServiceClient: control_planeconnect.NewSegmentRegistrationServiceClient(clt, baseURL, opts...),
		SegmentLookupServiceClient:       control_planeconnect.NewSegmentLookupServiceClient(clt, baseURL, opts...),
		ChainRenewalServiceClient:        control_planeconnect.NewChainRenewalServiceClient(clt, baseURL, opts...),
	}
}
