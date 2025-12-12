package controlplane

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/scionproto/scion/pkg/addr"
	cpb "github.com/scionproto/scion/pkg/proto/control_plane"
	crypto "github.com/scionproto/scion/pkg/proto/crypto"
	"google.golang.org/protobuf/proto"
)

// Server is the control plane HTTP/3 server.
type Server struct {
	server       *http3.Server
	addr         string
	controlPlane ControlPlane
}

// NewServer creates a new control plane server.
func NewServer(addr string, tlsConfig *tls.Config, cp ControlPlane) *Server {
	s := &Server{
		addr:         addr,
		controlPlane: cp,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/hello", handleHello)

	// Register HTTP/3 Protobuf handlers
	mux.HandleFunc(SegmentCreationServiceBeaconProcedure, s.handleBeacon)
	mux.HandleFunc(SegmentLookupServiceSegmentsProcedure, s.handleSegments)
	mux.HandleFunc(SegmentRegistrationServiceSegmentsRegistrationProcedure, s.handleSegmentsRegistration)
	mux.HandleFunc(TrustMaterialServiceChainsProcedure, s.handleChains)
	mux.HandleFunc(TrustMaterialServiceTRCProcedure, s.handleTRC)

	s.server = &http3.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	return s
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

// Close stops the server.
func (s *Server) Close() error {
	return s.server.Close()
}

type HelloResponse struct {
	Message string `json:"message"`
	Time    int64  `json:"time"`
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	resp := HelloResponse{
		Message: "Hello from CION Control Plane",
		Time:    time.Now().Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleBeacon implements the SegmentCreationService Beacon RPC.
func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Unmarshal request
	beaconReq := &cpb.BeaconRequest{}
	if err := proto.Unmarshal(reqBytes, beaconReq); err != nil {
		http.Error(w, "Failed to unmarshal BeaconRequest", http.StatusBadRequest)
		return
	}

	// Call core logic (ControlPlane)
	// For Proposal 0002, we primarily care about direct link establishment.
	// A Beacon from a direct neighbor could be interpreted as a 'hello'.
	// In a full implementation, this would involve processing and propagating PCBs.
	fmt.Printf("Received BeaconRequest from %s\n", s.controlPlane.GetLocalAddress())

	// TODO: Validate the incoming beacon for direct link context.
	// For now, just acknowledge.

	// Marshal and send empty response
	respBytes, err := proto.Marshal(&cpb.BeaconResponse{})
	if err != nil {
		http.Error(w, "Failed to marshal BeaconResponse", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/protobuf")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// handleSegments implements the SegmentLookupService Segments RPC.
func (s *Server) handleSegments(w http.ResponseWriter, r *http.Request) {
	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Unmarshal request
	segmentsReq := &cpb.SegmentsRequest{}
	if err := proto.Unmarshal(reqBytes, segmentsReq); err != nil {
		http.Error(w, "Failed to unmarshal SegmentsRequest", http.StatusBadRequest)
		return
	}

	// Call core logic (ControlPlane)
	// For Proposal 0002, this would primarily serve direct path segments.
	// In a full implementation, this would involve complex path lookup logic.

	srcIsdAs := segmentsReq.GetSrcIsdAs()
	dstIsdAs := segmentsReq.GetDstIsdAs()

	srcIA := addr.IA(srcIsdAs)
	dstIA := addr.IA(dstIsdAs)

	paths, err := s.controlPlane.GetPaths(r.Context(), SCIONAddress(srcIA.String()), SCIONAddress(dstIA.String()))
	if err != nil {
		http.Error(w, fmt.Sprintf("Path not found: %v", err), http.StatusNotFound)
		return
	}

	respSegments := make(map[int32]*cpb.SegmentsResponse_Segments)
	segmentsProto := make([]*cpb.PathSegment, len(paths))
	for i, p := range paths {
		// Convert internal PathSegment to protobuf PathSegment
		// This is a simplified conversion, actual PathSegment has more fields.
		// The cpb.PathSegment expects SegmentInfo and AsEntries.
		// For direct links, we can construct a minimal PathSegment.

		// For now, let's create a dummy segment info and a single AS entry.
		segmentInfo := &cpb.SegmentInformation{
			Timestamp: time.Now().Unix(),
			SegmentId: 1, // Dummy ID
		}
		segmentInfoBytes, err := proto.Marshal(segmentInfo)
		if err != nil {
			http.Error(w, "Failed to marshal SegmentInformation", http.StatusInternalServerError)
			return
		}

		asEntry := &cpb.ASEntry{
			// In a real implementation, this would be signed and contain proper HopFields.
			// For PoC direct link, we can just put minimal info.
			Signed: &crypto.SignedMessage{
				HeaderAndBody: []byte(fmt.Sprintf("Direct Link to %s", p.Segments[0].ID)),
				Signature:     []byte("dummy_signature"),
			},
		}

		segmentsProto[i] = &cpb.PathSegment{
			SegmentInfo: segmentInfoBytes,
			AsEntries:   []*cpb.ASEntry{asEntry},
		}
	}
	respSegments[int32(cpb.SegmentType_SEGMENT_TYPE_UP)] = &cpb.SegmentsResponse_Segments{
		Segments: segmentsProto,
	}

	// Marshal and send response
	resp := &cpb.SegmentsResponse{Segments: respSegments}
	respBytes, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal SegmentsResponse", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/protobuf")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// handleSegmentsRegistration implements the SegmentRegistrationService SegmentsRegistration RPC.
func (s *Server) handleSegmentsRegistration(w http.ResponseWriter, r *http.Request) {
	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Unmarshal request
	segmentsRegReq := &cpb.SegmentsRegistrationRequest{}
	if err := proto.Unmarshal(reqBytes, segmentsRegReq); err != nil {
		http.Error(w, "Failed to unmarshal SegmentsRegistrationRequest", http.StatusBadRequest)
		return
	}

	// Call core logic (ControlPlane)
	// For Proposal 0002, registration is minimal (primarily for direct links).
	// In a full implementation, this would involve storing path segments.

	// Marshal and send empty response
	respBytes, err := proto.Marshal(&cpb.SegmentsRegistrationResponse{})
	if err != nil {
		http.Error(w, "Failed to marshal SegmentsRegistrationResponse", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/protobuf")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// handleChains implements the TrustMaterialService Chains RPC.
func (s *Server) handleChains(w http.ResponseWriter, r *http.Request) {
	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Unmarshal request
	chainsReq := &cpb.ChainsRequest{}
	if err := proto.Unmarshal(reqBytes, chainsReq); err != nil {
		http.Error(w, "Failed to unmarshal ChainsRequest", http.StatusBadRequest)
		return
	}

	// Extract ISD and AS from IsdAs
	parsedIA := addr.IA(chainsReq.GetIsdAs())
	isd := int(parsedIA.ISD())
	as := int(parsedIA.AS())

	cert, err := s.controlPlane.GetCertificate(r.Context(), isd, as)
	if err != nil {
		http.Error(w, fmt.Sprintf("Certificate not found: %v", err), http.StatusNotFound)
		return
	}

	// For simplicity, we return a single chain with just the AS cert.
	// In a real scenario, this would involve the AS certificate and its issuing CA certificate.
	resp := &cpb.ChainsResponse{
		Chains: []*cpb.Chain{
			{
				AsCert: cert.Raw,
				CaCert: []byte{}, // No CA cert for self-signed or direct AS cert in PoC
			},
		},
	}

	// Marshal and send response
	respBytes, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal ChainsResponse", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/protobuf")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// handleTRC implements the TrustMaterialService TRC RPC.
func (s *Server) handleTRC(w http.ResponseWriter, r *http.Request) {
	// Check method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Unmarshal request
	rrcReq := &cpb.TRCRequest{}
	if err := proto.Unmarshal(reqBytes, rrcReq); err != nil {
		http.Error(w, "Failed to unmarshal TRCRequest", http.StatusBadRequest)
		return
	}

	// Call core logic (ControlPlane)
	trc, err := s.controlPlane.GetTRC(r.Context(), int(rrcReq.GetIsd()), int(rrcReq.GetSerial()))
	if err != nil {
		http.Error(w, fmt.Sprintf("TRC not found: %v", err), http.StatusNotFound)
		return
	}

	trcBytes, err := trc.Encode() // Assuming cppki.TRC has an Encode method that returns []byte
	if err != nil {
		http.Error(w, "Failed to encode TRC", http.StatusInternalServerError)
		return
	}

	// Marshal and send response
	resp := &cpb.TRCResponse{Trc: trcBytes}
	respBytes, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal TRCResponse", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/protobuf")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}
