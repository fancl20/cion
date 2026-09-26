package coordination

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/zstdframe"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/controlplane"
)

// serveCoordination serves the application's handler on an externally
// assembled HTTPS server over the given certificate, bound on a free port —
// the node assembly's own shape (proposal 0023): the listener and the TLS
// identity the server's, the three surfaces the application's. The address
// is bound before the call returns, so a client may dial at once.
func serveCoordination(t *testing.T, a *App, tlsCfg *tls.Config) string {
	t.Helper()
	clone := tlsCfg.Clone()
	clone.NextProtos = []string{"http/1.1"}
	listener, err := tls.Listen("tcp",
		fmt.Sprintf("127.0.0.1:%d", freePort(t)), clone)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			// The listener's close is the shutdown's own act — the same
			// read the node's serving loop makes of the exit.
			if err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				t.Errorf("the coordination endpoint exited: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the coordination endpoint did not stop")
		}
	})
	return listener.Addr().String()
}

// noiseHTTP dials the vendored client transport — the same controlhttp the
// vendor's client rides — and wraps it in an HTTP client speaking HTTP/2
// over the noise channel, the protocol's own grammar.
func noiseHTTP(t *testing.T, addr string, roots *x509.CertPool,
	control key.MachinePublic) *http.Client {

	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	machine := key.NewMachine()
	mon, err := netmon.New(eventbus.New(), logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	dialer := &controlhttp.Dialer{
		Hostname:        "127.0.0.1",
		MachineKey:      machine,
		ControlKey:      control,
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		HTTPPort:        "none",
		HTTPSPort:       port,
		ExtraRootCAs:    roots,
		NetMon:          mon,
		Dialer: func(ctx context.Context, network, address string) (
			net.Conn, error) {

			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	conn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dialing the noise channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	transport := &http2.Transport{
		DialTLSContext: func(context.Context, string, string, *tls.Config) (
			net.Conn, error) {

			return conn, nil
		},
	}
	return &http.Client{Transport: transport}
}

// register posts one registration over the noise channel, returning the
// response and the HTTP status.
func register(t *testing.T, client *http.Client,
	node key.NodePrivate, credential string) (*tailcfg.RegisterResponse, int) {

	t.Helper()
	req := tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: node.Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: credential},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post("https://"+TestDomain+"/machine/register",
		"application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the registration request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out tailcfg.RegisterResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding the registration response: %v", err)
	}
	return &out, resp.StatusCode
}

// fetchMap posts one non-streaming map request over the noise channel and
// decodes the first frame.
func fetchMap(t *testing.T, client *http.Client,
	node key.NodePrivate) (*tailcfg.MapResponse, error) {

	t.Helper()
	req := tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  node.Public(),
		Compress: "zstd",
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post("https://"+TestDomain+"/machine/map",
		"application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the map request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("map status %d: %s", resp.StatusCode, body)
	}
	var size [4]byte
	if _, err := io.ReadFull(resp.Body, size[:]); err != nil {
		return nil, fmt.Errorf("reading the frame size: %w", err)
	}
	frame := make([]byte, binary.LittleEndian.Uint32(size[:]))
	if _, err := io.ReadFull(resp.Body, frame); err != nil {
		return nil, fmt.Errorf("reading the frame: %w", err)
	}
	decoded, err := zstdframe.AppendDecode(nil, frame)
	if err != nil {
		return nil, fmt.Errorf("decoding the frame: %w", err)
	}
	var out tailcfg.MapResponse
	if err := json.Unmarshal(decoded, &out); err != nil {
		return nil, fmt.Errorf("decoding the map: %w", err)
	}
	return &out, nil
}

// TestProtocolRegisterAndMap drives the client protocol's own transport
// end to end: the key fetch over TLS, the noise handshake, an open
// registration issuing the allocated address, and the map answering with
// the tailnet-holding netmap — the same conversation a tailnet client
// runs at login.
func TestProtocolRegisterAndMap(t *testing.T) {
	store := &memStore{}
	nodeEntry := testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820")
	nodeEntry.PublicKey = testHostKey(0x11)
	if err := store.Publish(context.Background(), nodeEntry); err != nil {
		t.Fatal(err)
	}
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: store})
	addr := serveCoordination(t, a, tlsCfg)

	client := noiseHTTP(t, addr, roots, a.machineKey.Public())
	host := key.NewNode()

	// An open registration completes the login on the spot.
	resp, status := register(t, client, host, "")
	if status != http.StatusOK {
		t.Fatalf("the open registration status = %d, want 200", status)
	}
	if !resp.MachineAuthorized || resp.AuthURL != "" {
		t.Fatalf("the registration response = %+v, want the machine authorized with no URL", resp)
	}

	// The registry holds the allocation.
	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Hosts) != 1 || directory.Hosts[0].Addr.String() != "100.64.1.2" {
		t.Fatalf("the registry holds %+v, want the allocated 100.64.1.2", directory.Hosts)
	}

	// The map answers with the tailnet.
	netmap, err := fetchMap(t, client, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(netmap.Node.Addresses) != 1 ||
		netmap.Node.Addresses[0].String() != "100.64.1.2/32" {
		t.Errorf("the map's addresses = %v", netmap.Node.Addresses)
	}
	if len(netmap.Peers) != 1 || netmap.Peers[0].Key != nodePublicOf(nodeEntry.PublicKey) {
		t.Errorf("the map's peers = %v, want the owning node", netmap.Peers)
	}
	if len(netmap.DERPMap.Regions) != 1 {
		t.Errorf("the map's DERP regions = %d, want the core's one", len(netmap.DERPMap.Regions))
	}

	// A re-registration is idempotent: the record answers, the address
	// holds, and the registry does not grow.
	if _, status := register(t, client, host, ""); status != http.StatusOK {
		t.Fatalf("the re-registration status = %d, want 200", status)
	}
	directory, _ = store.List(context.Background())
	if len(directory.Hosts) != 1 {
		t.Fatalf("the registry grew to %d hosts on a re-registration", len(directory.Hosts))
	}
}

// TestProtocolRegistrationVerdicts checks the seam's verdicts on the wire:
// pending refuses the request for the client's retry loop to carry, deny
// refuses it for good, and allow issues the entry — each with exactly the
// facts the exchange established.
func TestProtocolRegistrationVerdicts(t *testing.T) {
	store := &memStore{}
	if err := store.Publish(context.Background(),
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820")); err != nil {

		t.Fatal(err)
	}
	auth := &askAuthorizer{}
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: store, Authorizer: auth})
	addr := serveCoordination(t, a, tlsCfg)
	client := noiseHTTP(t, addr, roots, a.machineKey.Public())

	// Pending: refused, nothing recorded, and the client's own polling
	// carries the wait.
	auth.answer = controlplane.AdmissionAnswer{Admission: controlplane.AdmissionPending}
	if _, status := register(t, client, key.NewNode(), ""); status != http.StatusServiceUnavailable {
		t.Errorf("pending status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	if hosts := storeHosts(t, store); len(hosts) != 0 {
		t.Fatalf("a pending registration recorded %d hosts, want none", len(hosts))
	}

	// Deny: refused for good, nothing recorded.
	auth.answer = controlplane.AdmissionAnswer{Admission: controlplane.AdmissionDeny}
	if _, status := register(t, client, key.NewNode(), ""); status != http.StatusForbidden {
		t.Errorf("deny status = %d, want %d", status, http.StatusForbidden)
	}
	if hosts := storeHosts(t, store); len(hosts) != 0 {
		t.Fatalf("a denied registration recorded %d hosts, want none", len(hosts))
	}

	// Allow with a credential and a note: the facts carry the machine and
	// node keys, the source the TLS connection named, and the credential
	// the joiner presented; the entry records the note.
	auth.answer = controlplane.AdmissionAnswer{
		Admission: controlplane.AdmissionAllow,
		Note:      "telegram invitation",
	}
	invited := key.NewNode()
	if resp, status := register(t, client, invited, "cion-0123456789abcdef"); status != http.StatusOK {
		t.Fatalf("allow status = %d, want 200", status)
	} else if !resp.MachineAuthorized {
		t.Error("the allowed registration is not machine-authorized")
	}
	hosts := storeHosts(t, store)
	if len(hosts) != 1 {
		t.Fatalf("the registry holds %d hosts, want the one", len(hosts))
	}
	if hosts[0].Note != "telegram invitation" {
		t.Errorf("the entry's note = %q, want the plugin's", hosts[0].Note)
	}
	asks := auth.asks()
	if len(asks) != 3 {
		t.Fatalf("the seam was asked %d times, want 3", len(asks))
	}
	last := asks[2]
	if last.Boundary != controlplane.BoundaryRegistration {
		t.Errorf("the boundary = %v, want registration", last.Boundary)
	}
	if last.Credential != "cion-0123456789abcdef" {
		t.Errorf("the credential = %q, want the presented one", last.Credential)
	}
	if len(last.Keys) != 2 {
		t.Errorf("the facts carry %d keys, want the machine and node", len(last.Keys))
	}
	if !last.Source.IsValid() || last.Source.Addr() != ip("127.0.0.1") {
		t.Errorf("the source = %v, want the TLS connection's", last.Source)
	}
	if !last.Claim.IsZero() {
		t.Errorf("the claim = %v, want zero at registration", last.Claim)
	}
}

// TestProtocolMapRequiresRegistration checks the map refuses a key the
// registry holds no registration for.
func TestProtocolMapRequiresRegistration(t *testing.T) {
	store := &memStore{}
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: store})
	addr := serveCoordination(t, a, tlsCfg)
	client := noiseHTTP(t, addr, roots, a.machineKey.Public())
	if _, err := fetchMap(t, client, key.NewNode()); err == nil {
		t.Error("an unregistered key mapped, want refusal")
	}
}

// storeHosts reads the registry's hosts.
func storeHosts(t *testing.T, store *memStore) []wireguard.HostEntry {
	t.Helper()
	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return directory.Hosts
}
