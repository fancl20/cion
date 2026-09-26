package coordination

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// TestKeysPersist checks the load-or-create pattern: a first read
// generates and persists, the second meets the same key, and the two named
// keys stay themselves.
func TestKeysPersist(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateMachineKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateMachineKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(again) {
		t.Error("the machine key did not persist")
	}
	derp, err := LoadOrCreateDERPKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	derpAgain, err := LoadOrCreateDERPKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !derpAgain.Equal(derp) {
		t.Error("the DERP key did not persist")
	}
}

// TestCapabilityPin is the compatibility commitment's guard (ADR-0011):
// the service advertises exactly the vendored client protocol's current
// capability version, and a vendored upgrade that moves it moves this pin
// or fails here.
func TestCapabilityPin(t *testing.T) {
	if servedCapabilityVersion != tailcfg.CurrentCapabilityVersion {
		t.Fatalf("the served capability %d is not the vendored %d",
			servedCapabilityVersion, tailcfg.CurrentCapabilityVersion)
	}
}

// TestKeyEndpoint checks the client protocol's first exchange: the noise
// machine key served over plain TLS, the one fact a client cannot begin
// the handshake without.
func TestKeyEndpoint(t *testing.T) {
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: &memStore{}})
	addr := serveCoordination(t, a, tlsCfg)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (
			net.Conn, error) {

			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get(fmt.Sprintf("https://%s/key?v=%d",
		TestDomain, servedCapabilityVersion))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatal(err)
	}
	var keys tailcfg.OverTLSPublicKeyResponse
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("decoding the key response %q: %v", raw, err)
	}
	if keys.PublicKey != a.machineKey.Public() {
		t.Errorf("the served key = %v, want the application's machine key", keys.PublicKey)
	}
}

// TestDERPRelay checks the relay fallback: two clients on their node keys
// connect through the coordination endpoint's HTTPS identity, and the
// relay carries a datagram from one to the other by key.
func TestDERPRelay(t *testing.T) {
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: &memStore{}})
	addr := serveCoordination(t, a, tlsCfg)

	aliceKey := key.NewNode()
	bobKey := key.NewNode()
	// The clients retire with their connections, the helpers' own cleanup.
	alice, aliceW := derpClientFor(t, addr, roots, aliceKey)
	bob, _ := derpClientFor(t, addr, roots, bobKey)

	// Bob's receives land in a channel the delivery loop below reads.
	received := make(chan derp.ReceivedPacket, 16)
	go func() {
		for {
			msg, err := bob.Recv()
			if err != nil {
				return
			}
			if pkt, ok := msg.(derp.ReceivedPacket); ok {
				received <- pkt
			}
		}
	}()

	// The relay carries the packet between connected clients. The first
	// send can race the server's reading of the destination's client key —
	// the same race the protocol's own clients cover with their send
	// retries — so the sender retries until the delivery lands.
	packet := []byte("over the relay")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := alice.Send(bobKey.Public(), packet); err != nil {
			t.Fatalf("sending over the relay: %v", err)
		}
		// The frame the send wrote waits in the buffer for the flush the
		// protocol's own HTTP wrapper would do.
		if err := aliceW.Flush(); err != nil {
			t.Fatal(err)
		}
		select {
		case pkt := <-received:
			if pkt.Source != aliceKey.Public() {
				t.Errorf("the relayed packet's source = %v, want the sender's", pkt.Source)
			}
			if string(pkt.Data) != string(packet) {
				t.Errorf("the relayed packet = %q, want %q", pkt.Data, packet)
			}
			return
		case <-time.After(50 * time.Millisecond):
			continue
		}
	}
	t.Fatal("the relay never delivered the packet")
}

// derpClientFor connects one relay client over the endpoint's TLS
// identity, by the protocol's own upgrade, keyed by its node key. The
// returned writer is the connection's buffered writer, which the caller
// flushes after each send — the flush the protocol's own HTTP wrapper
// does.
func derpClientFor(t *testing.T, addr string, roots *x509.CertPool,
	nodeKey key.NodePrivate) (*derp.Client, *bufio.Writer) {

	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    roots,
		ServerName: TestDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := "GET /derp HTTP/1.1\r\nHost: " + TestDomain +
		"\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || status == "" {
		t.Fatalf("reading the upgrade response: %v %q", err, status)
	}
	if want := "HTTP/1.1 101"; len(status) < len(want) || status[:len(want)] != want {
		body, _ := io.ReadAll(io.LimitReader(br, 4096))
		t.Fatalf("the relay upgrade answered %q %q", status, body)
	}
	// The rest of the 101's headers, then the relay's own framing.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	brw := bufio.NewReadWriter(br, bufio.NewWriter(conn))
	client, err := derp.NewClient(nodeKey, conn, brw, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// The frames the client wrote at construction wait in the buffer for
	// the flush the protocol's own HTTP wrapper would do.
	if err := brw.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return client, brw.Writer
}
