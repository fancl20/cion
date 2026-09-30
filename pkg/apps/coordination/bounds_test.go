package coordination

import (
	"bytes"
	"encoding/binary"
	"encoding/json/v2"
	"io"
	"net/http"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"

	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
)

// streamMap opens one streaming map request over the noise channel and reads
// its first frame — the full map every streaming conversation starts with.
func streamMap(t *testing.T, client *http.Client,
	node key.NodePrivate) (io.ReadCloser, *tailcfg.MapResponse) {

	t.Helper()
	req := tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  node.Public(),
		Compress: "zstd",
		Stream:   true,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post("https://"+TestDomain+"/machine/map",
		"application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the streaming map request: %v", err)
	}
	var size [4]byte
	if _, err := io.ReadFull(resp.Body, size[:]); err != nil {
		t.Fatalf("reading the frame size: %v", err)
	}
	frame := make([]byte, binary.LittleEndian.Uint32(size[:]))
	if _, err := io.ReadFull(resp.Body, frame); err != nil {
		t.Fatalf("reading the frame: %v", err)
	}
	decoded, err := zstdframe.AppendDecode(nil, frame)
	if err != nil {
		t.Fatalf("decoding the frame: %v", err)
	}
	var out tailcfg.MapResponse
	if err := json.Unmarshal(decoded, &out); err != nil {
		t.Fatalf("decoding the map: %v", err)
	}
	return resp.Body, &out
}

// TestMapStreamBound checks the stream bound: an open map stream holds one
// of the bounded set and releases it when the stream closes, and past the
// bound the map answers one full map and closes the stream — the protocol's
// own degradation, no error, the client's polling carrying the rest.
func TestMapStreamBound(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: store})
	addr := serveCoordination(t, a, tlsCfg)
	client := noiseHTTP(t, addr, roots, a.machineKey.Public())
	host := key.NewNode()
	if _, status := register(t, client, host, ""); status != http.StatusOK {
		t.Fatalf("the registration status = %d, want 200", status)
	}

	// An open stream holds one of the set, and releases it when the stream
	// closes.
	body, netmap := streamMap(t, client, host)
	if len(netmap.Node.Addresses) != 1 || netmap.Node.Key != host.Public() {
		t.Fatalf("the streamed map = %+v, want the host's own", netmap.Node)
	}
	if held := len(a.mapStreams); held != 1 {
		t.Fatalf("the bounded set holds %d streams, want the one", held)
	}
	_ = body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(a.mapStreams) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if held := len(a.mapStreams); held != 0 {
		t.Fatal("a closed stream kept its hold on the bounded set")
	}

	// Past the bound the map answers one full map and closes the stream.
	for i := 0; i < maxMapStreams; i++ {
		a.mapStreams <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < maxMapStreams; i++ {
			<-a.mapStreams
		}
	})
	body, netmap = streamMap(t, client, host)
	if len(netmap.Node.Addresses) != 1 || netmap.Node.Key != host.Public() {
		t.Fatalf("the degraded map = %+v, want the one full map", netmap.Node)
	}
	rest := make(chan []byte, 1)
	go func() {
		raw, _ := io.ReadAll(body)
		rest <- raw
	}()
	select {
	case raw := <-rest:
		if len(raw) != 0 {
			t.Errorf("the closed stream carried %d bytes past the map, want none", len(raw))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream past the bound never closed")
	}
}

// TestConversationBound checks the conversation bound: the application
// counts its served noise conversations, and past the bound the upgrade
// refuses before the handshake begins.
func TestConversationBound(t *testing.T) {
	store := &dbtest.MemStore{}
	roots, tlsCfg := testCert(t)
	a := testApp(t, Config{Store: store})
	addr := serveCoordination(t, a, tlsCfg)

	// Two clients hold two conversations.
	_ = noiseHTTP(t, addr, roots, a.machineKey.Public())
	_ = noiseHTTP(t, addr, roots, a.machineKey.Public())
	if served := a.conversations.Load(); served != 2 {
		t.Fatalf("the served conversations = %d, want the two", served)
	}

	// Past the bound the upgrade refuses before the handshake begins.
	a.conversations.Store(maxConversations)
	conn, err := dialNoise(t, addr, roots, a.machineKey.Public())
	if err == nil {
		_ = conn.Close()
		t.Error("a conversation past the bound upgraded, want the refusal")
	}
}
