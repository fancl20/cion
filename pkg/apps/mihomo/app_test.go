package mihomo

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
)

const controlURL = "https://cion.example"

// fetch answers one GET /mihomo against the topic and returns the body.
func fetch(t *testing.T, a *App) string {
	t.Helper()
	rec := httptest.NewRecorder()
	a.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mihomo", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /mihomo = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	return rec.Body.String()
}

// node is one directory node of the view the tests publish.
func node(ia, slice string) bus.TailnetNode {
	n := bus.TailnetNode{IA: addr.MustParseIA(ia)}
	if slice != "" {
		n.Slice = netip.MustParsePrefix(slice)
	}
	return n
}

// TestProviderListsTheExits checks the document: one instance per node of
// the topic's last view holding a slice, the node's own among them, in the
// view's order, each field in its place — the exit's serving address, a
// state directory derived from its ISD-AS, IPv4 alone, and the control
// URL.
func TestProviderListsTheExits(t *testing.T) {
	topic := &bus.Topic[bus.TailnetState]{}
	a := New(Config{Tailnet: topic, ControlURL: controlURL})
	topic.Publish(bus.NewTailnetState(netip.MustParsePrefix("100.64.1.0/24"), []bus.TailnetNode{
		node("1-ff00:0:111", "100.64.2.0/24"),
		node("1-ff00:0:110", "100.64.1.0/24"),
		node("1-ff00:0:112", ""),
	}, nil))

	want := `{"proxies":[` +
		`{"name":"1-ff00:0:110","type":"tailscale","control-url":"https://cion.example",` +
		`"exit-node":"100.64.1.1","state-dir":"cion/1-ff00_0_110","udp":true,"ip-version":"ipv4"},` +
		`{"name":"1-ff00:0:111","type":"tailscale","control-url":"https://cion.example",` +
		`"exit-node":"100.64.2.1","state-dir":"cion/1-ff00_0_111","udp":true,"ip-version":"ipv4"}]}`
	if diff := cmp.Diff(want, fetch(t, a)); diff != "" {
		t.Errorf("the provider (-want +got):\n%s", diff)
	}
}

// TestProviderStateDirsHold checks each instance's state directory holds
// across fetches while the exits come and go, so a refetch keeps every
// instance's login.
func TestProviderStateDirsHold(t *testing.T) {
	topic := &bus.Topic[bus.TailnetState]{}
	a := New(Config{Tailnet: topic, ControlURL: controlURL})
	dirs := func() map[string]string {
		raw := fetch(t, a)
		var doc provider
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("decoding %s: %v", raw, err)
		}
		got := make(map[string]string, len(doc.Proxies))
		for _, p := range doc.Proxies {
			got[p.Name] = p.StateDir
		}
		return got
	}

	topic.Publish(bus.NewTailnetState(netip.Prefix{}, []bus.TailnetNode{
		node("1-ff00:0:110", "100.64.1.0/24"),
		node("1-ff00:0:111", "100.64.2.0/24"),
	}, nil))
	first := dirs()
	topic.Publish(bus.NewTailnetState(netip.Prefix{}, []bus.TailnetNode{
		node("1-ff00:0:100", "100.64.3.0/24"),
		node("1-ff00:0:111", "100.64.2.0/24"),
		node("1-ff00:0:110", "100.64.1.0/24"),
	}, nil))
	second := dirs()

	want := map[string]string{
		"1-ff00:0:110": "cion/1-ff00_0_110",
		"1-ff00:0:111": "cion/1-ff00_0_111",
	}
	if diff := cmp.Diff(want, first); diff != "" {
		t.Errorf("the first fetch's state directories (-want +got):\n%s", diff)
	}
	want["1-ff00:0:100"] = "cion/1-ff00_0_100"
	if diff := cmp.Diff(want, second); diff != "" {
		t.Errorf("the second fetch's state directories (-want +got):\n%s", diff)
	}
}

// TestProviderEmptyBeforeTheFirstEvent checks the document before the
// tailnet topic's first event: a list of none.
func TestProviderEmptyBeforeTheFirstEvent(t *testing.T) {
	a := New(Config{Tailnet: &bus.Topic[bus.TailnetState]{}, ControlURL: controlURL})
	if diff := cmp.Diff(`{"proxies":[]}`, fetch(t, a)); diff != "" {
		t.Errorf("the provider before the first event (-want +got):\n%s", diff)
	}
}

// TestRunServesTheBorrowedListener checks Run: it borrows port 80, serves
// the provider on the listener until its context ends, and returns nil.
func TestRunServesTheBorrowedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ports := make(chan uint16, 1)
	a := New(Config{
		Listen: func(_ context.Context, port uint16) (net.Listener, error) {
			ports <- port
			return ln, nil
		},
		Tailnet:    &bus.Topic[bus.TailnetState]{},
		ControlURL: controlURL,
	})
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- a.Run(ctx) }()
	t.Cleanup(cancel)

	resp, err := http.Get("http://" + ln.Addr().String() + "/mihomo")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != `{"proxies":[]}` {
		t.Errorf("the served provider = %q, %v", body, err)
	}
	if got := <-ports; got != 80 {
		t.Errorf("Run borrowed port %d, want 80", got)
	}

	cancel()
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("Run = %v, want nil once its context ended", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return once its context ended")
	}
	if conn, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		_ = conn.Close()
		t.Error("the listener still accepts after Run returned")
	}
}

// TestRunEndsWhileWaitingForTheListener checks a context ending while the
// listener waits for the node's own address: Run returns nil, having served
// nothing.
func TestRunEndsWhileWaitingForTheListener(t *testing.T) {
	a := New(Config{
		Listen: func(ctx context.Context, _ uint16) (net.Listener, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Tailnet:    &bus.Topic[bus.TailnetState]{},
		ControlURL: controlURL,
	})
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- a.Run(ctx) }()
	cancel()
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return once its context ended")
	}
}

// TestRunReportsAFailedBorrow checks a listener the borrow could not bind
// while the context stands: Run returns the failure.
func TestRunReportsAFailedBorrow(t *testing.T) {
	refused := errors.New("the port is taken")
	a := New(Config{
		Listen:     func(context.Context, uint16) (net.Listener, error) { return nil, refused },
		Tailnet:    &bus.Topic[bus.TailnetState]{},
		ControlURL: controlURL,
	})
	if err := a.Run(t.Context()); !errors.Is(err, refused) {
		t.Errorf("Run = %v, want the borrow's failure", err)
	}
}
