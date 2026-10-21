package coordination

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// postRegisterClaiming drives one registration straight at the handler,
// carrying the hostinfo the client claims.
func postRegisterClaiming(t *testing.T, a *App, source string, machine key.MachinePrivate,
	node key.NodePrivate, hostinfo *tailcfg.Hostinfo) int {

	t.Helper()
	raw, err := json.Marshal(tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  node.Public(),
		Hostinfo: hostinfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/machine/register", bytes.NewReader(raw))
	r.RemoteAddr = source
	w := httptest.NewRecorder()
	a.handleRegister(w, r, machine.Public())
	return w.Code
}

// TestRegisterRecordsClaims checks a registration's claims about itself:
// the admitted entry records them, capped.
func TestRegisterRecordsClaims(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	auth := &askAuthorizer{answer: enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}}
	a := testApp(t, Config{Store: store, Authorizer: auth})
	long := strings.Repeat("é", claimCap) // two bytes a rune: the cap cuts between runes
	status := postRegisterClaiming(t, a, "203.0.113.5:41641", key.NewMachine(), key.NewNode(),
		&tailcfg.Hostinfo{Hostname: "lap\ntop", OS: long})
	if status != http.StatusOK {
		t.Fatalf("the registration status = %d, want 200", status)
	}
	capped := strings.Repeat("é", claimCap/2)
	hosts := storeHosts(t, store)
	if len(hosts) != 1 || hosts[0].Hostname != "laptop" || hosts[0].OS != capped {
		t.Errorf("the registry holds %+v, want the capped claims recorded", hosts)
	}
	if got := capClaim("a\x00b\xffc"); got != "abc" {
		t.Errorf("capClaim stripped to %q, want the control and invalid bytes gone", got)
	}
}

// streamMapAt opens one streaming map request straight at the handler and
// answers the recorder, the request's cancel, and a channel closing when
// the handler returns.
func streamMapAt(t *testing.T, a *App, machine key.MachinePrivate, node key.NodePrivate,
	hostinfo *tailcfg.Hostinfo) (*httptest.ResponseRecorder, context.CancelFunc, <-chan struct{}) {

	t.Helper()
	raw, err := json.Marshal(tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  node.Public(),
		Stream:   true,
		Hostinfo: hostinfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/machine/map", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleMap(w, r, machine.Public())
	}()
	return w, cancel, done
}

// waitFor waits until the condition holds, checking it every few
// milliseconds, and fails the test once the deadline passes first.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// TestRemoveHostClosesStream checks the release of a streaming host: it
// shows connected with its claims, and its release deletes the entry,
// forgets its presence, and closes its stream at the next re-read. The
// stream runs on the real clock: a map frame's encoder outlives the test
// in a process-wide pool, which a fake-time bubble must not own.
func TestRemoveHostClosesStream(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	auth := &askAuthorizer{answer: enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}}
	a := testApp(t, Config{Store: store, Authorizer: auth, MapResend: 10 * time.Millisecond})
	machine, node := key.NewMachine(), key.NewNode()
	if status := postRegisterClaiming(t, a, "203.0.113.5:41641", machine, node, nil); status != http.StatusOK {
		t.Fatalf("the registration status = %d, want 200", status)
	}

	w, cancel, done := streamMapAt(t, a, machine, node,
		&tailcfg.Hostinfo{Hostname: "laptop", OS: "linux"})
	defer cancel()
	waitFor(t, "the streaming host's presence", func() bool {
		return a.Presence()[nodeKeyOf(node.Public())].Connected
	})
	seen := a.Presence()[nodeKeyOf(node.Public())]
	if seen.Hostname != "laptop" || seen.OS != "linux" || seen.LastSeen.IsZero() {
		t.Fatalf("the streaming host's presence = %+v, want its claims and its sighting", seen)
	}

	if err := a.RemoveHost(t.Context(), nodeKeyOf(node.Public())); err != nil {
		t.Fatalf("releasing the host: %v", err)
	}
	if hosts := storeHosts(t, store); len(hosts) != 0 {
		t.Fatalf("the registry holds %+v after the release, want nothing", hosts)
	}
	if _, ok := a.Presence()[nodeKeyOf(node.Public())]; ok {
		t.Error("the released host's presence stays")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the released host's stream stayed open past the re-read")
	}
	if w.Code != http.StatusOK {
		t.Errorf("the stream answered %d before the release, want 200", w.Code)
	}
}

// TestRemoveHostFreesAddress checks what a release leaves behind: the freed
// address allocates to the next registration, and the released key's
// registration asks the seam again. The admission intervals pass in a
// fake-time bubble.
func TestRemoveHostFreesAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &dbtest.MemStore{}
		store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
		auth := &askAuthorizer{answer: enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}}
		a := testApp(t, Config{Store: store, Authorizer: auth})
		machine, node := key.NewMachine(), key.NewNode()
		if status := postRegisterClaiming(t, a, "203.0.113.5:41641", machine, node, nil); status != http.StatusOK {
			t.Fatalf("the registration status = %d, want 200", status)
		}
		if err := a.RemoveHost(t.Context(), nodeKeyOf(node.Public())); err != nil {
			t.Fatalf("releasing the host: %v", err)
		}

		time.Sleep(admissionMinInterval)
		if status := postRegisterClaiming(t, a, "203.0.113.6:41641", key.NewMachine(), key.NewNode(), nil); status != http.StatusOK {
			t.Fatalf("the next registration status = %d, want 200", status)
		}
		if hosts := storeHosts(t, store); len(hosts) != 1 || hosts[0].Addr.String() != "100.64.1.2" {
			t.Errorf("the next registration holds %+v, want the freed 100.64.1.2", hosts)
		}
		time.Sleep(admissionMinInterval)
		asked := len(auth.asks())
		if status := postRegisterClaiming(t, a, "203.0.113.5:41641", machine, node, nil); status != http.StatusOK {
			t.Fatalf("the released key's registration status = %d, want 200", status)
		}
		if got := len(auth.asks()); got != asked+1 {
			t.Errorf("the released key's registration asked the seam %d times, want once", got-asked)
		}
	})
}

// TestMapBindingKeepsRelease checks the map path's binding of a record from
// before the machine claim against a release that landed after the map
// read the registry: the binding reads the registry again under the
// admission lock, finds the record gone, maps nothing, and writes nothing
// back.
func TestMapBindingKeepsRelease(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	if err := store.PublishHost(context.Background(), registeredHost(dbtest.MustKey(0x41))); err != nil {
		t.Fatal(err)
	}
	a := testApp(t, Config{Store: store})
	stale, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveHost(context.Background(), dbtest.MustKey(0x41)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.netmap(context.Background(), nodePublicOf(dbtest.MustKey(0x41)),
		key.NewMachine().Public(), stale, key.DiscoPublic{}, tailcfg.HostinfoView{}); err == nil {
		t.Error("the stale snapshot mapped a released record, want refusal")
	}
	if hosts := storeHosts(t, store); len(hosts) != 0 {
		t.Errorf("the binding wrote the released record back: %+v", hosts)
	}
}
