package coordination

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// postRegister drives one registration straight at the handler — below the
// noise channel, for the door's own seams: the source address and the
// machine key are the test's to choose, and the concurrency the test's to
// fire. It returns the recorded response; a request that cannot marshal —
// none can — answers the zero status.
func postRegister(a *App, source string, machine key.MachinePrivate,
	node key.NodePrivate) *httptest.ResponseRecorder {

	req := tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: node.Public(),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return &httptest.ResponseRecorder{Code: 0}
	}
	r := httptest.NewRequest(http.MethodPost, "/machine/register",
		bytes.NewReader(raw))
	r.RemoteAddr = source
	w := httptest.NewRecorder()
	a.handleRegister(w, r, machine.Public())
	return w
}

// rateRefused names the rate refusal's own answer, for the status it rides
// is the pending refusal's.
const rateRefused = "registration exceeds the admission rate\n"

// TestRegisterRateCaps checks the door's caps ahead of the seam: a second
// ask inside the source interval is refused without the seam being asked —
// the ask recorder proves the door — the overall interval refuses across
// distinct sources, past the interval the asks pass again, and the record's
// idempotent answer never asks at all. The interval passes in a fake-time
// bubble.
func TestRegisterRateCaps(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &dbtest.MemStore{}
		store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
		auth := &askAuthorizer{
			answer: enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow},
		}
		a := testApp(t, Config{Store: store, Authorizer: auth})
		member := key.NewMachine()
		joiner := key.NewNode()

		if w := postRegister(a, "192.0.2.10:1111", member, joiner); w.Code != http.StatusOK {
			t.Fatalf("the first ask's status = %d, want 200", w.Code)
		}
		if asks := auth.asks(); len(asks) != 1 {
			t.Fatalf("the seam was asked %d times, want the one", len(asks))
		}

		// The same source inside the interval — from another port, for the cap
		// keys the address, an internet source's port being ephemeral: refused,
		// the seam never asked.
		if w := postRegister(a, "192.0.2.10:2222", member, key.NewNode()); w.Code != http.StatusServiceUnavailable ||
			w.Body.String() != rateRefused {
			t.Errorf("a second ask inside the source interval = %d %q, want the rate's %d %q",
				w.Code, w.Body.String(), http.StatusServiceUnavailable, rateRefused)
		}
		if asks := auth.asks(); len(asks) != 1 {
			t.Fatalf("the seam was asked %d times inside the interval, want the one",
				len(asks))
		}

		// The overall interval refuses across distinct sources: many slow
		// sources bound the door as one.
		if w := postRegister(a, "192.0.2.20:3333", key.NewMachine(), key.NewNode()); w.Code != http.StatusServiceUnavailable ||
			w.Body.String() != rateRefused {
			t.Errorf("an ask from a second source inside the overall interval = %d %q, want the rate's %d %q",
				w.Code, w.Body.String(), http.StatusServiceUnavailable, rateRefused)
		}
		if asks := auth.asks(); len(asks) != 1 {
			t.Fatalf("the seam was asked %d times inside the overall interval, want the one",
				len(asks))
		}

		// The record's idempotent answer passes uncapped, inside the interval:
		// the re-registering member's read is what the registry owes it.
		if w := postRegister(a, "192.0.2.99:4444", member, joiner); w.Code != http.StatusOK {
			t.Errorf("the idempotent re-registration inside the interval = %d, want 200",
				w.Code)
		}
		if asks := auth.asks(); len(asks) != 1 {
			t.Fatalf("the idempotent answer asked the seam %d times, want never", len(asks))
		}

		// Past the interval the asks pass again.
		time.Sleep(admissionMinInterval)
		if w := postRegister(a, "192.0.2.20:3333", key.NewMachine(), key.NewNode()); w.Code != http.StatusOK {
			t.Errorf("an ask past the interval = %d, want 200", w.Code)
		}
		if asks := auth.asks(); len(asks) != 2 {
			t.Fatalf("the seam was asked %d times past the interval, want 2", len(asks))
		}
	})
}

// TestRegisterSerializesAllocation is the collision episode held as a
// regression: registrations of many distinct keys fired concurrently, with a
// deliberately slow seam answer between the read and the write, allocate
// distinct addresses — each admission reads every record the last one wrote,
// the next free address chosen from what the registry holds.
func TestRegisterSerializesAllocation(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	auth := &askAuthorizer{
		answer: enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow},
		// The slow seam's answer outlasts the door's interval, so the queued
		// admissions pass the caps as their turns come and the overlap is
		// the transaction's alone to settle.
		delay: admissionMinInterval + 100*time.Millisecond,
	}
	a := testApp(t, Config{Store: store, Authorizer: auth})

	const joins = 4
	var wg sync.WaitGroup
	statuses := make([]int, joins)
	for i := range joins {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = postRegister(a, fmt.Sprintf("192.0.2.%d:1234", 10+i),
				key.NewMachine(), key.NewNode()).Code
		}(i)
	}
	wg.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("the concurrent registration %d = %d, want 200", i, status)
		}
	}
	hosts := storeHosts(t, store)
	if len(hosts) != joins {
		t.Fatalf("the registry holds %d hosts, want %d", len(hosts), joins)
	}
	issued := make(map[netip.Addr]bool, len(hosts))
	for _, host := range hosts {
		if issued[host.Addr] {
			t.Errorf("the address %s was allocated twice", host.Addr)
		}
		issued[host.Addr] = true
	}
}

// TestRegisterConvergesRacingKey checks the transaction's idempotent side:
// the same key registered concurrently — the seam slow between the read and
// the write — converges on one address and one record, the seam asked once.
func TestRegisterConvergesRacingKey(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	auth := &askAuthorizer{
		answer: enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow},
		delay:  admissionMinInterval + 100*time.Millisecond,
	}
	a := testApp(t, Config{Store: store, Authorizer: auth})

	machine, joiner := key.NewMachine(), key.NewNode()
	const races = 4
	var wg sync.WaitGroup
	statuses := make([]int, races)
	for i := range races {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = postRegister(a, fmt.Sprintf("192.0.2.%d:1234", 10+i),
				machine, joiner).Code
		}(i)
	}
	wg.Wait()
	for i, status := range statuses {
		if status != http.StatusOK {
			t.Errorf("the racing registration %d = %d, want 200", i, status)
		}
	}
	if asks := auth.asks(); len(asks) != 1 {
		t.Fatalf("the seam was asked %d times, want the one", len(asks))
	}
	hosts := storeHosts(t, store)
	if len(hosts) != 1 || hosts[0].PublicKey != nodeKeyOf(joiner.Public()) {
		t.Fatalf("the registry holds %+v, want the one record", hosts)
	}
}

// TestRegisterPlacesOnTheNamedNode checks where an admitted host lands: on
// the node the answer names, on the founding core when the answer names
// none, and nowhere while the named node holds no entry — the registration
// refused and nothing recorded, the client's retry landing once the node
// publishes. The admission intervals pass in a fake-time bubble.
func TestRegisterPlacesOnTheNamedNode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &dbtest.MemStore{}
		store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
		store.Seed(testNode(mustIA("1-ff00:0:2"), "100.64.2.0/24", "198.51.100.20:51820"))
		auth := &askAuthorizer{}
		a := testApp(t, Config{Store: store, Authorizer: auth})
		admit := func(node string) int {
			t.Helper()
			auth.answer = enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}
			if node != "" {
				auth.answer.Node = mustIA(node)
			}
			time.Sleep(admissionMinInterval)
			return postRegister(a, "192.0.2.10:1111", key.NewMachine(), key.NewNode()).Code
		}
		owners := func() map[string]string {
			owned := make(map[string]string)
			for _, host := range storeHosts(t, store) {
				owned[host.Addr.String()] = host.IA.String()
			}
			return owned
		}

		if status := admit("1-ff00:0:2"); status != http.StatusOK {
			t.Fatalf("the registration naming 1-ff00:0:2 = %d, want 200", status)
		}
		if status := admit(""); status != http.StatusOK {
			t.Fatalf("the registration naming no node = %d, want 200", status)
		}
		want := map[string]string{"100.64.2.2": "1-ff00:0:2", "100.64.1.2": "1-ff00:0:1"}
		if diff := cmp.Diff(want, owners()); diff != "" {
			t.Fatalf("the placements mismatch (-want +got):\n%s", diff)
		}

		// A named node without an entry refuses, and the retry lands once
		// the node publishes.
		auth.answer = enrollauth.AdmissionAnswer{
			Admission: enrollauth.AdmissionAllow,
			Node:      mustIA("1-ff00:0:3"),
		}
		machine, node := key.NewMachine(), key.NewNode()
		time.Sleep(admissionMinInterval)
		if w := postRegister(a, "192.0.2.10:1111", machine, node); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("the registration naming an absent node = %d, want 503", w.Code)
		}
		if diff := cmp.Diff(want, owners()); diff != "" {
			t.Fatalf("the refused registration recorded a host (-want +got):\n%s", diff)
		}
		store.Seed(testNode(mustIA("1-ff00:0:3"), "100.64.3.0/24", "198.51.100.30:51820"))
		time.Sleep(admissionMinInterval)
		if w := postRegister(a, "192.0.2.10:1111", machine, node); w.Code != http.StatusOK {
			t.Fatalf("the retry once the node published = %d, want 200", w.Code)
		}
		want["100.64.3.2"] = "1-ff00:0:3"
		if diff := cmp.Diff(want, owners()); diff != "" {
			t.Errorf("the retry's placement mismatches (-want +got):\n%s", diff)
		}
	})
}

// TestRegisterWithoutAuthorizerDenies checks that no policy admits no
// host: with no authorizer the registration is denied and nothing is
// recorded.
func TestRegisterWithoutAuthorizerDenies(t *testing.T) {
	store := &dbtest.MemStore{}
	store.Seed(testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"))
	a, err := New(Config{
		Domain:     webpkitest.Domain,
		Store:      store,
		IA:         mustIA("1-ff00:0:1"),
		StateDir:   t.TempDir(),
		MountHTTPS: http.NewServeMux().Handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if w := postRegister(a, "192.0.2.10:1111", key.NewMachine(), key.NewNode()); w.Code != http.StatusForbidden {
		t.Errorf("a registration with no authorizer = %d, want 403", w.Code)
	}
	if hosts := storeHosts(t, store); len(hosts) != 0 {
		t.Errorf("the registry holds %+v, want nothing", hosts)
	}
}
