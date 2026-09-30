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
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
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
// idempotent answer never asks at all.
func TestRegisterRateCaps(t *testing.T) {
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
}

// TestRegisterSerializesAllocation is the collision episode held as a
// regression: registrations of many distinct keys fired concurrently, with a
// deliberately slow seam answer between the read and the write, allocate
// distinct addresses — each admission reads every record the last one wrote,
// the freest slice chosen from what the registry holds.
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
