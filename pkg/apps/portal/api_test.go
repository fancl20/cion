package portal

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/passkeytest"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

func mustIA(s string) addr.IA { return addr.MustParseIA(s) }

// signedIn answers a console whose first passkey the key registered, and
// the browser that set it up.
func signedIn(t *testing.T) (*fixture, *console, *passkeytest.Authenticator) {
	t.Helper()
	f := newFixture(t)
	c := newConsole(t, f)
	key := passkeytest.New(t, testOrigin)
	c.setup(key, setupToken(t, f))
	return f, c, key
}

// TestNewRefusesAddressDomain checks that a console on an address identity
// refuses to build: a passkey binds to a DNS name.
func TestNewRefusesAddressDomain(t *testing.T) {
	_, err := New(Config{
		Domain:     "192.0.2.10",
		Origin:     "https://192.0.2.10",
		StateDir:   t.TempDir(),
		MountHTTPS: func(string, http.Handler) { t.Error("a refused console mounted its surface") },
	})
	if err == nil {
		t.Fatal("a console on an address identity built, want refusal")
	}
}

// TestSurfaceGuards checks the surface's guards: every response carries the
// security headers; the page serves at each view and the assets at theirs;
// the API refuses without a session and refuses a cross-origin write; and
// the ceremonies' doors refuse past their rate.
func TestSurfaceGuards(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		c := newConsole(t, f)
		for _, path := range []string{"/admin/", "/admin/nodes", "/admin/hosts",
			"/admin/keys", "/admin/settings", "/admin/setup"} {
			rec := c.expect(http.StatusOK, http.MethodGet, path, nil)
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
				t.Errorf("%s serves %q, want the page", path, got)
			}
		}
		for path, kind := range map[string]string{
			"/admin/portal.js": "text/javascript", "/admin/portal.css": "text/css",
		} {
			rec := c.expect(http.StatusOK, http.MethodGet, path, nil)
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, kind) {
				t.Errorf("%s serves %q, want %s", path, got, kind)
			}
		}
		for _, path := range []string{"/admin/", "/admin/api/session", "/admin/api/nodes"} {
			rec := c.do(http.MethodGet, path, nil)
			for header, want := range map[string]string{
				"Content-Security-Policy": contentSecurityPolicy,
				"X-Content-Type-Options":  "nosniff",
				"Referrer-Policy":         "no-referrer",
				"Cache-Control":           "no-store",
			} {
				if got := rec.Header().Get(header); got != want {
					t.Errorf("%s carries %s %q, want %q", path, header, got, want)
				}
			}
		}

		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/admin/api/nodes"},
			{http.MethodGet, "/admin/api/hosts"},
			{http.MethodDelete, "/admin/api/hosts/" + strings.Repeat("ab", 32)},
			{http.MethodPost, "/admin/api/asks/00/approve"},
			{http.MethodGet, "/admin/api/keys"},
			{http.MethodPost, "/admin/api/keys"},
			{http.MethodGet, "/admin/api/passkeys"},
			{http.MethodPost, "/admin/api/passkeys/begin"},
			{http.MethodPost, "/admin/api/logout"},
		} {
			c.expect(http.StatusUnauthorized, route.method, route.path, nil)
		}

		req := map[string]string{"token": setupToken(t, f)}
		crossSite := newConsole(t, f)
		crossSite.source = "192.0.2.9:1"
		rec := crossSite.doWith(http.MethodPost, "/admin/api/setup/begin", req,
			http.Header{"Sec-Fetch-Site": {"cross-site"}})
		if rec.Code != http.StatusForbidden {
			t.Errorf("a cross-site write answered %d, want 403", rec.Code)
		}

		c.expect(http.StatusOK, http.MethodPost, "/admin/api/setup/begin", req)
		c.expect(http.StatusTooManyRequests, http.MethodPost, "/admin/api/setup/begin", req)
		time.Sleep(time.Second)
		c.expect(http.StatusOK, http.MethodPost, "/admin/api/setup/begin", req)
	})
}

// doWith sends one request carrying the extra headers.
func (c *console) doWith(method, path string, body any,
	headers http.Header) *httptest.ResponseRecorder {

	c.t.Helper()
	c.extra = headers
	defer func() { c.extra = nil }()
	return c.do(method, path, body)
}

// TestRecordsAPI checks the console's views of the records: the nodes beside
// the method's node and vote asks, the slice's capacity counted; the hosts
// beside its registration asks, none available without the coordination
// application; and a release reaching the records, a malformed key refused
// before it.
func TestRecordsAPI(t *testing.T) {
	f, c, _ := signedIn(t)
	f.records.nodes = []Node{{
		IA:       mustIA("1-ff00:0:110"),
		Key:      "aa01",
		Expires:  time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Role:     RoleFounder,
		Overlay:  netip.MustParsePrefix("100.64.0.0/24"),
		Endpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
		Issued:   2,
	}}
	f.records.hosts = []Host{{
		Addr:      netip.MustParseAddr("100.64.0.2"),
		NodeKey:   strings.Repeat("ab", 32),
		Owner:     mustIA("1-ff00:0:110"),
		Note:      "portal operator",
		Hostname:  "laptop",
		OS:        "linux",
		Connected: true,
	}}
	seen := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	f.operator.asks = []enrollauth.Ask{
		{
			ID:        "e1",
			Boundary:  enrollauth.BoundaryEnrollment,
			Claim:     mustIA("1-ff00:0:111"),
			Keys:      []string{"bb02"},
			Source:    netip.MustParseAddrPort("192.0.2.7:30042"),
			FirstSeen: seen,
			LastSeen:  seen,
			Attempts:  3,
			Verdict:   enrollauth.AdmissionPending,
		},
		{
			ID:         "r1",
			Boundary:   enrollauth.BoundaryRegistration,
			Keys:       []string{"mkey:01", "nodekey:01"},
			Label:      "phone (ios)",
			Credential: true,
			FirstSeen:  seen,
			LastSeen:   seen,
			Attempts:   1,
			Verdict:    enrollauth.AdmissionDeny,
			Until:      seen.Add(24 * time.Hour),
		},
	}

	nodes := decodeJSON[struct {
		Nodes []nodeView `json:"nodes"`
		Asks  []askView  `json:"asks"`
	}](t, c.expect(http.StatusOK, http.MethodGet, "/admin/api/nodes", nil))
	wantNode := nodeView{
		IA:       "1-ff00:0:110",
		Key:      "aa01",
		Expires:  time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Role:     RoleFounder,
		Overlay:  "100.64.0.0/24",
		Endpoint: "198.51.100.10:41641",
		Issued:   2,
		Capacity: 253,
	}
	if diff := cmp.Diff([]nodeView{wantNode}, nodes.Nodes); diff != "" {
		t.Errorf("the nodes mismatch (-want +got):\n%s", diff)
	}
	wantAsk := askView{
		ID:        "e1",
		Boundary:  "enrollment",
		Claim:     "1-ff00:0:111",
		Keys:      []string{"bb02"},
		Source:    "192.0.2.7:30042",
		FirstSeen: seen,
		LastSeen:  seen,
		Attempts:  3,
		State:     "pending",
	}
	if diff := cmp.Diff([]askView{wantAsk}, nodes.Asks); diff != "" {
		t.Errorf("the nodes' asks mismatch (-want +got):\n%s", diff)
	}

	hosts := decodeJSON[struct {
		Available bool       `json:"available"`
		Hosts     []hostView `json:"hosts"`
		Asks      []askView  `json:"asks"`
	}](t, c.expect(http.StatusOK, http.MethodGet, "/admin/api/hosts", nil))
	if !hosts.Available || len(hosts.Hosts) != 1 || hosts.Hosts[0].Hostname != "laptop" ||
		!hosts.Hosts[0].Connected {
		t.Errorf("the hosts = %+v, want the laptop connected", hosts)
	}
	wantAsk = askView{
		ID:         "r1",
		Boundary:   "registration",
		Keys:       []string{"mkey:01", "nodekey:01"},
		Label:      "phone (ios)",
		Credential: true,
		FirstSeen:  seen,
		LastSeen:   seen,
		Attempts:   1,
		State:      "rejected",
		Until:      seen.Add(24 * time.Hour),
	}
	if diff := cmp.Diff([]askView{wantAsk}, hosts.Asks); diff != "" {
		t.Errorf("the hosts' asks mismatch (-want +got):\n%s", diff)
	}

	c.expect(http.StatusBadRequest, http.MethodDelete, "/admin/api/hosts/nodekey", nil)
	c.expect(http.StatusNoContent, http.MethodDelete, "/admin/api/hosts/"+strings.Repeat("ab", 32), nil)
	if len(f.records.released) != 1 || f.records.released[0] != strings.Repeat("ab", 32) {
		t.Errorf("the records were asked to release %v, want the host", f.records.released)
	}

	f.records.noCoordination = true
	hosts = decodeJSON[struct {
		Available bool       `json:"available"`
		Hosts     []hostView `json:"hosts"`
		Asks      []askView  `json:"asks"`
	}](t, c.expect(http.StatusOK, http.MethodGet, "/admin/api/hosts", nil))
	if hosts.Available || len(hosts.Hosts) != 0 {
		t.Errorf("without coordination the hosts read %+v, want none available", hosts)
	}
	c.expect(http.StatusConflict, http.MethodDelete, "/admin/api/hosts/"+strings.Repeat("ab", 32), nil)
}

// TestDecideAPI checks the asks' decisions over the API: a rejection and an
// approval reach the method, and an ID the method holds no ask of is not
// found.
func TestDecideAPI(t *testing.T) {
	f, c, _ := signedIn(t)
	f.operator.asks = []enrollauth.Ask{{
		ID:       "e1",
		Boundary: enrollauth.BoundaryEnrollment,
		Verdict:  enrollauth.AdmissionPending,
	}}
	c.expect(http.StatusNoContent, http.MethodPost, "/admin/api/asks/e1/reject", nil)
	if got := f.operator.verdictOf("e1"); got != enrollauth.AdmissionDeny {
		t.Errorf("the rejected ask holds %d, want deny", got)
	}
	c.expect(http.StatusNoContent, http.MethodPost, "/admin/api/asks/e1/approve", nil)
	if got := f.operator.verdictOf("e1"); got != enrollauth.AdmissionAllow {
		t.Errorf("the approved ask holds %d, want allow", got)
	}
	c.expect(http.StatusNotFound, http.MethodPost, "/admin/api/asks/zz/reject", nil)
}

// TestKeysAPI checks the auth keys over the API: an expiry outside the
// contract's bounds refuses before the method is asked; a minting reaches
// the method with its description cleaned and answers the key once, the
// listing never; and a revocation lands, an unknown ID not found.
func TestKeysAPI(t *testing.T) {
	f, c, _ := signedIn(t)
	for _, days := range []int{enrollauth.MinKeyDays - 1, enrollauth.MaxKeyDays + 1} {
		c.expect(http.StatusBadRequest, http.MethodPost, "/admin/api/keys",
			map[string]any{"days": days})
	}
	if len(f.operator.minted) != 0 {
		t.Fatalf("the refused mintings reached the method: %+v", f.operator.minted)
	}
	minted := decodeJSON[struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}](t, c.expect(http.StatusOK, http.MethodPost, "/admin/api/keys",
		map[string]any{"description": " ci\x00 runner ", "reusable": true, "days": 7}))
	want := []enrollauth.KeyRequest{{Description: "ci runner", Reusable: true, Days: 7}}
	if diff := cmp.Diff(want, f.operator.minted); diff != "" {
		t.Errorf("the method's mintings mismatch (-want +got):\n%s", diff)
	}
	if minted.Key != "cion-auth-"+minted.ID+"-secret" {
		t.Fatalf("the minting answered %+v, want the method's key", minted)
	}
	listing := c.expect(http.StatusOK, http.MethodGet, "/admin/api/keys", nil)
	if strings.Contains(listing.Body.String(), minted.Key) {
		t.Error("the listing carries the key")
	}
	keys := decodeJSON[struct {
		Keys []keyView `json:"keys"`
	}](t, listing).Keys
	if len(keys) != 1 || keys[0].Description != "ci runner" || !keys[0].Reusable ||
		keys[0].State != enrollauth.KeyActive {
		t.Fatalf("the keys list %+v, want the active reusable key", keys)
	}
	c.expect(http.StatusNoContent, http.MethodDelete, "/admin/api/keys/"+minted.ID, nil)
	c.expect(http.StatusNotFound, http.MethodDelete, "/admin/api/keys/ffffffff", nil)
	keys = decodeJSON[struct {
		Keys []keyView `json:"keys"`
	}](t, c.expect(http.StatusOK, http.MethodGet, "/admin/api/keys", nil)).Keys
	if len(keys) != 1 || keys[0].State != enrollauth.KeyRevoked {
		t.Errorf("the keys list %+v, want the key revoked", keys)
	}
}
