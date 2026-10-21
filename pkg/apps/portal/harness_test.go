package portal

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/passkeytest"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// The test console's relying party.
const (
	testDomain = "portal.test"
	testOrigin = "https://portal.test"
)

// fixture is one console under test: the application, the surface it
// mounted, and the fakes it decides for and reads.
type fixture struct {
	app      *App
	handler  http.Handler
	operator *fakeOperator
	records  *fakeRecords
}

// newFixture builds a console over a fresh state directory.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureAt(t, t.TempDir())
}

// newFixtureAt builds a console over the state directory, its method and
// its records the fakes'.
func newFixtureAt(t *testing.T, state string) *fixture {
	t.Helper()
	f := &fixture{operator: &fakeOperator{}, records: &fakeRecords{}}
	app, err := New(Config{
		Domain:   testDomain,
		Origin:   testOrigin,
		StateDir: state,
		Operator: f.operator,
		Records:  f.records,
		MountHTTPS: func(pattern string, handler http.Handler) {
			if pattern != "/admin/" {
				t.Errorf("the console mounted %s, want /admin/", pattern)
			}
			f.handler = handler
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.app = app
	return f
}

// setupToken reads the token the setup link carries.
func setupToken(t *testing.T, f *fixture) string {
	t.Helper()
	_, token, found := strings.Cut(f.app.SetupLink(), "#")
	if !found {
		t.Fatalf("the setup link %q carries no token", f.app.SetupLink())
	}
	return token
}

// console is a test's browser on the portal: requests go straight to the
// mounted surface, each from the source it names with the extra headers it
// holds, and the cookies a response sets ride the requests after it.
type console struct {
	t       *testing.T
	handler http.Handler
	source  string
	extra   http.Header
	cookies map[string]*http.Cookie
}

func newConsole(t *testing.T, f *fixture) *console {
	return &console{t: t, handler: f.handler, source: "192.0.2.1:1234", cookies: map[string]*http.Cookie{}}
}

// do sends one request: a nil body sends none, raw bytes go as they are,
// and any other value as its JSON.
func (c *console) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var reader io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, testOrigin+path, reader)
	req.RemoteAddr = c.source
	for name, values := range c.extra {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
			continue
		}
		c.cookies[cookie.Name] = cookie
	}
	return rec
}

// expect sends one request and fails the test unless it answers the status.
func (c *console) expect(status int, method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	rec := c.do(method, path, body)
	if rec.Code != status {
		c.t.Fatalf("%s %s = %d %s, want %d", method, path, rec.Code, rec.Body.String(), status)
	}
	return rec
}

// register runs one registration ceremony at the begin and finish routes
// with the passkey, answering the finish's response.
func (c *console) register(key *passkeytest.Authenticator, begin, finish string,
	body any) *httptest.ResponseRecorder {

	c.t.Helper()
	options := c.expect(http.StatusOK, http.MethodPost, begin, body)
	answer, err := key.Create(options.Body.Bytes())
	if err != nil {
		c.t.Fatal(err)
	}
	return c.do(http.MethodPost, finish, answer)
}

// setup registers the operator's first passkey with the setup token,
// signing the console in.
func (c *console) setup(key *passkeytest.Authenticator, token string) {
	c.t.Helper()
	rec := c.register(key, "/admin/api/setup/begin", "/admin/api/setup/finish",
		map[string]string{"token": token, "name": "laptop"})
	if rec.Code != http.StatusNoContent {
		c.t.Fatalf("finishing the setup = %d %s, want 204", rec.Code, rec.Body.String())
	}
}

// login runs one login ceremony with the passkey, answering the finish's
// response.
func (c *console) login(key *passkeytest.Authenticator) *httptest.ResponseRecorder {
	c.t.Helper()
	options := c.expect(http.StatusOK, http.MethodPost, "/admin/api/login/begin", map[string]string{})
	answer, err := key.Get(options.Body.Bytes())
	if err != nil {
		c.t.Fatal(err)
	}
	return c.do(http.MethodPost, "/admin/api/login/finish", answer)
}

// decodeJSON decodes a response's body.
func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return v
}

// fakeRecords is the records a test console reads: the nodes and hosts it
// holds, the coordination application's absence, and the releases it was
// asked.
type fakeRecords struct {
	mtx            sync.Mutex
	nodes          []Node
	hosts          []Host
	noCoordination bool
	released       []string
}

func (f *fakeRecords) Nodes(context.Context) ([]Node, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.nodes, nil
}

func (f *fakeRecords) Hosts(context.Context) ([]Host, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if f.noCoordination {
		return nil, ErrNoCoordination
	}
	return f.hosts, nil
}

func (f *fakeRecords) RemoveHost(_ context.Context, nodeKey string) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if f.noCoordination {
		return ErrNoCoordination
	}
	f.released = append(f.released, nodeKey)
	return nil
}

// fakeOperator is the admission method a test console decides for: the
// asks it holds, the decisions it records on them, and the keys it mints,
// each minted key reading cion-auth-<id>-secret.
type fakeOperator struct {
	mtx    sync.Mutex
	asks   []enrollauth.Ask
	keys   []enrollauth.AuthKey
	minted []enrollauth.KeyRequest
}

func (f *fakeOperator) Asks(boundaries ...enrollauth.Boundary) []enrollauth.Ask {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	var asks []enrollauth.Ask
	for _, a := range f.asks {
		if slices.Contains(boundaries, a.Boundary) {
			asks = append(asks, a)
		}
	}
	return asks
}

func (f *fakeOperator) Decide(id string, approve bool) bool {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	i := slices.IndexFunc(f.asks, func(a enrollauth.Ask) bool { return a.ID == id })
	if i < 0 {
		return false
	}
	f.asks[i].Verdict = enrollauth.AdmissionDeny
	if approve {
		f.asks[i].Verdict = enrollauth.AdmissionAllow
	}
	return true
}

func (f *fakeOperator) MintKey(req enrollauth.KeyRequest) (string, enrollauth.AuthKey, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	now := time.Now()
	key := enrollauth.AuthKey{
		ID:          fmt.Sprintf("%08x", len(f.keys)+1),
		Description: req.Description,
		Reusable:    req.Reusable,
		Created:     now,
		Expires:     now.AddDate(0, 0, req.Days),
		State:       enrollauth.KeyActive,
	}
	f.keys = append(f.keys, key)
	f.minted = append(f.minted, req)
	return "cion-auth-" + key.ID + "-secret", key, nil
}

func (f *fakeOperator) Keys() []enrollauth.AuthKey {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return slices.Clone(f.keys)
}

func (f *fakeOperator) RevokeKey(id string) (bool, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	i := slices.IndexFunc(f.keys, func(k enrollauth.AuthKey) bool { return k.ID == id })
	if i < 0 {
		return false, nil
	}
	f.keys[i].State = enrollauth.KeyRevoked
	return true, nil
}

// verdictOf reads the decision the fake holds on the ask.
func (f *fakeOperator) verdictOf(id string) enrollauth.AdmissionVerdict {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, a := range f.asks {
		if a.ID == id {
			return a.Verdict
		}
	}
	return enrollauth.AdmissionPending
}
