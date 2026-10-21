package portal

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/internal/passkeytest"
)

// TestSetupToken checks the first passkey's token: a portal with no passkey
// mints one and Run logs its link once; a wrong token refuses; the token
// registers the first passkey and signs the console in, after which setup
// is closed to the same token; a portal over the same state mints none,
// over a fresh state a different one; and no file holds the token.
func TestSetupToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := t.TempDir()
		f := newFixtureAt(t, state)
		link := f.app.SetupLink()
		if !strings.HasPrefix(link, testOrigin+"/admin/setup#") {
			t.Fatalf("the setup link = %q, want the console's setup view with the token", link)
		}
		token := setupToken(t, f)
		if logged := runLogs(t, f.app); strings.Count(logged, link) != 1 {
			t.Errorf("Run logged %q, want the setup link once", logged)
		}

		c := newConsole(t, f)
		c.expect(http.StatusForbidden, http.MethodPost, "/admin/api/setup/begin",
			map[string]string{"token": "not-the-token"})
		key := passkeytest.New(t, testOrigin)
		time.Sleep(time.Second)
		c.setup(key, token)
		session := decodeJSON[struct {
			SignedIn bool `json:"signedIn"`
			Setup    bool `json:"setup"`
		}](t, c.expect(http.StatusOK, http.MethodGet, "/admin/api/session", nil))
		if !session.SignedIn || session.Setup {
			t.Errorf("after setup the session reads %+v, want signed in and setup closed", session)
		}
		if f.app.SetupLink() != "" {
			t.Error("a registered passkey left the setup link open")
		}
		time.Sleep(time.Second)
		c.expect(http.StatusConflict, http.MethodPost, "/admin/api/setup/begin",
			map[string]string{"token": token})

		if restarted := newFixtureAt(t, state); restarted.app.SetupLink() != "" {
			t.Error("a portal over a registered passkey minted a setup token")
		}
		if fresh := newFixtureAt(t, t.TempDir()); setupToken(t, fresh) == token {
			t.Error("a fresh portal minted the same setup token")
		}
		_ = filepath.WalkDir(state, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if raw, _ := os.ReadFile(path); bytes.Contains(raw, []byte(token)) {
				t.Errorf("%s holds the setup token", path)
			}
			return nil
		})
	})
}

// runLogs runs the console's loop for a moment and answers what it logged.
func runLogs(t *testing.T, a *App) string {
	t.Helper()
	var buf syncBuffer
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = a.Run(ctx)
	}()
	synctest.Wait()
	cancel()
	<-done
	return buf.String()
}

// syncBuffer is a buffer safe for the logger's and the test's goroutines.
type syncBuffer struct {
	mtx sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.buf.String()
}

// TestLogin checks the login ceremony: the registered passkey signs a fresh
// console in, and the session cookie carries its attributes.
func TestLogin(t *testing.T) {
	f, _, key := signedIn(t)
	c := newConsole(t, f)
	c.expect(http.StatusUnauthorized, http.MethodGet, "/admin/api/nodes", nil)
	if rec := c.login(key); rec.Code != http.StatusNoContent {
		t.Fatalf("the login = %d %s, want 204", rec.Code, rec.Body.String())
	}
	cookie := c.cookies[sessionCookie]
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Errorf("the session cookie = %+v, want __Host- secure, HttpOnly, strict, at /", cookie)
	}
	c.expect(http.StatusOK, http.MethodGet, "/admin/api/nodes", nil)
	c.expect(http.StatusNoContent, http.MethodPost, "/admin/api/logout", nil)
	c.expect(http.StatusUnauthorized, http.MethodGet, "/admin/api/nodes", nil)
}

// TestLoginRefusals checks what the ceremony refuses: an assertion from
// another origin, for another relying party, or without user verification;
// a passkey another console registered; a ceremony replayed, or answered
// past its lifetime; and an authenticator whose counter went back.
func TestLoginRefusals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _, key := signedIn(t)
		refused := func(what string, answer *passkeytest.Authenticator) {
			t.Helper()
			time.Sleep(time.Second)
			c := newConsole(t, f)
			if rec := c.login(answer); rec.Code != http.StatusBadRequest {
				t.Errorf("%s: the login = %d %s, want 400", what, rec.Code, rec.Body.String())
			}
			if c.cookies[sessionCookie] != nil {
				t.Errorf("%s: the refused login opened a session", what)
			}
		}
		bent := func(bend func(*passkeytest.Authenticator)) *passkeytest.Authenticator {
			copied := *key
			bend(&copied)
			return &copied
		}
		refused("another origin", bent(func(a *passkeytest.Authenticator) {
			a.Origin = "https://elsewhere.test"
		}))
		refused("another relying party", bent(func(a *passkeytest.Authenticator) {
			a.RPID = "elsewhere.test"
		}))
		refused("no user verification", bent(func(a *passkeytest.Authenticator) {
			a.SkipVerification = true
		}))
		stranger := passkeytest.New(t, testOrigin)
		other := newFixture(t)
		newConsole(t, other).setup(stranger, setupToken(t, other))
		refused("another console's passkey", stranger)

		// A ceremony completes once, and not past its lifetime.
		time.Sleep(time.Second)
		c := newConsole(t, f)
		options := c.expect(http.StatusOK, http.MethodPost, "/admin/api/login/begin", nil)
		ceremony := c.cookies[ceremonyCookie]
		answer, err := key.Get(options.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		c.expect(http.StatusNoContent, http.MethodPost, "/admin/api/login/finish", answer)
		time.Sleep(time.Second)
		c.cookies[ceremonyCookie] = ceremony
		c.expect(http.StatusBadRequest, http.MethodPost, "/admin/api/login/finish", answer)
		time.Sleep(time.Second)
		options = c.expect(http.StatusOK, http.MethodPost, "/admin/api/login/begin", nil)
		answer, err = key.Get(options.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(ceremonyLifetime)
		c.expect(http.StatusBadRequest, http.MethodPost, "/admin/api/login/finish", answer)

		// The stored counter stands ahead of a clone that went back.
		refused("a counter gone back", bent(func(a *passkeytest.Authenticator) {
			a.Counter = 0
		}))
	})
}

// TestPasskeys checks the operator's passkeys: a signed-in console adds a
// second, both list, and either signs in; one deletes, and the last refuses
// to.
func TestPasskeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, c, first := signedIn(t)
		second := passkeytest.New(t, testOrigin)
		rec := c.register(second, "/admin/api/passkeys/begin", "/admin/api/passkeys/finish",
			map[string]string{"name": "phone"})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("adding a passkey = %d %s, want 204", rec.Code, rec.Body.String())
		}
		listed := decodeJSON[struct {
			Passkeys []passkeyView `json:"passkeys"`
		}](t, c.expect(http.StatusOK, http.MethodGet, "/admin/api/passkeys", nil)).Passkeys
		if len(listed) != 2 || listed[0].Name != "laptop" || listed[1].Name != "phone" {
			t.Fatalf("the passkeys list %+v, want the laptop and the phone", listed)
		}
		time.Sleep(time.Second)
		if rec := newConsole(t, f).login(second); rec.Code != http.StatusNoContent {
			t.Errorf("the added passkey's login = %d %s, want 204", rec.Code, rec.Body.String())
		}

		c.expect(http.StatusNoContent, http.MethodDelete, "/admin/api/passkeys/"+listed[0].ID, nil)
		c.expect(http.StatusConflict, http.MethodDelete, "/admin/api/passkeys/"+listed[1].ID, nil)
		c.expect(http.StatusNotFound, http.MethodDelete, "/admin/api/passkeys/"+listed[0].ID, nil)
		time.Sleep(time.Second)
		if rec := newConsole(t, f).login(first); rec.Code != http.StatusBadRequest {
			t.Errorf("the deleted passkey's login = %d %s, want 400", rec.Code, rec.Body.String())
		}
	})
}
