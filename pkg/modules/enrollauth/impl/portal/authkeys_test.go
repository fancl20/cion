package portal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// TestAuthKeys checks the keys at the registration boundary: a one-use key
// admits the machine that first presents it onto its node with its note —
// that machine's retries passing on it until their admission lands — and
// denies any other machine, listing no ask; a reusable key admits and
// counts every use, a key naming no node answering the founding core's
// zero IA; an expired or revoked key denies, listed in its standing; and a
// key admits nothing at another boundary.
func TestAuthKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPortal(t)
		leaf := mustIA("1-ff00:0:111")
		once, record, err := p.MintKey(enrollauth.KeyRequest{Description: "laptop", Days: 7, Node: leaf})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(once, authKeyPrefix+record.ID+"-") || record.Node != leaf {
			t.Fatalf("the minted key %q lists %+v, want %s<id>-<secret> naming %s",
				once, record, authKeyPrefix, leaf)
		}
		want := enrollauth.AdmissionAnswer{
			Admission: enrollauth.AdmissionAllow,
			Note:      authKeyNotePre + record.ID,
			Node:      leaf,
		}
		if answer := p.Authorize(t.Context(), registration("mkey:01", "nodekey:01", once)); answer != want {
			t.Fatalf("the one-use key answered %+v, want %+v", answer, want)
		}
		if answer := p.Authorize(t.Context(), registration("mkey:01", "nodekey:01b", once)); answer != want {
			t.Errorf("the holder's retry answered %+v, want %+v", answer, want)
		}
		if got := keyNamed(t, p, record.ID); got.Uses != 1 || got.State != enrollauth.KeySpent {
			t.Errorf("the one-use key lists %+v, want one use and spent", got)
		}
		if got := verdict(p, registration("mkey:02", "nodekey:02", once)); got != enrollauth.AdmissionDeny {
			t.Errorf("the spent key answered %d, want deny", got)
		}
		if asks := p.Asks(enrollauth.BoundaryRegistration); len(asks) != 0 {
			t.Errorf("the spent key listed %+v, want no ask", asks)
		}

		reusable, record, err := p.MintKey(enrollauth.KeyRequest{Description: "fleet", Reusable: true, Days: 1})
		if err != nil {
			t.Fatal(err)
		}
		for i, machine := range []string{"mkey:03", "mkey:04"} {
			answer := p.Authorize(t.Context(), registration(machine, "nodekey:x", reusable))
			if answer.Admission != enrollauth.AdmissionAllow || !answer.Node.IsZero() {
				t.Fatalf("the reusable key's use %d answered %+v, want allow onto the founding core", i+1, answer)
			}
		}
		if got := keyNamed(t, p, record.ID); got.Uses != 2 || got.State != enrollauth.KeyActive {
			t.Errorf("the reusable key lists %+v, want two uses and active", got)
		}
		if got := verdict(p, enrollauth.AdmissionFacts{
			Boundary:   enrollauth.BoundaryEnrollment,
			Keys:       []string{"cc"},
			Credential: reusable,
		}); got != enrollauth.AdmissionPending {
			t.Errorf("a key at the enrollment boundary answered %d, want the operator's ask", got)
		}
		time.Sleep(24 * time.Hour)
		if got := verdict(p, registration("mkey:05", "nodekey:x", reusable)); got != enrollauth.AdmissionDeny {
			t.Errorf("the expired key answered %d, want deny", got)
		}
		if got := keyNamed(t, p, record.ID); got.State != enrollauth.KeyExpired {
			t.Errorf("the reusable key lists %+v past its expiry, want expired", got)
		}

		revoked, record, err := p.MintKey(enrollauth.KeyRequest{Days: 30})
		if err != nil {
			t.Fatal(err)
		}
		if found, err := p.RevokeKey(record.ID); !found || err != nil {
			t.Fatalf("revoking the key = %v, %v", found, err)
		}
		if got := keyNamed(t, p, record.ID); got.State != enrollauth.KeyRevoked {
			t.Errorf("the revoked key lists %+v, want revoked", got)
		}
		if found, err := p.RevokeKey("00000000"); found || err != nil {
			t.Errorf("revoking an unknown key = %v, %v, want none found", found, err)
		}
		if got := verdict(p, registration("mkey:06", "nodekey:x", revoked)); got != enrollauth.AdmissionDeny {
			t.Errorf("the revoked key answered %d, want deny", got)
		}
	})
}

// keyNamed finds the listed key of the ID.
func keyNamed(t *testing.T, p *Portal, id string) enrollauth.AuthKey {
	t.Helper()
	for _, k := range p.Keys() {
		if k.ID == id {
			return k
		}
	}
	t.Fatalf("no key %s is listed", id)
	return enrollauth.AuthKey{}
}

// TestAuthKeysPersist checks the keys' state file: the keys, their uses,
// and their nodes survive a restart, the file holds each key's digest and
// never the key, and a key leaves the file at its expiry.
func TestAuthKeysPersist(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := t.TempDir()
		p := newPortalAt(t, state)
		leaf := mustIA("1-ff00:0:111")
		key, record, err := p.MintKey(enrollauth.KeyRequest{
			Description: "ci", Reusable: true, Days: 1, Node: leaf,
		})
		if err != nil {
			t.Fatal(err)
		}
		verdict(p, registration("mkey:01", "nodekey:01", key))

		raw, err := os.ReadFile(filepath.Join(state, "enrollauth", authKeysFile))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(key))
		if bytes.Contains(raw, []byte(key)) || !bytes.Contains(raw, []byte(hex.EncodeToString(digest[:]))) {
			t.Fatalf("the state file holds %s, want the key's digest and never the key", raw)
		}

		restarted := newPortalAt(t, state)
		if got := keyNamed(t, restarted, record.ID); got.Uses != 1 || got.Description != "ci" || got.Node != leaf {
			t.Errorf("the restarted portal lists %+v, want the key with its use and node", got)
		}
		if answer := restarted.Authorize(t.Context(), registration("mkey:02", "nodekey:02", key)); answer.Admission != enrollauth.AdmissionAllow || answer.Node != leaf {
			t.Errorf("the restarted portal answered the key %+v, want allow onto %s", answer, leaf)
		}

		time.Sleep(24 * time.Hour)
		restarted.sweep(time.Now())
		raw, err = os.ReadFile(filepath.Join(state, "enrollauth", authKeysFile))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(record.ID)) {
			t.Errorf("the expired key stays in the state file: %s", raw)
		}
	})
}
