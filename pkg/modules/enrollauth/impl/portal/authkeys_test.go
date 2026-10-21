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
// admits the machine that first presents it with its note — that machine's
// retries passing on it until their admission lands — and falls through
// for any other machine to an ask flagged as carrying a credential; a
// reusable key admits and counts every use; an expired or revoked key
// falls through, listed in its standing; and a key admits nothing at
// another boundary.
func TestAuthKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPortal(t)
		once, record, err := p.MintKey(enrollauth.KeyRequest{Description: "laptop", Days: 7})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(once, authKeyPrefix+record.ID+"-") {
			t.Fatalf("the minted key %q does not read %s<id>-<secret>", once, authKeyPrefix)
		}
		answer := p.Authorize(t.Context(), registration("mkey:01", "nodekey:01", once))
		if answer.Admission != enrollauth.AdmissionAllow || answer.Note != authKeyNotePre+record.ID {
			t.Fatalf("the one-use key answered %+v, want allow with its note", answer)
		}
		if got := verdict(p, registration("mkey:01", "nodekey:01b", once)); got != enrollauth.AdmissionAllow {
			t.Errorf("the holder's retry answered %d, want allow", got)
		}
		if got := keyNamed(t, p, record.ID); got.Uses != 1 || got.State != enrollauth.KeySpent {
			t.Errorf("the one-use key lists %+v, want one use and spent", got)
		}
		if got := verdict(p, registration("mkey:02", "nodekey:02", once)); got != enrollauth.AdmissionPending {
			t.Errorf("the spent key answered %d, want the operator's ask", got)
		}
		asks := p.Asks(enrollauth.BoundaryRegistration)
		if len(asks) != 1 || !asks[0].Credential {
			t.Errorf("the spent key's ask lists %+v, want it flagged as carrying a credential", asks)
		}

		reusable, record, err := p.MintKey(enrollauth.KeyRequest{Description: "fleet", Reusable: true, Days: 1})
		if err != nil {
			t.Fatal(err)
		}
		for i, machine := range []string{"mkey:03", "mkey:04"} {
			if got := verdict(p, registration(machine, "nodekey:x", reusable)); got != enrollauth.AdmissionAllow {
				t.Fatalf("the reusable key's use %d answered %d, want allow", i+1, got)
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
		if got := verdict(p, registration("mkey:05", "nodekey:x", reusable)); got != enrollauth.AdmissionPending {
			t.Errorf("the expired key answered %d, want the operator's ask", got)
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
		if got := verdict(p, registration("mkey:06", "nodekey:x", revoked)); got != enrollauth.AdmissionPending {
			t.Errorf("the revoked key answered %d, want the operator's ask", got)
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

// TestAuthKeysPersist checks the keys' state file: the keys and their uses
// survive a restart, the file holds each key's digest and never the key,
// and a key leaves the file at its expiry.
func TestAuthKeysPersist(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := t.TempDir()
		p := newPortalAt(t, state)
		key, record, err := p.MintKey(enrollauth.KeyRequest{Description: "ci", Reusable: true, Days: 1})
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
		if got := keyNamed(t, restarted, record.ID); got.Uses != 1 || got.Description != "ci" {
			t.Errorf("the restarted portal lists %+v, want the key with its use", got)
		}
		if got := verdict(restarted, registration("mkey:02", "nodekey:02", key)); got != enrollauth.AdmissionAllow {
			t.Errorf("the restarted portal answered the key %d, want allow", got)
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
