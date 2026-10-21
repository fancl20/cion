package portal

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/fancl20/cion/pkg/libs/statefile"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
)

// An auth key reads cion-auth-<id>-<secret>: the ID the console lists and
// the secret only the minting response ever carries. The method keeps the
// key's digest, never the key, and each key expires within the contract's
// bounds.
const (
	authKeyPrefix      = "cion-auth-"
	authKeyIDBytes     = 4
	authKeySecretBytes = 16
	authKeysFile       = "portal-auth-keys.json"
)

// keyDigest is an auth key's SHA-256 digest, hex encoded in the state file.
type keyDigest [sha256.Size]byte

func (d keyDigest) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(d[:])), nil
}

func (d *keyDigest) UnmarshalText(text []byte) error {
	raw, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != len(d) {
		return fmt.Errorf("a key digest is %d bytes, not %d", len(d), len(raw))
	}
	copy(d[:], raw)
	return nil
}

// authKey is one minted key as the state file holds it.
type authKey struct {
	ID          string    `json:"id"`
	Digest      keyDigest `json:"digest"`
	Description string    `json:"description,omitempty"`
	Reusable    bool      `json:"reusable,omitempty"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires"`
	Uses        int       `json:"uses,omitempty"`
	// Holder names the identity a one-use key admitted, hex encoded: the
	// caller may refuse an admitted registration after the policy answered
	// — no slice yet to allocate in — so the holder's retries pass on the
	// key until their admission lands, and no other identity's do.
	Holder  string `json:"holder,omitempty"`
	Revoked bool   `json:"revoked,omitempty"`
}

// state names the key's standing: revoked, spent — a one-use key used —
// expired, or active.
func (k *authKey) state(now time.Time) enrollauth.KeyState {
	switch {
	case k.Revoked:
		return enrollauth.KeyRevoked
	case !k.Reusable && k.Uses > 0:
		return enrollauth.KeySpent
	case !now.Before(k.Expires):
		return enrollauth.KeyExpired
	default:
		return enrollauth.KeyActive
	}
}

// view is the key as the operator reads it.
func (k *authKey) view(now time.Time) enrollauth.AuthKey {
	return enrollauth.AuthKey{
		ID:          k.ID,
		Description: k.Description,
		Reusable:    k.Reusable,
		Created:     k.Created,
		Expires:     k.Expires,
		Uses:        k.Uses,
		State:       k.state(now),
	}
}

// MintKey creates one key and persists the set, answering the key itself —
// the one time it leaves the core — beside its record. The request's
// lifetime stands within the contract's bounds, the console's check.
func (p *Portal) MintKey(req enrollauth.KeyRequest) (string, enrollauth.AuthKey, error) {
	secret := randomHex(authKeySecretBytes)
	now := time.Now()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	id := randomHex(authKeyIDBytes)
	for slices.ContainsFunc(p.keys, func(k *authKey) bool { return k.ID == id }) {
		id = randomHex(authKeyIDBytes)
	}
	key := authKeyPrefix + id + "-" + secret
	record := &authKey{
		ID:          id,
		Digest:      sha256.Sum256([]byte(key)),
		Description: req.Description,
		Reusable:    req.Reusable,
		Created:     now,
		Expires:     now.AddDate(0, 0, req.Days),
	}
	p.keys = append(p.keys, record)
	if err := p.persistKeysLocked(now); err != nil {
		p.keys = p.keys[:len(p.keys)-1]
		return "", enrollauth.AuthKey{}, err
	}
	slog.Info("The portal minted an auth key", "id", record.ID,
		"reusable", record.Reusable, "expires", record.Expires)
	return key, record.view(now), nil
}

// spendLocked admits a credential matching a key that stands for the
// identity — a reusable key, counting the use; a one-use key's first
// presentation, binding the identity as its holder; or its holder's retry
// — persisting the set, and answers the key's ID. A failed write keeps the
// admission: the use is counted in memory, and the next write carries it.
func (p *Portal) spendLocked(credential, identity string, now time.Time) (string, bool) {
	digest := sha256.Sum256([]byte(credential))
	for _, k := range p.keys {
		if subtle.ConstantTimeCompare(k.Digest[:], digest[:]) != 1 {
			continue
		}
		switch {
		case k.Revoked || !now.Before(k.Expires):
			return "", false
		case k.Reusable:
			k.Uses++
		case k.Uses == 0:
			k.Uses, k.Holder = 1, identity
		case k.Holder != identity:
			return "", false
		default:
			return k.ID, true
		}
		if err := p.persistKeysLocked(now); err != nil {
			slog.Warn("Persisting the portal's auth keys", "err", err)
		}
		return k.ID, true
	}
	return "", false
}

// RevokeKey retires the key the ID names, reporting whether it named one.
func (p *Portal) RevokeKey(id string) (bool, error) {
	now := time.Now()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	i := slices.IndexFunc(p.keys, func(k *authKey) bool { return k.ID == id })
	if i < 0 {
		return false, nil
	}
	p.keys[i].Revoked = true
	return true, p.persistKeysLocked(now)
}

// Keys snapshots the keys, newest first.
func (p *Portal) Keys() []enrollauth.AuthKey {
	now := time.Now()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	out := make([]enrollauth.AuthKey, 0, len(p.keys))
	for _, k := range p.keys {
		out = append(out, k.view(now))
	}
	slices.SortFunc(out, func(a, b enrollauth.AuthKey) int { return b.Created.Compare(a.Created) })
	return out
}

// loadKeys reads the persisted keys; a missing file is a fresh start.
func (p *Portal) loadKeys() error {
	raw, err := os.ReadFile(p.keysPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the auth keys: %w", err)
	}
	if err := json.Unmarshal(raw, &p.keys); err != nil {
		return fmt.Errorf("parsing the auth keys: %w", err)
	}
	return nil
}

// persistKeysLocked writes the keys back whole, a key past its expiry
// leaving the file; the caller holds the mutex.
func (p *Portal) persistKeysLocked(now time.Time) error {
	p.keys = slices.DeleteFunc(p.keys, func(k *authKey) bool { return !now.Before(k.Expires) })
	raw, err := json.Marshal(p.keys)
	if err != nil {
		return err
	}
	if err := statefile.Write(p.keysPath(), raw); err != nil {
		return fmt.Errorf("writing the auth keys: %w", err)
	}
	return nil
}

// sweepKeysLocked drops the keys past their expiry, writing the set back
// when one left.
func (p *Portal) sweepKeysLocked(now time.Time) {
	if !slices.ContainsFunc(p.keys, func(k *authKey) bool { return !now.Before(k.Expires) }) {
		return
	}
	if err := p.persistKeysLocked(now); err != nil {
		slog.Warn("Persisting the portal's auth keys", "err", err)
	}
}

func (p *Portal) keysPath() string {
	return filepath.Join(p.state, "enrollauth", authKeysFile)
}
