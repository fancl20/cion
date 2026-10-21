// Package passkeytest is a software passkey for tests: it answers a
// relying party's creation and request options the way a browser driving a
// platform authenticator does, with one ES256 key, so a test runs real
// WebAuthn ceremonies without a browser. Its exported fields bend one fact
// of the answers each, for the refusals a test proves.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The authenticator data's flags the answers set.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

// Authenticator is one software passkey: its key, its credential, the user
// handle its registration bound it to, and its signature counter.
type Authenticator struct {
	// Origin is the origin the client data names, as a browser reports the
	// page's own.
	Origin string
	// RPID overrides the relying party the answers hash; empty hashes the
	// one the options name.
	RPID string
	// SkipVerification leaves the user-verified flag out of the answers.
	SkipVerification bool
	// Counter is the signature counter; each assertion increments it before
	// signing.
	Counter uint32

	key          *ecdsa.PrivateKey
	credentialID []byte
	userHandle   []byte
	rpID         string
}

// New returns a fresh passkey answering for the origin.
func New(t testing.TB, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &Authenticator{Origin: origin, key: key, credentialID: id}
}

// Create answers creation options — the document a relying party's
// registration begins with — with the registration response its finish
// takes, attesting the passkey's key under the "none" format.
func (a *Authenticator) Create(options []byte) ([]byte, error) {
	var opts struct {
		PublicKey struct {
			RP struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("parsing the creation options: %w", err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("decoding the user handle: %w", err)
	}
	a.userHandle = handle
	a.rpID = opts.PublicKey.RP.ID
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	cose, err := cbor.Marshal(map[int]any{
		1:  2,           // key type: EC2
		3:  -7,          // algorithm: ES256
		-1: 1,           // curve: P-256
		-2: point[1:33], // x
		-3: point[33:],  // y
	})
	if err != nil {
		return nil, err
	}
	data := a.authenticatorData(opts.PublicKey.RP.ID, flagAttested)
	data = append(data, make([]byte, 16)...) // the AAGUID, all zero
	data = binary.BigEndian.AppendUint16(data, uint16(len(a.credentialID)))
	data = append(data, a.credentialID...)
	data = append(data, cose...)
	attestation, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": data,
	})
	if err != nil {
		return nil, err
	}
	clientData, err := a.clientData("webauthn.create", opts.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}
	encode := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id":    encode(a.credentialID),
		"rawId": encode(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    encode(clientData),
			"attestationObject": encode(attestation),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
}

// Get answers request options — the document a relying party's login
// begins with — with the assertion its finish takes, signed by the passkey
// and naming the user handle its registration bound.
func (a *Authenticator) Get(options []byte) ([]byte, error) {
	if a.userHandle == nil {
		return nil, errors.New("the passkey holds no registration to assert")
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("parsing the request options: %w", err)
	}
	rpID := opts.PublicKey.RPID
	if rpID == "" {
		rpID = a.rpID
	}
	a.Counter++
	data := a.authenticatorData(rpID, 0)
	clientData, err := a.clientData("webauthn.get", opts.PublicKey.Challenge)
	if err != nil {
		return nil, err
	}
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	encode := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id":    encode(a.credentialID),
		"rawId": encode(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    encode(clientData),
			"authenticatorData": encode(data),
			"signature":         encode(signature),
			"userHandle":        encode(a.userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
}

// authenticatorData renders the data's fixed head: the relying party's
// hash, the flags — user present and, unless skipped, verified, beside the
// extra ones — and the counter.
func (a *Authenticator) authenticatorData(rpID string, extra byte) []byte {
	if a.RPID != "" {
		rpID = a.RPID
	}
	flags := flagUserPresent | flagUserVerified | extra
	if a.SkipVerification {
		flags &^= flagUserVerified
	}
	hash := sha256.Sum256([]byte(rpID))
	data := make([]byte, 0, len(hash)+1+4)
	data = append(data, hash[:]...)
	data = append(data, flags)
	return binary.BigEndian.AppendUint32(data, a.Counter)
}

// clientData renders the client data a browser collects for the ceremony.
func (a *Authenticator) clientData(ceremony, challenge string) ([]byte, error) {
	return json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{ceremony, challenge, a.Origin, false})
}
