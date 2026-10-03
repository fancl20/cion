package testnetwork

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	trustbbolt "github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/trust"
)

// seedValidity is the pre-seeded material's lifetime: short enough to sit
// inside the rotation threshold, long enough to outlive the lab.
const seedValidity = 6 * time.Hour

// seedFounder writes the founding core's pre-seeded state: the identity, the
// four persisted keys, and the trust database pinning the base TRC the
// material signs — the founder's three certificates and the authoritative's
// one, all short-dated, both ASes named cores.
func seedFounder(
	t *testing.T,
	founderIA, authIA addr.IA,
	authKey crypto.Signer,
	authCert *x509.Certificate,
) (string, cppki.SignedTRC) {

	t.Helper()
	state := t.TempDir()
	keys := mintCoreKeys(t)
	sensitive := mintVotingCert(t, founderIA, keys.Sensitive, true)
	regular := mintVotingCert(t, founderIA, keys.Regular, false)
	root := mintRootCert(t, founderIA, keys.Root)
	persistIAFile(t, state, founderIA)
	persistKeyFile(t, state, trust.SensitiveKeyFile, keys.Sensitive)
	persistKeyFile(t, state, trust.RegularKeyFile, keys.Regular)
	persistKeyFile(t, state, trust.RootKeyFile, keys.Root)
	persistKeyFile(t, state, trust.CAKeyFile, keys.CA)

	// Whole seconds and a backdate, the genesis certificates' own shape.
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	trc := cppki.TRC{
		Version:  1,
		ID:       cppki.TRCID{ISD: founderIA.ISD(), Base: 1, Serial: 1},
		Validity: cppki.Validity{NotBefore: now, NotAfter: now.Add(seedValidity)},
		Quorum:   1,
		CoreASes: []addr.AS{founderIA.AS(), authIA.AS()},
		AuthoritativeASes: []addr.AS{
			founderIA.AS(), authIA.AS(),
		},
		Description:  "CION seeded rotation lab TRC",
		Certificates: []*x509.Certificate{sensitive, regular, root, authCert},
	}
	signed := signSeedTRC(t, trc, []crypto.Signer{keys.Sensitive, keys.Regular, authKey},
		[]*x509.Certificate{sensitive, regular, authCert})
	db, err := trustbbolt.New(filepath.Join(state, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTRC(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return state, signed
}

// seedAuthoritative writes the authoritative core's pre-seeded state: the
// identity and the short-dated voting pair.
func seedAuthoritative(t *testing.T, ia addr.IA) (string, crypto.Signer, *x509.Certificate) {
	t.Helper()
	state := t.TempDir()
	key := mintKey(t)
	cert := mintVotingCert(t, ia, key, false)
	persistIAFile(t, state, ia)
	persistKeyFile(t, state, trust.RegularKeyFile, key)
	if err := os.MkdirAll(filepath.Join(state, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "keys", trust.RegularVotingCertFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return state, key, cert
}

// signSeedTRC CMS-signs the seeded TRC with every voter the base rules name.
func signSeedTRC(
	t *testing.T,
	trc cppki.TRC,
	keys []crypto.Signer,
	certs []*x509.Certificate,
) cppki.SignedTRC {

	t.Helper()
	payload, err := trc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	eci, err := protocol.NewDataEncapsulatedContentInfo(payload)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		if err := sd.AddSignerInfo([]*x509.Certificate{certs[i]}, key); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cppki.DecodeSignedTRC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Verify(nil); err != nil {
		t.Fatalf("the seeded TRC does not verify: %v", err)
	}
	return signed
}

// mintCoreKeys mints the founder's four keys.
func mintCoreKeys(t *testing.T) trust.CoreKeys {
	t.Helper()
	sensitive := mintKey(t)
	regular := mintKey(t)
	root := mintKey(t)
	ca := mintKey(t)
	return trust.CoreKeys{
		Sensitive: sensitive, Regular: regular, Root: root, CA: ca,
	}
}

// mintKey mints a fresh ECDSA P-256 key.
func mintKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// seedSubject builds the distinguished name carrying the ISD-AS, the
// production certificates' own construction: the common name beside the
// dedicated RDN cppki extracts the IA from.
func seedSubject(ia addr.IA, cn string) pkix.Name {
	return pkix.Name{
		CommonName: cn,
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: cppki.OIDNameIA, Value: ia.String()},
		},
	}
}

// mintVotingCert mints the self-signed voting certificate over the key, the
// production shape short-dated: the sensitive flag selects the id-kp
// sensitive over the id-kp-regular extended key usage.
func mintVotingCert(t *testing.T, ia addr.IA, key crypto.Signer, sensitive bool) *x509.Certificate {
	t.Helper()
	usage := cppki.OIDExtKeyUsageRegular
	cn := ia.String() + " regular voting"
	if sensitive {
		usage = cppki.OIDExtKeyUsageSensitive
		cn = ia.String() + " sensitive voting"
	}
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Version:            cppki.CertVersion,
		SerialNumber:       new(big.Int).SetBytes(serial),
		Subject:            seedSubject(ia, cn),
		NotBefore:          now,
		NotAfter:           now.Add(seedValidity),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{usage},
		SubjectKeyId:       skid,
	}
	return createSeedCert(t, tmpl, tmpl, key.Public(), key)
}

// mintRootCert mints the self-signed CP root certificate over the key.
func mintRootCert(t *testing.T, ia addr.IA, key crypto.Signer) *x509.Certificate {
	t.Helper()
	skid, err := cppki.SubjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		Version:               cppki.CertVersion,
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               seedSubject(ia, "cp root"),
		NotBefore:             now,
		NotAfter:              now.Add(seedValidity),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{cppki.OIDExtKeyUsageRoot},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}
	return createSeedCert(t, tmpl, tmpl, key.Public(), key)
}

// createSeedCert signs template with parent, or self-signs it when parent is
// the template itself.
func createSeedCert(
	t *testing.T,
	template, parent *x509.Certificate,
	subjectPub any, issuerKey any,
) *x509.Certificate {

	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, subjectPub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cppki.ValidateCert(cert); err != nil {
		t.Fatalf("the seeded certificate does not classify: %v", err)
	}
	return cert
}

// persistIAFile writes the state directory's identity file.
func persistIAFile(t *testing.T, state string, ia addr.IA) {
	t.Helper()
	if err := trust.PersistIA(state, ia); err != nil {
		t.Fatal(err)
	}
}

// persistKeyFile writes a PKCS8 key under the state directory's keys folder.
func persistKeyFile(t *testing.T, state, name string, key crypto.Signer) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCoresRotateBySensitiveUpdate is the rotation seam's integration proof:
// a founder and an authoritative core whose state is pre-seeded so each
// holder's material approaches expiry — the founder's watch casts its own
// roll, the authoritative's submits its own, both pin, and the ladder's
// serials stay monotone; a third node discovers the successors from the
// founder's signed messages and a node enrolled after the founder's pin
// holds a chain under the fresh root, while the founder's own pre-pin chain
// keeps verifying through the grace; replacing the authoritative's persisted
// voting pair fires the mismatch roll at the next pass.
func TestCoresRotateBySensitiveUpdate(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipB, ipC, ipD := hostSlot(t), hostSlot(t), hostSlot(t), hostSlot(t)

	founderIA, err := trust.GenerateIA()
	if err != nil {
		t.Fatal(err)
	}
	drawn, err := trust.GenerateIA()
	if err != nil {
		t.Fatal(err)
	}
	authIA := addr.MustIAFrom(founderIA.ISD(), drawn.AS())
	authState, authKey, authCert := seedAuthoritative(t, authIA)
	founderState, base := seedFounder(t, founderIA, authIA, authKey, authCert)
	ctx := context.Background()

	// The founding core, its material pre-seeded: the founder's watch rolls
	// its own three inside the cast it signs itself.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = founderState
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	// The authoritative core, its material pre-seeded and already named by
	// the seeded base: its watch submits its own roll through the channel
	// its join used.
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = authState
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	// A third node joining the founder, to watch the successors spread.
	c := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})

	// The founder's own chain — issued synchronously at boot, under the
	// seeded root — is the chain issued before the pin.
	preChain := ownChain(t, a)
	if err := cppki.VerifyChain(preChain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&base.TRC}, CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("the founder's pre-pin chain does not verify against the base: %v", err)
	}

	// Both holders roll their own material: the founder's three inside its
	// own cast, the authoritative's one through its submission.
	founderRolled := pollRolled(t, a, founderIA, base)
	authRolled := pollRolled(t, b, authIA, base)

	// The ladder's serials stay monotone: every successor the rollers pinned
	// verifies against the pin before it.
	for name, rolled := range map[string]cppki.SignedTRC{
		"the founder's roll": founderRolled, "the authoritative's roll": authRolled,
	} {
		pred := base
		for serial := scrypto.Version(2); serial <= rolled.TRC.ID.Serial; serial++ {
			successor, err := a.app.TrustDB().SignedTRC(ctx,
				cppki.TRCID{ISD: founderIA.ISD(), Base: 1, Serial: serial})
			if err != nil {
				t.Fatal(err)
			}
			if successor.IsZero() {
				t.Fatalf("%s pinned serial %d that the founder never saw", name, serial)
			}
			if err := successor.Verify(&pred.TRC); err != nil {
				t.Fatalf("%s's rung %d does not verify against its predecessor: %v",
					name, serial, err)
			}
			pred = successor
		}
	}
	// The staged sets persisted: each holder's disk holds the keys its
	// successor's certificates cover.
	persistedFounder, err := trust.LoadOrCreateCoreKeys(founderState)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range trust.CertsOf(founderRolled.TRC, founderIA) {
		if !covers(persistedFounder, cert) {
			t.Error("the founder's persisted keys do not cover its rolled certificates")
		}
	}
	persistedAuth, err := trust.LoadOrCreateVotingKey(authState)
	if err != nil {
		t.Fatal(err)
	}
	if authCerts := trust.CertsOf(authRolled.TRC, authIA); len(authCerts) != 1 ||
		!trust.KeyMatchesCert(persistedAuth, authCerts[0]) {

		t.Error("the authoritative's persisted key does not cover its rolled certificate")
	}

	// The third node discovers the successors from the founder's signed
	// messages — the cited TRC the verifier reports — and the grace carries
	// the pre-pin chain: it verifies against the newest beside its
	// predecessor, and against the newest alone it does not.
	newest := pollDiscovered(t, c, founderIA.ISD(), base)
	if err := cppki.VerifyChain(preChain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&newest.TRC, &base.TRC}, CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("the pre-pin chain does not verify through the grace: %v", err)
	}
	if err := cppki.VerifyChain(preChain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&newest.TRC}, CurrentTime: time.Now(),
	}); err == nil {
		t.Error("the pre-pin chain verified against the successor alone, want the grace carrying it")
	}

	// A node enrolled after the founder's pin holds a chain under the fresh
	// root: it verifies against the successor the founder pinned.
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	Poll(t, "the post-pin node enrolled", func() bool {
		return holdsAssemblyChain(t, d, d.app.IA())
	})
	postChain := ownChain(t, d)
	if err := cppki.VerifyChain(postChain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&founderRolled.TRC}, CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("the post-pin chain does not verify under the fresh root: %v", err)
	}

	// Replacing the authoritative's persisted voting pair fires the mismatch
	// roll at the next pass, whatever the calendar says. The replacement
	// waits the roll's persist out, so it is not itself overwritten by the
	// pair the landing roll writes.
	Poll(t, "the authoritative's rolled pair to persist", func() bool {
		key, err := trust.LoadOrCreateVotingKey(authState)
		if err != nil {
			t.Fatal(err)
		}
		return trust.KeyMatchesCert(key, trust.CertsOf(authRolled.TRC, authIA)[0])
	})
	stranger := mintKey(t)
	strangerCert := mintVotingCert(t, authIA, stranger, false)
	persistKeyFile(t, authState, trust.RegularKeyFile, stranger)
	if err := os.WriteFile(filepath.Join(authState, "keys", trust.RegularVotingCertFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: strangerCert.Raw}),
		0o600); err != nil {
		t.Fatal(err)
	}
	mismatch := pollRolled(t, b, authIA, authRolled)
	if mismatch.TRC.ID.Serial <= authRolled.TRC.ID.Serial {
		t.Fatalf("the mismatch roll's serial = %d, want past the landed roll's %d",
			mismatch.TRC.ID.Serial, authRolled.TRC.ID.Serial)
	}
}

// pollRolled waits for the core's watch to roll its material past the given
// pin: the newest TRC it pins naming a certificate for the core the pin did
// not carry.
func pollRolled(
	t *testing.T,
	n *assemblyNode,
	ia addr.IA,
	pin cppki.SignedTRC,
) cppki.SignedTRC {

	t.Helper()
	var rolled cppki.SignedTRC
	Poll(t, "the core's roll to land", func() bool {
		newest, err := n.app.TrustDB().SignedTRC(context.Background(), cppki.TRCID{
			ISD: ia.ISD(), Base: scrypto.LatestVer, Serial: scrypto.LatestVer,
		})
		if err != nil || newest.IsZero() {
			return false
		}
		rolled = newest
		for _, cert := range trust.CertsOf(newest.TRC, ia) {
			if slices.ContainsFunc(trust.CertsOf(pin.TRC, ia), cert.Equal) {
				return false
			}
		}
		return len(trust.CertsOf(newest.TRC, ia)) > 0
	})
	return rolled
}

// pollDiscovered waits for the node to pin a successor past the given pin —
// the discovery the founder's signed messages carry.
func pollDiscovered(
	t *testing.T,
	n *assemblyNode,
	isd addr.ISD,
	pin cppki.SignedTRC,
) cppki.SignedTRC {

	t.Helper()
	var discovered cppki.SignedTRC
	Poll(t, "the successor to spread", func() bool {
		newest, err := n.app.TrustDB().SignedTRC(context.Background(), cppki.TRCID{
			ISD: isd, Base: scrypto.LatestVer, Serial: scrypto.LatestVer,
		})
		if err != nil || newest.IsZero() {
			return false
		}
		discovered = newest
		return newest.TRC.ID.Serial > pin.TRC.ID.Serial
	})
	return discovered
}

// ownChain returns the node's own chain valid now.
func ownChain(t *testing.T, n *assemblyNode) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	Poll(t, "the node's own chain", func() bool {
		chains, err := n.app.TrustDB().Chains(context.Background(), trustdb.ChainQuery{
			IA: n.app.IA(),
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range chains {
			if chain == nil || c[0].NotAfter.After(chain[0].NotAfter) {
				chain = c
			}
		}
		return chain != nil
	})
	return chain
}

// covers reports whether one of the core keys covers the certificate.
func covers(keys trust.CoreKeys, cert *x509.Certificate) bool {
	for _, key := range []crypto.Signer{keys.Sensitive, keys.Regular, keys.Root} {
		if trust.KeyMatchesCert(key, cert) {
			return true
		}
	}
	return false
}
