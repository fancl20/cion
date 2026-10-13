package testnetwork

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/fs"
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
	"github.com/fancl20/cion/pkg/statefile"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// seedValidity is the pre-seeded material's lifetime: short enough to sit
// inside the rotation threshold, long enough to outlive the lab.
const seedValidity = 6 * time.Hour

// seedFounder writes the founding core's pre-seeded state: the identity, the
// four live keys, and the trust database pinning the base TRC the
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

	// The validity every seeded certificate covers, the latest start to the
	// earliest end: each mint takes its own truncated clock, and the TRC's
	// window must sit inside each certificate's own whatever second a mint
	// fell on.
	validity := cppki.Validity{NotBefore: authCert.NotBefore, NotAfter: authCert.NotAfter}
	for _, cert := range []*x509.Certificate{sensitive, regular, root} {
		if cert.NotBefore.After(validity.NotBefore) {
			validity.NotBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(validity.NotAfter) {
			validity.NotAfter = cert.NotAfter
		}
	}
	trc := cppki.TRC{
		Version:  1,
		ID:       cppki.TRCID{ISD: founderIA.ISD(), Base: 1, Serial: 1},
		Validity: validity,
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
	if _, err := db.InsertTRC(t.Context(), signed); err != nil {
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
	persistCertFile(t, state, trust.RegularVotingCertFile, cert)
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
	// Whole seconds and a backdate, the genesis certificates' own shape.
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
	// Whole seconds and a backdate, the genesis certificates' own shape.
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
	if err := statefile.Write(filepath.Join(state, "keys", name),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
}

// persistCertFile writes a certificate under the state directory's keys
// folder.
func persistCertFile(t *testing.T, state, name string, cert *x509.Certificate) {
	t.Helper()
	if err := statefile.Write(filepath.Join(state, "keys", name),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})); err != nil {
		t.Fatal(err)
	}
}

// TestCoresRotateByTRCUpdate is the rotation seam's integration proof: a
// founder and an authoritative core whose state is pre-seeded so each
// holder's material approaches expiry — the founder's watch casts its own
// roll by sensitive update, the authoritative's submits its own by regular
// update, both pin, and the ladder's serials stay monotone; the founder's
// pre-pin chain verifies through the window its rung opened; a third node
// discovers the successors from the founder's signed messages, and it and
// the founder leave the replaced root; a node enrolled after the founder's
// pin holds a chain under the fresh root; replacing the authoritative's live
// voting pair fires the mismatch roll at the next pass, a sensitive update
// the founder votes on at its admission policy's allow.
func TestCoresRotateByTRCUpdate(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
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

	// The founding core, its material pre-seeded: the founder's watch rolls
	// its own three inside the cast it signs itself, and its admission
	// policy allows the vote the mismatch roll below asks for. It and the
	// two nodes below inspect their chains at the enrollment pace, so each
	// leaves the replaced root within the lab's polls.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = founderState
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.EnrollAuth = votingAuth
		cfg.Pacing.EnrollmentInspect = EnrollRetry
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
		cfg.RootCAs = wpki.Pool
		cfg.Pacing.EnrollmentInspect = EnrollRetry
	})
	// A third node joining the founder, to watch the successors spread.
	c := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
		cfg.Pacing.EnrollmentInspect = EnrollRetry
	})

	// The founder's own chain issued synchronously at boot, under the seeded
	// root, is the chain issued before the pin. The founder leaves that root
	// at its first pass after its roll, so its newest chain may already be
	// under the fresh one.
	preChain := chainUnder(t, a, base)

	// Both holders roll their own material: the founder's three inside its
	// own cast, the authoritative's one through its submission.
	founderRolled := pollRolled(t, a, founderIA, base)
	authRolled := pollRolled(t, b, authIA, base)

	// The ladder's serials stay monotone and each rung's type follows its
	// roller: every successor the rollers pinned verifies against the pin
	// before it, a rung that changes the founder's certificates is a
	// sensitive update, and one that changes only the authoritative's is a
	// regular update its old key voted on. The founder's rung is the one
	// that replaced the root.
	var founderRung, founderPred cppki.SignedTRC
	pred := base
	top := max(founderRolled.TRC.ID.Serial, authRolled.TRC.ID.Serial)
	for serial := scrypto.Version(2); serial <= top; serial++ {
		successor := pinnedRung(t, a, founderIA.ISD(), serial)
		if err := successor.Verify(&pred.TRC); err != nil {
			t.Fatalf("rung %d does not verify against its predecessor: %v", serial, err)
		}
		want := cppki.RegularUpdate
		if !slices.EqualFunc(trust.CertsOf(successor.TRC, founderIA),
			trust.CertsOf(pred.TRC, founderIA), (*x509.Certificate).Equal) {

			want = cppki.SensitiveUpdate
			founderRung, founderPred = successor, pred
		}
		if got := updateType(t, successor, pred); got != want {
			t.Errorf("rung %d is a %v update, want a %v one", serial, got, want)
		}
		pred = successor
	}
	if founderRung.IsZero() {
		t.Fatal("no rung of the ladder changes the founder's certificates")
	}
	// The rolls promoted: each holder's live files hold the keys its
	// successor's certificates cover, and no staged file remains. A roll
	// pins its successor before it promotes, so the polls wait for the
	// promotion, which also keeps a late promotion from overwriting the
	// stranger pair below.
	Poll(t, "the founder's roll to promote", func() bool {
		if hasStaged(t, founderState) {
			return false
		}
		keys, err := trust.LoadOrCreateCoreKeys(founderState)
		if err != nil {
			t.Fatal(err)
		}
		for _, cert := range trust.CertsOf(founderRolled.TRC, founderIA) {
			if !covers(keys, cert) {
				return false
			}
		}
		return true
	})
	Poll(t, "the authoritative's roll to promote", func() bool {
		if hasStaged(t, authState) {
			return false
		}
		key, err := trust.LoadOrCreateVotingKey(authState)
		if err != nil {
			t.Fatal(err)
		}
		cert := trust.CertsOf(authRolled.TRC, authIA)
		return len(cert) == 1 && trust.KeyMatchesCert(key, cert[0])
	})

	// The founder's rung opened a grace window for the replaced root: the
	// pre-pin chain verifies against the rung beside its predecessor, and
	// against the rung alone it does not.
	if err := cppki.VerifyChain(preChain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&founderRung.TRC, &founderPred.TRC}, CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("the pre-pin chain does not verify through the founder's window: %v", err)
	}
	if err := cppki.VerifyChain(preChain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&founderRung.TRC}, CurrentTime: time.Now(),
	}); err == nil {
		t.Error("the pre-pin chain verified against the founder's rung alone, want the window carrying it")
	}

	// The third node discovers the successors from the founder's signed
	// messages — the cited TRC the verifier reports — and both it and the
	// founder leave the replaced root: their own chains verify against their
	// newest pinned TRC alone.
	pollDiscovered(t, c, founderIA.ISD(), base)
	for _, n := range []struct {
		name string
		node *assemblyNode
	}{{"founder", a}, {"third node", c}} {
		Poll(t, "the "+n.name+"'s chain to leave the replaced root", func() bool {
			return anchoredInNewest(t, n.node, base)
		})
	}

	// A node enrolled after the founder's pin holds a chain under the fresh
	// root: it verifies against the successor the founder pinned.
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
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

	// Replacing the authoritative's live voting pair fires the mismatch roll
	// at the next pass, whatever the calendar says: a sensitive update, for
	// the live key no longer votes for the certificate the newest TRC names.
	stranger := mintKey(t)
	strangerCert := mintVotingCert(t, authIA, stranger, false)
	persistKeyFile(t, authState, trust.RegularKeyFile, stranger)
	persistCertFile(t, authState, trust.RegularVotingCertFile, strangerCert)
	mismatch := pollRolled(t, b, authIA, authRolled)
	if mismatch.TRC.ID.Serial <= authRolled.TRC.ID.Serial {
		t.Fatalf("the mismatch roll's serial = %d, want past the landed roll's %d",
			mismatch.TRC.ID.Serial, authRolled.TRC.ID.Serial)
	}
	pred = pinnedRung(t, a, founderIA.ISD(), mismatch.TRC.ID.Serial-1)
	if got := updateType(t, mismatch, pred); got != cppki.SensitiveUpdate {
		t.Errorf("the mismatch roll is a %v update, want a sensitive one", got)
	}
}

// TestFounderBootPromotesStagedRoll checks a founder stopped between its
// roll's pin and the promotion: booted again, it promotes the staged keys,
// so its live keys cover the successor's certificates and no staged file
// remains, and a node that joins it holds a chain that verifies against the
// successor alone.
func TestFounderBootPromotesStagedRoll(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB := hostSlot(t), hostSlot(t)
	state := t.TempDir()
	boot := func() *assemblyNode {
		return bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.Core = true
			cfg.State = state
			cfg.Internal = PinnedUDPAddrOn(t, ipA)
			cfg.Control = FreeUDPAddrOn(t, ipA)
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		})
	}

	// The founder starts and stops, and its roll pins on the stopped node's
	// state directory, leaving the staged keys unpromoted.
	a := boot()
	ia := a.app.IA()
	a.stop(t)
	ctx := t.Context()
	db, err := trustbbolt.New(filepath.Join(state, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pred, err := db.SignedTRC(ctx, cppki.TRCID{
		ISD: ia.ISD(), Base: scrypto.LatestVer, Serial: scrypto.LatestVer,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rolled, err := trust.RotateCoreKeys(ctx, db, state, ia, pred)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if !hasStaged(t, state) {
		t.Fatal("the roll left no staged file")
	}

	// The second boot promotes the staged keys.
	a = boot()
	keys, err := trust.LoadOrCreateCoreKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range trust.CertsOf(rolled.TRC, ia) {
		if !covers(keys, cert) {
			t.Errorf("the live keys do not cover the successor's %s", cert.Subject)
		}
	}
	if hasStaged(t, state) {
		t.Error("the staged file outlived the boot")
	}

	// A node that joins the founder holds a chain under the successor's
	// root.
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	Poll(t, "the joiner to enroll", func() bool {
		return holdsAssemblyChain(t, b, b.app.IA())
	})
	if err := cppki.VerifyChain(ownChain(t, b), cppki.VerifyOptions{
		TRC: []*cppki.TRC{&rolled.TRC}, CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("the joiner's chain does not verify against the successor alone: %v", err)
	}
}

// pinnedRung returns the TRC of the ISD's base 1 the node pins at the
// serial, failing the test when it pins none.
func pinnedRung(
	t *testing.T,
	n *assemblyNode,
	isd addr.ISD,
	serial scrypto.Version,
) cppki.SignedTRC {

	t.Helper()
	trc, err := n.app.TrustDB().SignedTRC(t.Context(),
		cppki.TRCID{ISD: isd, Base: 1, Serial: serial})
	if err != nil {
		t.Fatal(err)
	}
	if trc.IsZero() {
		t.Fatalf("serial %d of ISD %d is not pinned", serial, isd)
	}
	return trc
}

// updateType returns the type the successor's update classifies as against
// its predecessor.
func updateType(t *testing.T, successor, pred cppki.SignedTRC) cppki.UpdateType {
	t.Helper()
	update, err := successor.TRC.ValidateUpdate(&pred.TRC)
	if err != nil {
		t.Fatal(err)
	}
	return update.Type
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
		newest, err := n.app.TrustDB().SignedTRC(t.Context(), cppki.TRCID{
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
		newest, err := n.app.TrustDB().SignedTRC(t.Context(), cppki.TRCID{
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
		chains, err := n.app.TrustDB().Chains(t.Context(), trustdb.ChainQuery{
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

// chainUnder returns the node's own chain that verifies against the TRC's
// roots, polling until the node holds one.
func chainUnder(t *testing.T, n *assemblyNode, trc cppki.SignedTRC) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	Poll(t, "the node's chain under the TRC's roots", func() bool {
		chains, err := n.app.TrustDB().Chains(t.Context(), trustdb.ChainQuery{
			IA: n.app.IA(),
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range chains {
			if cppki.VerifyChain(c, cppki.VerifyOptions{
				TRC: []*cppki.TRC{&trc.TRC}, CurrentTime: time.Now(),
			}) == nil {
				chain = c
				return true
			}
		}
		return false
	})
	return chain
}

// anchoredInNewest reports whether the node's newest chain verifies against
// its newest pinned TRC alone, once that TRC is a successor of the base.
func anchoredInNewest(t *testing.T, n *assemblyNode, base cppki.SignedTRC) bool {
	t.Helper()
	ctx := t.Context()
	newest, err := n.app.TrustDB().SignedTRC(ctx, cppki.TRCID{
		ISD: base.TRC.ID.ISD, Base: scrypto.LatestVer, Serial: scrypto.LatestVer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if newest.TRC.ID.Serial <= base.TRC.ID.Serial {
		return false
	}
	chain, err := trust.NewestChain(ctx, n.app.TrustDB(), n.app.IA(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return chain != nil && cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&newest.TRC}, CurrentTime: time.Now(),
	}) == nil
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

// hasStaged reports whether the state directory holds a staged file: a roll
// not yet promoted.
func hasStaged(t *testing.T, state string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(state, "keys", trust.StagedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}
