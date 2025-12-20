package dbtest

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/trust"
)

// chainEqual compares two certificate chains for equality
func chainEqual(a, b []*x509.Certificate) bool {
	return slices.EqualFunc(a, b, func(ca, cb *x509.Certificate) bool {
		return ca.Equal(cb)
	})
}

// chainsEqual compares two slices of certificate chains for equality, ignoring order
func chainsEqual(a, b [][]*x509.Certificate) bool {
	f := func(i, j []*x509.Certificate) int {
		return slices.CompareFunc(i, j, func(ci, cj *x509.Certificate) int {
			return slices.Compare(ci.Raw, cj.Raw)
		})
	}

	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, f)
	slices.SortFunc(b, f)

	return slices.EqualFunc(a, b, chainEqual)
}

var (
	// DefaultTimeout is the default timeout for running the test harness.
	DefaultTimeout = 5 * time.Second
	// DefaultRelPath is the default relative path to the test data.
	DefaultRelPath = "../dbtest/testdata"
)

// Config holds the configuration for the trust database testing harness.
type Config struct {
	Timeout time.Duration
	RelPath string
}

// InitDefaults initializes the default values for the config.
func (cfg *Config) InitDefaults() {
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.RelPath == "" {
		cfg.RelPath = DefaultRelPath
	}
}

func (cfg *Config) filePath(name string) string {
	return filepath.Join(cfg.RelPath, name)
}

// TestableDB extends the trust db interface with methods that are needed for testing.
type TestableDB interface {
	trust.DB
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// Run should be used to test any implementation of the trust.DB interface.
// An implementation interface should at least have one test method that calls
// this test-suite.
func Run(t *testing.T, db TestableDB, cfg Config) {
	cfg.InitDefaults()
	tests := map[string]func(*testing.T, trust.DB, Config){
		"test TRC":   testTRC,
		"test chain": testChain,
	}
	// Run test suite on DB directly.
	for name, test := range tests {
		t.Run("DB: "+name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			test(t, db, cfg)
			db.Close()
		})
	}
}

func testTRC(t *testing.T, db trust.DB, cfg Config) {
	trc := loadTRCFile(t, "ISD1-B1-S1.trc", cfg)

	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()

	in, err := db.InsertTRC(ctx, trc)
	if err != nil {
		t.Fatalf("InsertTRC failed: %v", err)
	}
	if !in {
		t.Fatal("InsertTRC should return true for new TRC")
	}

	t.Run("InsertTRC", func(t *testing.T) {
		t.Run("Insert existing", func(t *testing.T) {
			in, err := db.InsertTRC(ctx, trc)
			if err != nil {
				t.Errorf("InsertTRC failed: %v", err)
			}
			if in {
				t.Error("InsertTRC should return false for existing TRC")
			}
		})
		t.Run("Insert existing modified", func(t *testing.T) {
			trcCopy := trc
			trcCopy.TRC.Raw = append([]byte{}, trc.TRC.Raw...)
			trcCopy.TRC.Raw[0] = trcCopy.TRC.Raw[0] ^ 0xFF
			in, err := db.InsertTRC(ctx, trcCopy)
			if err == nil {
				t.Error("InsertTRC should return error for modified TRC")
			}
			if in {
				t.Error("InsertTRC should return false for modified TRC")
			}
		})
	})
	t.Run("SignedTRC", func(t *testing.T) {
		t.Run("Non existing TRC", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
				ISD:    trc.TRC.ID.ISD + 1,
				Base:   trc.TRC.ID.Base,
				Serial: trc.TRC.ID.Serial,
			})
			if err != nil {
				t.Errorf("SignedTRC failed: %v", err)
			}
			if !cmp.Equal(aTRC, cppki.SignedTRC{}) {
				t.Errorf("SignedTRC should return empty TRC for non-existing TRC, got %v", aTRC)
			}
		})
		t.Run("Invalid request", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
				ISD:    trc.TRC.ID.ISD,
				Base:   scrypto.LatestVer,
				Serial: trc.TRC.ID.Serial,
			})
			if err == nil {
				t.Error("SignedTRC should return error for invalid request")
			}
			if !cmp.Equal(aTRC, cppki.SignedTRC{}) {
				t.Errorf("SignedTRC should return empty TRC for invalid request, got %v", aTRC)
			}
		})
		t.Run("Existing TRC", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, trc.TRC.ID)
			if err != nil {
				t.Errorf("SignedTRC failed: %v", err)
			}
			if !cmp.Equal(trc, aTRC) {
				t.Errorf("SignedTRC should return the inserted TRC, got %v, want %v", aTRC, trc)
			}
		})
		t.Run("Latest TRC single", func(t *testing.T) {
			aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
				ISD:    trc.TRC.ID.ISD,
				Base:   scrypto.LatestVer,
				Serial: scrypto.LatestVer,
			})
			if err != nil {
				t.Errorf("SignedTRC failed: %v", err)
			}
			if !cmp.Equal(trc, aTRC) {
				t.Errorf("SignedTRC should return the inserted TRC, got %v, want %v", aTRC, trc)
			}
		})
		t.Run("Latest TRC multiple in DB", func(t *testing.T) {
			t.Run("same base, higher serial", func(t *testing.T) {
				trcS5 := trc
				trcS5.TRC.ID.Serial = 5
				rawS5, err := trcS5.Encode()
				if err != nil {
					t.Fatalf("Encode failed: %v", err)
				}
				trcS5, err = cppki.DecodeSignedTRC(rawS5)
				if err != nil {
					t.Fatalf("DecodeSignedTRC failed: %v", err)
				}
				_, err = db.InsertTRC(ctx, trcS5)
				if err != nil {
					t.Fatalf("InsertTRC failed: %v", err)
				}

				aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
					ISD:    trc.TRC.ID.ISD,
					Base:   scrypto.LatestVer,
					Serial: scrypto.LatestVer,
				})
				if err != nil {
					t.Errorf("SignedTRC failed: %v", err)
				}
				if !cmp.Equal(trcS5, aTRC) {
					t.Errorf("SignedTRC should return the TRC with higher serial, got %v, want %v", aTRC, trcS5)
				}
			})
			t.Run("higher base, lower serial", func(t *testing.T) {
				trcB2S4 := trc
				trcB2S4.TRC.ID.Base, trcB2S4.TRC.ID.Serial = 2, 4
				rawB2S4, err := trcB2S4.Encode()
				if err != nil {
					t.Fatalf("Encode failed: %v", err)
				}
				trcB2S4, err = cppki.DecodeSignedTRC(rawB2S4)
				if err != nil {
					t.Fatalf("DecodeSignedTRC failed: %v", err)
				}
				_, err = db.InsertTRC(ctx, trcB2S4)
				if err != nil {
					t.Fatalf("InsertTRC failed: %v", err)
				}

				aTRC, err := db.SignedTRC(ctx, cppki.TRCID{
					ISD:    trc.TRC.ID.ISD,
					Base:   scrypto.LatestVer,
					Serial: scrypto.LatestVer,
				})
				if err != nil {
					t.Errorf("SignedTRC failed: %v", err)
				}
				if !cmp.Equal(trcB2S4, aTRC) {
					t.Errorf("SignedTRC should return the TRC with higher base, got %v, want %v", aTRC, trcB2S4)
				}
			})
		})
	})
}

func testChain(t *testing.T, db trust.DB, cfg Config) {
	// first load all chains
	bern1Chain := loadChainFiles(t, "bern", 1, cfg)
	bern2Chain := loadChainFiles(t, "bern", 2, cfg)
	bern3Chain := loadChainFiles(t, "bern", 3, cfg)
	geneva1Chain := loadChainFiles(t, "geneva", 1, cfg)
	geneva2Chain := loadChainFiles(t, "geneva", 2, cfg)

	ctx, cancelF := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancelF()

	// prefill DB with chains that we expect to exist.
	in, err := db.InsertChain(ctx, bern1Chain)
	if err != nil {
		t.Fatalf("InsertChain failed: %v", err)
	}
	if !in {
		t.Fatal("InsertChain should return true for new chain")
	}

	t.Run("InsertChain", func(t *testing.T) {
		t.Run("Invalid chain length", func(t *testing.T) {
			in, err := db.InsertChain(ctx, geneva1Chain[:1])
			if in {
				t.Error("InsertChain should return false for invalid chain length")
			}
			if err == nil {
				t.Error("InsertChain should return error for invalid chain length")
			}
			in, err = db.InsertChain(ctx, append(geneva1Chain, geneva2Chain...))
			if in {
				t.Error("InsertChain should return false for invalid chain length")
			}
			if err == nil {
				t.Error("InsertChain should return error for invalid chain length")
			}
		})
		t.Run("New chain", func(t *testing.T) {
			in, err := db.InsertChain(ctx, geneva1Chain)
			if err != nil {
				t.Errorf("InsertChain failed: %v", err)
			}
			if !in {
				t.Error("InsertChain should return true for new chain")
			}
		})
		t.Run("Insert existing chain", func(t *testing.T) {
			in, err := db.InsertChain(ctx, bern1Chain)
			if err != nil {
				t.Errorf("InsertChain failed: %v", err)
			}
			if in {
				t.Error("InsertChain should return false for existing chain")
			}
		})
	})
	t.Run("Chain", func(t *testing.T) {
		t.Run("Non existing chain", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:111"),
				SubjectKeyID: []byte("non-existing"),
				Validity: cppki.Validity{
					NotBefore: time.Now(),
					NotAfter:  time.Now(),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			if len(chains) != 0 {
				t.Errorf("Chains should return empty slice for non-existing chain, got %v", chains)
			}
		})
		t.Run("Existing chain no overlap", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 25, 14, 0, 0, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 27, 0, 0, 0, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected := [][]*x509.Certificate{bern1Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return the expected chain, got %v, want %v", chains, expected)
			}
		})
		t.Run("Existing chain query time out of range", func(t *testing.T) {
			// insert another chain to make sure it is not found
			_, err = db.InsertChain(ctx, bern2Chain)
			if err != nil {
				t.Fatalf("InsertChain failed: %v", err)
			}
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 27, 12, 0, 1, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 27, 12, 0, 1, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			if len(chains) != 0 {
				t.Errorf("Chains should return empty slice for time out of range, got %v", chains)
			}
			chains, err = db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 24, 11, 59, 59, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 24, 11, 59, 59, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			if len(chains) != 0 {
				t.Errorf("Chains should return empty slice for time out of range, got %v", chains)
			}
		})
		t.Run("All certificate chains", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected := [][]*x509.Certificate{bern1Chain, geneva1Chain, bern2Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return all chains, got %v, want %v", chains, expected)
			}
		})
		t.Run("Active certificate chain in a given time", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 26, 11, 59, 59, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 26, 11, 59, 59, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected := [][]*x509.Certificate{bern1Chain, geneva1Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return active chains, got %v, want %v", chains, expected)
			}
		})
		t.Run("certificate chain for a given ISD-AS", func(t *testing.T) {
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA: addr.MustParseIA("1-ff00:0:110"),
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected := [][]*x509.Certificate{bern1Chain, bern2Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return chains for given ISD-AS, got %v, want %v", chains, expected)
			}
		})
		t.Run("Existing chain overlap different key", func(t *testing.T) {
			_, err := db.InsertChain(ctx, bern2Chain)
			if err != nil {
				t.Fatalf("InsertChain failed: %v", err)
			}
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern1Chain[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected := [][]*x509.Certificate{bern1Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return the expected chain, got %v, want %v", chains, expected)
			}
			chains, err = db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern2Chain[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 26, 13, 0, 0, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected = [][]*x509.Certificate{bern2Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return the expected chain, got %v, want %v", chains, expected)
			}
		})
		t.Run("Existing chain overlap same key", func(t *testing.T) {
			_, err := db.InsertChain(ctx, bern3Chain)
			if err != nil {
				t.Fatalf("InsertChain failed: %v", err)
			}
			chains, err := db.Chains(ctx, trust.ChainQuery{
				IA:           addr.MustParseIA("1-ff00:0:110"),
				SubjectKeyID: bern3Chain[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: time.Date(2020, 6, 28, 13, 0, 0, 0, time.UTC),
					NotAfter:  time.Date(2020, 6, 28, 13, 0, 0, 0, time.UTC),
				},
			})
			if err != nil {
				t.Errorf("Chains failed: %v", err)
			}
			expected := [][]*x509.Certificate{bern2Chain, bern3Chain}
			if !chainsEqual(chains, expected) {
				t.Errorf("Chains should return the expected chains, got %v, want %v", chains, expected)
			}
		})
	})
}

func loadTRCFile(t *testing.T, file string, cfg Config) cppki.SignedTRC {
	data, err := os.ReadFile(cfg.filePath(file))
	if err != nil {
		t.Fatalf("Failed to read TRC file %s: %v", file, err)
	}
	trc, err := cppki.DecodeSignedTRC(data)
	if err != nil {
		t.Fatalf("Failed to decode TRC from file %s: %v", file, err)
	}
	return trc
}

func loadChainFiles(t *testing.T, org string, asVersion int, cfg Config) []*x509.Certificate {
	return []*x509.Certificate{
		loadCertFile(t, filepath.Join(org, fmt.Sprintf("cp-as%d.crt", asVersion)), cfg),
		loadCertFile(t, filepath.Join(org, "cp-ca.crt"), cfg),
	}
}

func loadCertFile(t *testing.T, name string, cfg Config) *x509.Certificate {
	certs, err := cppki.ReadPEMCerts(cfg.filePath(name))
	if err != nil {
		t.Fatalf("Failed to read cert file %s: %v", name, err)
	}
	if len(certs) != 1 {
		t.Fatalf("Expected 1 certificate in file %s, got %d", name, len(certs))
	}
	return certs[0]
}
