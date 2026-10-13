package trust

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/libs/statefile"
)

// stagedFileHeader is the PEM header of a staged block naming the live file
// the block replaces.
const stagedFileHeader = "File"

// PromoteStaged makes a roll's staged material live once the TRC names it:
// when the staged keys cover every certificate the TRC names for the ISD-AS,
// it writes each staged block to the live file its header names, removes
// the staged file, and reports true. It reports false, leaving any staged
// file in place, when none is staged or the TRC does not name it: the roll
// has not pinned, or the founder pinned a TRC the node has not learned yet.
// A promotion that stops partway is redone whole: each write gives a file
// the content it would hold anyway, and the staged file goes last.
func PromoteStaged(stateDir string, ia addr.IA, trc cppki.TRC) (bool, error) {
	blocks, err := readStaged(stateDir)
	if err != nil {
		return false, err
	}
	if blocks == nil {
		return false, nil
	}
	var keys []crypto.Signer
	for _, block := range blocks {
		if block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := parseKeyDER(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("%s: %s: %w", StagedFile, block.Headers[stagedFileHeader], err)
		}
		keys = append(keys, key)
	}
	named := CertsOf(trc, ia)
	if len(named) == 0 {
		return false, nil
	}
	for _, cert := range named {
		if !slices.ContainsFunc(keys, func(key crypto.Signer) bool {
			return KeyMatchesCert(key, cert)
		}) {
			return false, nil
		}
	}
	dir := keyDir(stateDir)
	for _, block := range blocks {
		live := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
		if err := statefile.Write(filepath.Join(dir, block.Headers[stagedFileHeader]), live); err != nil {
			return false, err
		}
	}
	if err := statefile.Remove(filepath.Join(dir, StagedFile)); err != nil {
		return false, err
	}
	return true, nil
}

// staged returns the block marked to replace the named live file.
func staged(file string, block *pem.Block) *pem.Block {
	block.Headers = map[string]string{stagedFileHeader: file}
	return block
}

// writeStaged stages the blocks in a single write, so a stop never leaves
// part of a set staged.
func writeStaged(stateDir string, blocks ...*pem.Block) error {
	var raw []byte
	for _, block := range blocks {
		raw = append(raw, pem.EncodeToMemory(block)...)
	}
	return statefile.Write(filepath.Join(keyDir(stateDir), StagedFile), raw)
}

// readStaged returns the staged blocks, nil when no file is staged.
func readStaged(stateDir string) ([]*pem.Block, error) {
	path := filepath.Join(keyDir(stateDir), StagedFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var blocks []*pem.Block
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Headers[stagedFileHeader] == "" {
			return nil, fmt.Errorf("%s: a block names no live file", path)
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return blocks, nil
}

// stagedBlock returns the staged block that replaces the named live file.
func stagedBlock(blocks []*pem.Block, file string) (*pem.Block, error) {
	i := slices.IndexFunc(blocks, func(block *pem.Block) bool {
		return block.Headers[stagedFileHeader] == file
	})
	if i < 0 {
		return nil, fmt.Errorf("%s holds no block for %s", StagedFile, file)
	}
	return blocks[i], nil
}

// stagedKey returns the staged key that replaces the named live file.
func stagedKey(blocks []*pem.Block, file string) (crypto.Signer, error) {
	block, err := stagedBlock(blocks, file)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyDER(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", StagedFile, file, err)
	}
	return key, nil
}

// stagedCert returns the staged certificate that replaces the named live
// file.
func stagedCert(blocks []*pem.Block, file string) (*x509.Certificate, error) {
	block, err := stagedBlock(blocks, file)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", StagedFile, file, err)
	}
	return cert, nil
}
