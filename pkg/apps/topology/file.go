package topology

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/links"
)

// FileWatchInterval is the link-set's modification-time poll: the one watch
// the static provider keeps, a constant — no reload signals, no API, no
// operator tuning.
const FileWatchInterval = 10 * time.Second

// FileConfig configures the file provider.
type FileConfig struct {
	// Core marks the founding core: its draw is its network's name already.
	Core bool
	// Path is the link-set file's path.
	Path string
	// Notify signals a store change — every mutation lands as a data plane
	// generation swap.
	Notify func()
	// WatchInterval overrides the modification-time poll; zero keeps the
	// constant. The integration tests pace it.
	WatchInterval time.Duration
}

// File is the static topology provider (ADR 0009): a link-set file the
// operator vouches for, reconciled into the store the way the old
// configured interfaces worked — an entry named in the file established
// with its pinned addresses, an entry absent from it retired, every change
// a data plane generation swap the node already performs. It runs none of
// the measured machinery: no rendezvous acceptor, no node directory, no
// selection loop; the entries arrive named and established — the operator's
// vouch — so liveness and beaconing treat a static link exactly as a
// measured one, the drafts' exchanges alone crossing the wire.
type File struct {
	cfg FileConfig
	pcs Pieces

	// read is the file's parsed state of the last good read, kept so an
	// unchanged modification time writes nothing and a changed one
	// reconciles against what the store holds.
	entries []fileEntry
	modTime time.Time
	size    int64
}

// NewFile builds the static provider.
func NewFile(cfg FileConfig) *File {
	return &File{cfg: cfg}
}

// Entry is one link of the link-set: the neighbor's ISD-AS — the vouch —
// and the link's two underlay addresses, both pinned because the pairing
// must be writable on both ends: the acceptor that would exchange allocated
// addresses belongs to the measured provider, so a static link has no
// handshake — each node's file names the other's address. The interface ID
// is optional, allocated monotonically when absent. Identity, keys, and the
// node's bind arguments never ride the file: it is a policy artifact, not
// the retired configuration file reborn.
type Entry struct {
	// IA is the neighbor's ISD-AS.
	IA string `json:"ia"`
	// Local is the link's local underlay address, pinned — bound by every
	// generation as an allocated address is.
	Local string `json:"local"`
	// Remote is the neighbor's link underlay address the socket connects
	// to.
	Remote string `json:"remote"`
	// Interface optionally names the local interface ID.
	Interface *uint16 `json:"interface,omitempty"`
}

// fileEntry is a link-set entry in the provider's own form, parsed and
// validated.
type fileEntry struct {
	ia     addr.IA
	local  netip.AddrPort
	remote netip.AddrPort
	ifID   uint16 // zero: the store allocates
}

// readLinkSet reads and parses the link-set: unknown members are refused
// rather than silently ignored — the WireGuard configuration's discipline —
// so a file still naming a retired field fails loudly.
func readLinkSet(path string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the link-set: %w", err)
	}
	var entries []Entry
	if err := json.Unmarshal(raw, &entries, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parsing the link-set: %w", err)
	}
	return entries, nil
}

// linkSet validates the file's entries into the provider's own form.
func linkSet(entries []Entry) ([]fileEntry, error) {
	out := make([]fileEntry, 0, len(entries))
	for i, e := range entries {
		ia, err := addr.ParseIA(e.IA)
		if err != nil {
			return nil, fmt.Errorf("parsing entry %d's ISD-AS: %w", i, err)
		}
		local, err := netip.ParseAddrPort(e.Local)
		if err != nil {
			return nil, fmt.Errorf("parsing entry %d's local address: %w", i, err)
		}
		remote, err := netip.ParseAddrPort(e.Remote)
		if err != nil {
			return nil, fmt.Errorf("parsing entry %d's remote address: %w", i, err)
		}
		entry := fileEntry{ia: ia, local: local, remote: remote}
		if e.Interface != nil {
			if *e.Interface == 0 {
				return nil, fmt.Errorf("entry %d's interface ID must be positive", i)
			}
			entry.ifID = *e.Interface
		}
		out = append(out, entry)
	}
	return out, nil
}

// load reads and parses the file, recording its state for the poll's
// change detection.
func (f *File) load() error {
	entries, err := readLinkSet(f.cfg.Path)
	if err != nil {
		return err
	}
	parsed, err := linkSet(entries)
	if err != nil {
		return err
	}
	info, err := os.Stat(f.cfg.Path)
	if err != nil {
		return err
	}
	f.entries = parsed
	f.modTime = info.ModTime()
	f.size = info.Size()
	return nil
}

// CompleteIdentity completes a first start's identity offline, per the
// ADR: the first entry's ISD with the node's drawn AS, so the entries'
// completed ISD-ASes name a network the node belongs to. The founding
// core's draw is its network's name already — a static lab starts its
// founding node first, or any node whose name is already final; the
// ordering is the file provider's one operational ceremony.
func (f *File) CompleteIdentity(_ context.Context, ia addr.IA) (addr.IA, error) {
	if f.cfg.Core {
		return ia, nil
	}
	if err := f.load(); err != nil {
		return ia, err
	}
	if len(f.entries) == 0 {
		return ia, fmt.Errorf(
			"a non-core's first start needs a non-empty --link-set: the neighbor requirement")
	}
	completed, err := addr.IAFrom(f.entries[0].ia.ISD(), ia.AS())
	if err != nil {
		return ia, err
	}
	if completed != ia {
		slog.Info("Completed the identity with the link-set's ISD",
			"isd_as", completed, "provisional", ia)
	}
	return completed, nil
}

// Wire stores the phases' products; the store is the piece the
// reconciliation lands in.
func (f *File) Wire(pcs Pieces) {
	f.pcs = pcs
}

// Seed reconciles the link-set into the store before the first data plane
// generation builds: the operator vouches, so a named entry is established
// outright — no candidate window, no evidence check — with its pinned
// addresses and optional interface ID.
func (f *File) Seed(ctx context.Context) error {
	if len(f.entries) == 0 && f.modTime.IsZero() {
		if err := f.load(); err != nil {
			return err
		}
	}
	return f.reconcile(ctx)
}

// Mounts serves none: the static provider mounts nothing on the endpoint.
func (f *File) Mounts() ([]controlplane.Mount, error) {
	return nil, nil
}

// Run watches the file's modification time on the constant poll and
// reconciles the store when it moves; a read or parse that fails logs and
// keeps the last good topology — a malformed edit never strands the links
// the store already serves.
func (f *File) Run(ctx context.Context) {
	interval := f.cfg.WatchInterval
	if interval == 0 {
		interval = FileWatchInterval
	}
	for sleepCtx(ctx, interval) {
		info, err := os.Stat(f.cfg.Path)
		if err != nil {
			slog.Error("Watching the link-set", "err", err)
			continue
		}
		if info.ModTime().Equal(f.modTime) && info.Size() == f.size {
			continue
		}
		if err := f.load(); err != nil {
			slog.Error("Reading the changed link-set", "err", err)
			continue
		}
		if err := f.reconcile(ctx); err != nil {
			slog.Error("Reconciling the link-set", "err", err)
		}
	}
}

// Close releases nothing: the provider holds no sockets.
func (f *File) Close() error { return nil }

// reconcile lands the file's link-set in the store: an entry named in the
// file is established with its addresses — an unchanged one untouched, an
// address change recorded without a new interface ID, the ID being the
// store's key — and an entry absent from the file retires, its interface ID
// held back by the store's existing rule. A pass that changed nothing
// writes nothing; one that did notifies exactly one generation swap.
func (f *File) reconcile(ctx context.Context) error {
	store := f.pcs.Store
	if store == nil {
		return errors.New("the file provider was wired with no store")
	}
	changed := false
	named := make(map[addr.IA]bool, len(f.entries))
	for _, e := range f.entries {
		named[e.ia] = true
		entry, err := store.ByNeighbor(ctx, e.ia)
		if err != nil {
			return err
		}
		if entry == nil {
			if err := store.Insert(ctx, &links.Link{
				NeighborIA: e.ia,
				IfID:       e.ifID,
				Local:      e.local,
				Remote:     e.remote,
				State:      links.StateEstablished,
			}); err != nil {
				return err
			}
			changed = true
			slog.Info("Established a vouched link", "neighbor", e.ia,
				"local", e.local, "remote", e.remote)
			continue
		}
		if entry.Local == e.local && entry.Remote == e.remote &&
			entry.State == links.StateEstablished {
			continue
		}
		if e.ifID != 0 && e.ifID != entry.IfID {
			// The ID is the store's key: an edit that moves it needs the
			// entry retired first, which removing it from the file does.
			slog.Warn("The link-set's interface ID differs from the entry's",
				"neighbor", e.ia, "entry", entry.IfID, "file", e.ifID)
		}
		entry.Local = e.local
		entry.Remote = e.remote
		entry.State = links.StateEstablished
		if err := store.Update(ctx, entry); err != nil {
			return err
		}
		changed = true
		slog.Info("Recorded the link-set's addresses", "neighbor", e.ia,
			"local", e.local, "remote", e.remote)
	}
	existing, err := store.All(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, l := range existing {
		if !l.Live() || named[l.NeighborIA] {
			continue
		}
		l.State = links.StateRetired
		l.Retired = now
		if err := store.Update(ctx, l); err != nil {
			return err
		}
		changed = true
		slog.Info("Retired a link absent from the link-set", "neighbor", l.NeighborIA,
			"interface", l.IfID)
	}
	if changed && f.cfg.Notify != nil {
		f.cfg.Notify()
	}
	return nil
}
