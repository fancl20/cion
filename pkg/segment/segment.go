// Package segment wraps the vendored control-plane protobuf path segment
// messages in CION-owned domain types: parsing path-construction beacons,
// creating and signing AS entries, computing hop-field MACs, and building
// data-plane paths from registered segments.
package segment

import (
	"context"
	"crypto/rand"
	"hash"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"google.golang.org/protobuf/proto"
)

const (
	// HopExpTime is the expiration time of created hop fields: a hop expires
	// (1+HopExpTime) hop-field units after the segment timestamp — six hours.
	HopExpTime uint8 = 63

	// MTU is the intra-AS MTU advertised in created AS entries (draft Section
	// 2.2.2.2; a fixed default, like the reference implementation's).
	MTU uint32 = 1500
)

// Signer signs an AS entry body with its associated data (draft Section
// 2.2.2.6); trust.Engine and trust.Signer satisfy it.
type Signer interface {
	Sign(ctx context.Context, msg []byte, associatedData ...[]byte) (*cryptopb.SignedMessage, error)
}

// PCB is a parsed path-construction beacon or path segment: the wire message
// with its segment information and AS entries decoded (control plane draft,
// Section 2.2).
type PCB struct {
	// PB is the wire form; it is mutated by AppendEntry.
	PB *cppb.PathSegment
	// Info is the decoded segment information.
	Info Info
	// Entries are the decoded AS entries, in construction direction.
	Entries []ASEntry
}

// Info is the decoded segment information (Section 2.2.1): the creation
// timestamp set by the originating core, and the 16-bit segment identifier
// seeding the hop-field MAC chain.
type Info struct {
	Timestamp time.Time
	ID        uint16
}

// ASEntry is one decoded AS entry: the signed body's fields together with the
// raw signed component they were extracted from.
type ASEntry struct {
	// IA is the ISD-AS of the AS that created this entry.
	IA addr.IA
	// Next is the ISD-AS of the downstream AS the beacon is forwarded to;
	// zero on a terminating entry (Section 3.1.1).
	Next addr.IA
	// IngressMTU is the MTU of the ingress interface in beaconing direction.
	IngressMTU uint32
	// Hop is the data-plane hop field of this entry.
	Hop path.HopField
	// Signed is the raw signed component, the input to signature
	// verification.
	Signed *cryptopb.SignedMessage
}

// NewPCB creates a fresh beacon's wire form: new segment information with a
// cryptographically random 16-bit segment ID and the creation timestamp
// (Section 2.2.1). The caller appends the originating core's AS entry.
func NewPCB(now time.Time) (*PCB, error) {
	id := make([]byte, 2)
	if _, err := rand.Read(id); err != nil {
		return nil, serrors.Wrap("generating segment ID", err)
	}
	return PCBWithID(now, uint16(id[0])<<8|uint16(id[1]))
}

// PCBWithID creates a fresh beacon's wire form with the given segment ID.
func PCBWithID(now time.Time, id uint16) (*PCB, error) {
	ts := util.TimeToSecs(now)
	info := &cppb.SegmentInformation{Timestamp: int64(ts), SegmentId: uint32(id)}
	raw, err := proto.Marshal(info)
	if err != nil {
		return nil, serrors.Wrap("packing segment information", err)
	}
	return &PCB{
		PB:      &cppb.PathSegment{SegmentInfo: raw},
		Info:    Info{Timestamp: util.SecsToTime(ts), ID: id},
		Entries: nil,
	}, nil
}

// ParsePCB decodes the wire message's segment information and AS entries.
func ParsePCB(pb *cppb.PathSegment) (*PCB, error) {
	if pb == nil {
		return nil, serrors.New("nil path segment")
	}
	var info cppb.SegmentInformation
	if err := proto.Unmarshal(pb.SegmentInfo, &info); err != nil {
		return nil, serrors.Wrap("parsing segment information", err)
	}
	if info.SegmentId > 0xffff {
		return nil, serrors.New("segment ID exceeds 16 bits", "segment_id", info.SegmentId)
	}
	p := &PCB{
		PB:      pb,
		Info:    Info{Timestamp: util.SecsToTime(uint32(info.Timestamp)), ID: uint16(info.SegmentId)},
		Entries: make([]ASEntry, 0, len(pb.AsEntries)),
	}
	for i, entry := range pb.AsEntries {
		if entry == nil || entry.Signed == nil {
			return nil, serrors.New("AS entry without signed component", "index", i)
		}
		parsed, err := parseASEntry(entry.Signed)
		if err != nil {
			return nil, serrors.Wrap("parsing AS entry", err, "index", i)
		}
		p.Entries = append(p.Entries, parsed)
	}
	return p, nil
}

// parseASEntry decodes the signed component into the entry's fields.
func parseASEntry(signed *cryptopb.SignedMessage) (ASEntry, error) {
	var hb cryptopb.HeaderAndBody
	if err := proto.Unmarshal(signed.HeaderAndBody, &hb); err != nil {
		return ASEntry{}, serrors.Wrap("parsing header and body", err)
	}
	var body cppb.ASEntrySignedBody
	if err := proto.Unmarshal(hb.Body, &body); err != nil {
		return ASEntry{}, serrors.Wrap("parsing signed body", err)
	}
	if body.HopEntry == nil || body.HopEntry.HopField == nil {
		return ASEntry{}, serrors.New("AS entry without hop field")
	}
	hf := body.HopEntry.HopField
	if hf.ExpTime > 0xff || hf.Ingress > 0xffff || hf.Egress > 0xffff {
		return ASEntry{}, serrors.New("hop field out of range",
			"exp_time", hf.ExpTime, "ingress", hf.Ingress, "egress", hf.Egress)
	}
	hop := path.HopField{
		ExpTime:     uint8(hf.ExpTime),
		ConsIngress: uint16(hf.Ingress),
		ConsEgress:  uint16(hf.Egress),
	}
	copy(hop.Mac[:], hf.Mac)
	return ASEntry{
		IA:         addr.IA(body.IsdAs),
		Next:       addr.IA(body.NextIsdAs),
		IngressMTU: body.HopEntry.IngressMtu,
		Hop:        hop,
		Signed:     signed,
	}, nil
}

// Clone returns a deep copy of the segment's current state, for extending one
// candidate into several propagated or terminated segments.
func (p *PCB) Clone() (*PCB, error) {
	cloned := proto.Clone(p.PB).(*cppb.PathSegment)
	return ParsePCB(cloned)
}

// Timestamp returns the segment's creation timestamp.
func (p *PCB) Timestamp() time.Time { return p.Info.Timestamp }

// ID returns the segment's identifier.
func (p *PCB) ID() uint16 { return p.Info.ID }

// FirstIA returns the ISD-AS of the first entry, the segment's originator.
func (p *PCB) FirstIA() addr.IA { return p.Entries[0].IA }

// LastIA returns the ISD-AS of the last entry.
func (p *PCB) LastIA() addr.IA { return p.Entries[len(p.Entries)-1].IA }

// ContainsIA reports whether any entry names the given ISD-AS.
func (p *PCB) ContainsIA(ia addr.IA) bool {
	for _, e := range p.Entries {
		if e.IA.Equal(ia) {
			return true
		}
	}
	return false
}

// Expiration returns the earliest absolute hop expiration of the segment
// (Section 2.2.2.5): each hop expires its ExpTime units after the segment
// timestamp.
func (p *PCB) Expiration() time.Time {
	expiration := p.Info.Timestamp
	for i, e := range p.Entries {
		hopExp := p.Info.Timestamp.Add(path.ExpTimeToDuration(e.Hop.ExpTime))
		if i == 0 || hopExp.Before(expiration) {
			expiration = hopExp
		}
	}
	return expiration
}

// AssociatedData returns the signature input association for entry i (Section
// 2.2.2.6): the segment information followed by the signed component and
// signature of every previous entry.
func (p *PCB) AssociatedData(i int) [][]byte {
	ad := make([][]byte, 0, 1+2*i)
	ad = append(ad, p.PB.SegmentInfo)
	for j := 0; j < i; j++ {
		ad = append(ad, p.Entries[j].Signed.HeaderAndBody, p.Entries[j].Signed.Signature)
	}
	return ad
}

// EntryOptions describes the AS entry to append to the segment.
type EntryOptions struct {
	// Next is the ISD-AS of the neighbor the beacon is propagated to; zero
	// terminates the segment (Section 3.1.1).
	Next addr.IA
	// IngressIfID is the interface the beacon entered this AS on; zero on
	// the originating core.
	IngressIfID uint16
	// EgressIfID is the interface the beacon leaves on; zero on a
	// terminating entry.
	EgressIfID uint16
}

// AppendEntry appends this AS's signed entry to the segment and MACs the hop
// field with the data-plane forwarding key — the same MAC algorithm the
// processor verifies — chaining the segment ID through the existing hops
// (dataplane draft, Section 4.1).
func (p *PCB) AppendEntry(
	ctx context.Context,
	ia addr.IA,
	opts EntryOptions,
	macFactory func() hash.Hash,
	signer Signer,
) error {

	body := &cppb.ASEntrySignedBody{
		IsdAs:     uint64(ia),
		NextIsdAs: uint64(opts.Next),
		Mtu:       MTU,
		HopEntry: &cppb.HopEntry{
			IngressMtu: MTU,
			HopField: &cppb.HopField{
				Ingress: uint64(opts.IngressIfID),
				Egress:  uint64(opts.EgressIfID),
				ExpTime: uint32(HopExpTime),
			},
		},
	}
	hop := path.HopField{
		ExpTime:     HopExpTime,
		ConsIngress: opts.IngressIfID,
		ConsEgress:  opts.EgressIfID,
	}
	// The hop field is MACed with the segment ID as it stands at this hop:
	// each previous hop's MAC advanced it (MAC chaining).
	info := path.InfoField{SegID: p.Info.ID, Timestamp: util.TimeToSecs(p.Info.Timestamp)}
	for i := 0; i < len(p.Entries); i++ {
		info.UpdateSegID(p.Entries[i].Hop.Mac)
	}
	hop.Mac = path.MAC(macFactory(), info, hop, nil)
	body.HopEntry.HopField.Mac = hop.Mac[:]

	rawBody, err := proto.Marshal(body)
	if err != nil {
		return serrors.Wrap("packing signed body", err)
	}
	signedMsg, err := signer.Sign(ctx, rawBody, p.AssociatedData(len(p.Entries))...)
	if err != nil {
		return serrors.Wrap("signing AS entry", err)
	}
	p.PB.AsEntries = append(p.PB.AsEntries, &cppb.ASEntry{Signed: signedMsg})
	p.Entries = append(p.Entries, ASEntry{
		IA:         ia,
		Next:       opts.Next,
		IngressMTU: MTU,
		Hop:        hop,
		Signed:     signedMsg,
	})
	return nil
}

// AppendRouteHop appends this AS's hop field to the segment without signing
// an entry: the enrollment route built from an unverified beacon, whose
// reversed path needs the node's own hop to leave its router. The appended
// entry carries no signature — it is a route, never a stored, propagated, or
// registered segment.
func (p *PCB) AppendRouteHop(
	ia addr.IA,
	opts EntryOptions,
	macFactory func() hash.Hash,
) (path.HopField, error) {

	hop := path.HopField{
		ExpTime:     HopExpTime,
		ConsIngress: opts.IngressIfID,
		ConsEgress:  opts.EgressIfID,
	}
	info := path.InfoField{SegID: p.Info.ID, Timestamp: util.TimeToSecs(p.Info.Timestamp)}
	for i := 0; i < len(p.Entries); i++ {
		info.UpdateSegID(p.Entries[i].Hop.Mac)
	}
	hop.Mac = path.MAC(macFactory(), info, hop, nil)

	body := &cppb.ASEntrySignedBody{
		IsdAs: uint64(ia),
		HopEntry: &cppb.HopEntry{
			IngressMtu: MTU,
			HopField: &cppb.HopField{
				Ingress: uint64(opts.IngressIfID),
				Egress:  uint64(opts.EgressIfID),
				ExpTime: uint32(HopExpTime),
				Mac:     hop.Mac[:],
			},
		},
	}
	rawBody, err := proto.Marshal(body)
	if err != nil {
		return path.HopField{}, serrors.Wrap("packing route entry body", err)
	}
	p.PB.AsEntries = append(p.PB.AsEntries, &cppb.ASEntry{
		Signed: &cryptopb.SignedMessage{HeaderAndBody: rawBody},
	})
	p.Entries = append(p.Entries, ASEntry{
		IA:         ia,
		IngressMTU: MTU,
		Hop:        hop,
		Signed:     &cryptopb.SignedMessage{HeaderAndBody: rawBody},
	})
	return hop, nil
}

// ForwardPath returns the data-plane path in construction direction:
// originator to terminator, hop fields as beaconed.
func (p *PCB) ForwardPath() *scion.Decoded {
	hops := make([]path.HopField, len(p.Entries))
	for i, e := range p.Entries {
		hops[i] = e.Hop
	}
	return decodedPath(path.InfoField{
		SegID:     p.Info.ID,
		ConsDir:   true,
		Timestamp: util.TimeToSecs(p.Info.Timestamp),
	}, hops)
}

// ReversePath returns the data-plane path against construction direction:
// terminator to originator, hop fields reversed, and the segment ID chained
// through every hop but the terminator's own — the value the info field holds
// when a packet starts at this end (dataplane draft, Section 4.1).
func (p *PCB) ReversePath() *scion.Decoded {
	info := path.InfoField{
		SegID:     p.Info.ID,
		Timestamp: util.TimeToSecs(p.Info.Timestamp),
	}
	for i := 0; i < len(p.Entries)-1; i++ {
		info.UpdateSegID(p.Entries[i].Hop.Mac)
	}
	hops := make([]path.HopField, len(p.Entries))
	for i, e := range p.Entries {
		hops[len(p.Entries)-1-i] = e.Hop
	}
	return decodedPath(info, hops)
}

// decodedPath builds a single-segment data-plane path.
func decodedPath(info path.InfoField, hops []path.HopField) *scion.Decoded {
	return &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  0,
				SegLen:  [3]uint8{uint8(len(hops)), 0, 0},
			},
			NumINF:  1,
			NumHops: len(hops),
		},
		InfoFields: []path.InfoField{info},
		HopFields:  hops,
	}
}

// Compose concatenates segment paths into one end-to-end data-plane path: up
// (reversed), core, and down segments in travel order. The result starts at
// the first part's current position.
func Compose(parts ...*scion.Decoded) (*scion.Decoded, error) {
	if len(parts) == 0 {
		return nil, serrors.New("no parts to compose")
	}
	var numHops int
	segLen := [3]uint8{}
	if len(parts) > 3 {
		return nil, serrors.New("too many path segments", "parts", len(parts))
	}
	var infos []path.InfoField
	var hops []path.HopField
	for i, part := range parts {
		hops = append(hops, part.HopFields...)
		infos = append(infos, part.InfoFields...)
		segLen[i] = uint8(len(part.HopFields))
		numHops += len(part.HopFields)
	}
	return &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{CurrINF: 0, CurrHF: 0, SegLen: segLen},
			NumINF:   len(parts),
			NumHops:  numHops,
		},
		InfoFields: infos,
		HopFields:  hops,
	}, nil
}
