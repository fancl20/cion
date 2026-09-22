package dataplane

import (
	"bytes"
	"math/rand"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// corpusPath is the benchmark transit shape with a varied info field: the
// SegID and timestamp move inside what the fast path accepts, while the
// current hop stays on the benchmark node's interfaces. The SegID is the
// free dimension — the MAC input's remaining bytes are fixed by the shape.
func corpusPath(tb testing.TB, key []byte, ts uint32, segID uint16) *scion.Decoded {
	tb.Helper()
	info := path.InfoField{SegID: segID, ConsDir: true, Timestamp: ts}
	ours := path.HopField{ConsIngress: 1, ConsEgress: 2, ExpTime: benchHopExpTime}
	ours.Mac = benchMAC(tb, key, info, ours)
	arrived := info
	arrived.UpdateSegID(ours.Mac)
	theirs := path.HopField{ConsIngress: 21, ConsEgress: 0, ExpTime: benchHopExpTime}
	theirs.Mac = benchMAC(tb, key, arrived, theirs)
	return &scion.Decoded{
		InfoFields: []path.InfoField{info},
		HopFields:  []path.HopField{ours, theirs},
		NumINF:     1,
		NumHops:    2,
		PathMeta:   scion.MetaHdr{SegLen: [3]uint8{2, 0, 0}},
	}
}

// corpusKey returns the MAC input the cache is keyed on for one corpus
// path — the same block verifyCurrentMAC stages.
func corpusKey(segID uint16, ts uint32) [path.MACBufferSize]byte {
	var key [path.MACBufferSize]byte
	path.MACInput(segID, ts, benchHopExpTime, 1, 2, key[:])
	return key
}

// corpusSlot is the cache slot one corpus path's MAC input maps to.
func corpusSlot(segID uint16, ts uint32) int {
	key := corpusKey(segID, ts)
	return macCacheSlot(&key)
}

// driveMACPacket pushes one filled template through the processor and
// returns the verdict, the slow-path request it raised (if any), and the
// full MAC the verification compared the packet's tag against (on
// pForward).
func driveMACPacket(
	proc *scionPacketProcessor, pool PacketPool, tmpl []byte, ingress Link,
) (disposition, slowPathRequest, []byte) {
	p := fillBenchPacket(pool.Get(), tmpl, ingress)
	disp := proc.processPkt(p)
	req := p.slowPathRequest
	var mac []byte
	if disp == pForward {
		mac = append([]byte(nil), proc.cachedMac...)
	}
	pool.Put(p)
	return disp, req, mac
}

// TestMACCacheVerdictEquivalence drives a randomized corpus of paths —
// valid and invalid tags — through a cold processor and a warm one: the
// cached verdict, and the full MAC its tag was compared against, equal the
// uncached computation. The warm processor's second pass over each packet
// reads the slot the first filled.
func TestMACCacheVerdictEquivalence(t *testing.T) {
	n := newBenchNode(t, benchRunConfig)
	pool := newTestPool(64, minHeadroom)
	warm := newPacketProcessor(n.d)

	rng := rand.New(rand.NewSource(1))
	now := util.TimeToSecs(time.Now())
	for i := range 128 {
		ts := now - uint32(rng.Intn(3600))
		segID := uint16(rng.Intn(1 << 16))
		p := corpusPath(t, n.key, ts, segID)
		badTag := i%4 == 0
		if badTag {
			p.HopFields[0].Mac[0] ^= 0xff
		}
		tmpl := serializeUDP(t, benchSrcAS, benchDstAS, p, benchFlow, benchPad)

		fresh := newPacketProcessor(n.d)
		dispCold, reqCold, macCold := driveMACPacket(fresh, pool, tmpl, n.if1)
		dispFill, reqFill, macFill := driveMACPacket(warm, pool, tmpl, n.if1)
		dispHit, reqHit, macHit := driveMACPacket(warm, pool, tmpl, n.if1)

		if dispFill != dispCold || dispHit != dispCold {
			t.Fatalf("corpus %d (segID %#x, ts %d, badTag %v): cached verdicts %v/%v, want the uncached %v",
				i, segID, ts, badTag, dispFill, dispHit, dispCold)
		}
		if reqFill != reqCold || reqHit != reqCold {
			t.Fatalf("corpus %d: cached slow-path request drifted from the uncached one", i)
		}
		if dispCold == pForward {
			if !bytes.Equal(macFill, macCold) || !bytes.Equal(macHit, macCold) {
				t.Fatalf("corpus %d: the MAC the tag was compared against drifted", i)
			}
		}

		key := corpusKey(segID, ts)
		entry := &warm.macCache.entries[macCacheSlot(&key)]
		if badTag {
			// A failed verification fills nothing, so an attacker who
			// cannot present valid tags cannot evict entries either.
			if entry.input == key {
				t.Fatalf("corpus %d: a failed verification filled the slot", i)
			}
		} else if entry.input != key || !bytes.Equal(entry.fullMac[:], macCold) {
			t.Fatalf("corpus %d: the slot does not hold this input's computed MAC", i)
		}
	}
}

// TestMACCacheCollision finds two MAC inputs that hash to one slot and
// checks that the full key disambiguates: neither borrows the other's MAC,
// and the slot ends up answering for whichever input filled it last.
func TestMACCacheCollision(t *testing.T) {
	n := newBenchNode(t, benchRunConfig)
	pool := newTestPool(64, minHeadroom)
	proc := newPacketProcessor(n.d)

	ts := util.TimeToSecs(time.Now())
	const a = uint16(1)
	b := a
	for {
		b++
		if corpusSlot(b, ts) == corpusSlot(a, ts) {
			break
		}
		if b == a {
			t.Fatal("no SegID shares SegID 1's cache slot")
		}
	}

	pkt := func(segID uint16) []byte {
		return serializeUDP(t, benchSrcAS, benchDstAS,
			corpusPath(t, n.key, ts, segID), benchFlow, benchPad)
	}

	// A fills the shared slot and verifies from it a second time.
	if disp, _, _ := driveMACPacket(proc, pool, pkt(a), n.if1); disp != pForward {
		t.Fatalf("first pass over A: disposition %v, want %v", disp, pForward)
	}
	if disp, _, _ := driveMACPacket(proc, pool, pkt(a), n.if1); disp != pForward {
		t.Fatalf("cached pass over A: disposition %v, want %v", disp, pForward)
	}
	// B hashes to the same slot. Borrowing A's MAC would fail B's valid
	// tag; the full key forces the recomputation.
	if disp, _, _ := driveMACPacket(proc, pool, pkt(b), n.if1); disp != pForward {
		t.Fatalf("B after A in one slot: disposition %v, want %v", disp, pForward)
	}
	keyA, keyB := corpusKey(a, ts), corpusKey(b, ts)
	entry := &proc.macCache.entries[macCacheSlot(&keyB)]
	if entry.input != keyB {
		t.Fatal("the shared slot does not hold B's input")
	}
	// A still verifies, by recomputation, and takes the slot back.
	if disp, _, _ := driveMACPacket(proc, pool, pkt(a), n.if1); disp != pForward {
		t.Fatalf("A after eviction: disposition %v, want %v", disp, pForward)
	}
	if entry.input != keyA {
		t.Fatal("the shared slot does not hold A's input after A refilled it")
	}
}

// TestMACCacheInvalidTagOnHit checks the hit path's failure branch: a
// packet presenting a remembered input with an invalid tag routes to the
// slow path with the invalid-hop-field-MAC code, and the failed
// verification leaves the slot as it found it.
func TestMACCacheInvalidTagOnHit(t *testing.T) {
	n := newBenchNode(t, benchRunConfig)
	pool := newTestPool(64, minHeadroom)
	proc := newPacketProcessor(n.d)

	ts := util.TimeToSecs(time.Now())
	valid := serializeUDP(t, benchSrcAS, benchDstAS,
		corpusPath(t, n.key, ts, 0x111), benchFlow, benchPad)
	if disp, _, _ := driveMACPacket(proc, pool, valid, n.if1); disp != pForward {
		t.Fatalf("filling the slot: disposition %v, want %v", disp, pForward)
	}

	key := corpusKey(0x111, ts)
	entry := &proc.macCache.entries[macCacheSlot(&key)]
	input, fullMac := entry.input, entry.fullMac

	// Same MAC input, corrupted tag.
	p := corpusPath(t, n.key, ts, 0x111)
	p.HopFields[0].Mac[3] ^= 0x80
	invalid := serializeUDP(t, benchSrcAS, benchDstAS, p, benchFlow, benchPad)
	disp, req, _ := driveMACPacket(proc, pool, invalid, n.if1)
	if disp != pSlowPath {
		t.Fatalf("invalid tag on a hit: disposition %v, want %v", disp, pSlowPath)
	}
	if req.code != slayers.SCMPCodeInvalidHopFieldMAC {
		t.Fatalf("slow-path code = %v, want %v", req.code, slayers.SCMPCodeInvalidHopFieldMAC)
	}
	if entry.input != input || entry.fullMac != fullMac {
		t.Fatal("the failed verification rewrote the slot")
	}

	// The remembered MAC still serves the next valid packet.
	if disp, _, _ := driveMACPacket(proc, pool, valid, n.if1); disp != pForward {
		t.Fatalf("valid tag after the failure: disposition %v, want %v", disp, pForward)
	}
}

// TestHopExpiryBatchClock checks the batch-staged clock: packets whose
// windows expire strictly before or strictly after the batch's reading
// verdict correctly, and a packet expiring inside the stale edge the
// reading leaves is accepted — the tolerance, made deliberate. The next
// batch's fresh reading expires it.
func TestHopExpiryBatchClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBenchNode(t, benchRunConfig)
		pool := newTestPool(64, minHeadroom)
		proc := newPacketProcessor(n.d)

		// Date the transit template so its validity window ends on a whole
		// second — the finest the wire format can express.
		window := path.ExpTimeToDuration(benchHopExpTime)
		expiry := time.Now().Add(window).Truncate(time.Second)
		ts := util.TimeToSecs(expiry.Add(-window))
		tmpl := serializeUDP(t, benchSrcAS, benchDstAS,
			transitPath(t, n.key, ts), benchFlow, benchPad)

		drive := func() (disposition, slayers.SCMPCode) {
			p := fillBenchPacket(pool.Get(), tmpl, n.if1)
			disp := proc.processPkt(p)
			code := p.slowPathRequest.code
			pool.Put(p)
			return disp, code
		}

		// The window ends strictly after the reading: forwarded.
		proc.now = expiry.Add(-2 * time.Second)
		if disp, _ := drive(); disp != pForward {
			t.Fatalf("unexpired window: disposition %v, want %v", disp, pForward)
		}
		// Strictly before: expired, and named so.
		proc.now = expiry.Add(2 * time.Second)
		if disp, code := drive(); disp != pSlowPath || code != slayers.SCMPCodePathExpired {
			t.Fatalf("expired window: disposition %v, code %v, want %v/%v",
				disp, code, pSlowPath, slayers.SCMPCodePathExpired)
		}

		// The stale edge: the clock moves past the expiry while the batch's
		// reading stays the one taken before it.
		time.Sleep(time.Until(expiry.Add(500 * time.Millisecond)))
		proc.now = expiry.Add(-500 * time.Millisecond)
		if disp, _ := drive(); disp != pForward {
			t.Fatalf("window expiring inside the stale edge: disposition %v, want %v",
				disp, pForward)
		}
		// The next batch reads the clock again and the same packet expires.
		proc.now = time.Now()
		if disp, code := drive(); disp != pSlowPath || code != slayers.SCMPCodePathExpired {
			t.Fatalf("fresh reading after the stale edge: disposition %v, code %v, want %v/%v",
				disp, code, pSlowPath, slayers.SCMPCodePathExpired)
		}
	})
}
