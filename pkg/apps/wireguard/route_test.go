package wireguard

import (
	"context"
	"hash"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// unsignedSigner signs by wrapping the body unsigned — the route tests read
// entries, never verify them.
type unsignedSigner struct{}

func (unsignedSigner) Sign(
	_ context.Context, msg []byte, _ ...[]byte,
) (*cryptopb.SignedMessage, error) {
	return &cryptopb.SignedMessage{HeaderAndBody: msg}, nil
}

// declaredSeg builds a two-AS segment of the given type whose single edge —
// from's egress interface to to's ingress — declares the given one-way
// delay; zero declares none.
func declaredSeg(
	t *testing.T, typ pathdb.SegmentType, now time.Time,
	from, to addr.IA, egress, ingress uint16, latency time.Duration,
) *pathdb.Segment {
	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x333)
	if err != nil {
		t.Fatal(err)
	}
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(testMACKey)
		return mac
	}
	if err := pcb.AppendEntry(context.Background(), from, segment.EntryOptions{
		EgressIfID: egress, EgressLatency: latency,
	}, macFactory, unsignedSigner{}); err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), to, segment.EntryOptions{
		IngressIfID: ingress,
	}, macFactory, unsignedSigner{}); err != nil {
		t.Fatal(err)
	}
	return &pathdb.Segment{Type: typ, PCB: pcb}
}

// pickCase is one case of the pick's table: a sequence of windows, the
// choice carried between them.
type pickCase struct {
	name    string
	windows []pickWindow
}

// pickWindow is one window of the pick's table: the candidates it offers and
// the landing it wants — the pick named by its single link's interface ID,
// zero for none, and whether the pick switched.
type pickWindow struct {
	candidates []scion.Candidate
	wantPick   uint16
	wantSwitch bool
}

// TestPickRoute runs the pick's table: the rank, the pools, the incumbent's
// fates, the ratio, the streak, and the declaration gaps, window by window.
func TestPickRoute(t *testing.T) {
	fresh := time.Now()
	// mint names one candidate by its single link's interface ID, the
	// identity the assertions read picks by.
	mint := func(name uint16, hops, entries int, fresh time.Time) scion.Candidate {
		return scion.Candidate{
			Links:   []segment.LinkID{{IA: addr.MustIAFrom(20, addr.AS(name)), IfID: name}},
			Hops:    hops,
			Entries: entries,
			Fresh:   fresh,
		}
	}
	declared := func(c scion.Candidate, d time.Duration) scion.Candidate {
		c.Latency = &d
		return c
	}
	crossing := func(c scion.Candidate) scion.Candidate {
		c.Crossing = true
		return c
	}
	incumbent100 := declared(mint(1, 4, 6, fresh), 100*time.Millisecond)
	cases := []pickCase{
		{
			name: "a smaller declared sum outranks fewer hops",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					declared(mint(1, 3, 6, fresh), 30*time.Millisecond),
					declared(mint(2, 5, 4, fresh), 10*time.Millisecond),
				},
				wantPick: 2,
			}},
		},
		{
			name: "an undeclared candidate ranks behind a declared one",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					declared(mint(1, 5, 6, fresh), 100*time.Millisecond),
					mint(2, 1, 4, fresh),
				},
				wantPick: 1,
			}},
		},
		{
			name: "a tie on the declared sum falls to the path layer's rank",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					declared(mint(1, 3, 6, fresh), 10*time.Millisecond),
					declared(mint(2, 2, 4, fresh), 10*time.Millisecond),
				},
				wantPick: 2, // fewer hops
			}},
		},
		{
			name: "an undeclared tie falls to the path layer's rank",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					mint(1, 2, 4, fresh),
					mint(2, 2, 4, fresh.Add(time.Hour)),
				},
				wantPick: 2, // fresher
			}},
		},
		{
			name: "a tie past hops and freshness falls to fewer entries",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					mint(1, 2, 6, fresh),
					mint(2, 2, 4, fresh),
				},
				wantPick: 2,
			}},
		},
		{
			name: "a crossing candidate is never picked while a clean one stands",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					declared(mint(1, 5, 6, fresh), 50*time.Millisecond),
					crossing(declared(mint(2, 1, 4, fresh), time.Millisecond)),
				},
				wantPick: 1,
			}},
		},
		{
			name: "the last-resort pool is ranked the same way",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					crossing(declared(mint(1, 2, 4, fresh), 30*time.Millisecond)),
					crossing(declared(mint(2, 4, 6, fresh), 10*time.Millisecond)),
				},
				wantPick: 2,
			}},
		},
		{
			name: "an incumbent demoted to the crossing pool while clean stands loses its route at once",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{
						crossing(declared(mint(1, 2, 4, fresh), 10*time.Millisecond)),
					},
					wantPick: 1,
				},
				{
					candidates: []scion.Candidate{
						crossing(declared(mint(1, 2, 4, fresh), 10*time.Millisecond)),
						declared(mint(2, 4, 6, fresh), 50*time.Millisecond),
					},
					wantPick:   2,
					wantSwitch: true,
				},
			},
		},
		{
			name: "no incumbent picks best without a switch",
			windows: []pickWindow{{
				candidates: []scion.Candidate{
					declared(mint(1, 3, 6, fresh), 30*time.Millisecond),
					declared(mint(2, 5, 4, fresh), 10*time.Millisecond),
				},
				wantPick: 2,
			}},
		},
		{
			name: "an incumbent the window cannot compose is replaced at once",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{declared(mint(1, 2, 4, fresh), 50*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{declared(mint(2, 4, 6, fresh), 60*time.Millisecond)},
					wantPick:   2,
					wantSwitch: true,
				},
			},
		},
		{
			name: "an incumbent holding the lead keeps its route",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{
						declared(mint(1, 2, 4, fresh), 10*time.Millisecond),
						declared(mint(2, 4, 6, fresh), 50*time.Millisecond),
					},
					wantPick: 1,
				},
				{
					candidates: []scion.Candidate{
						declared(mint(1, 2, 4, fresh), 10*time.Millisecond),
						declared(mint(2, 4, 6, fresh), 50*time.Millisecond),
					},
					wantPick: 1,
				},
			},
		},
		{
			name: "a challenger a fifth faster switches on the second window",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   2,
					wantSwitch: true,
				},
			},
		},
		{
			name: "a challenger inside the ratio never switches",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 85*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 85*time.Millisecond)},
					wantPick:   1,
				},
			},
		},
		{
			name: "a challenger at the exact ratio never switches",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 80*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 80*time.Millisecond)},
					wantPick:   1,
				},
			},
		},
		{
			name: "a broken window resets the streak",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   1, // the streak builds
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 90*time.Millisecond)},
					wantPick:   1, // inside the ratio: the streak resets
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   1, // the streak restarts
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   2,
					wantSwitch: true,
				},
			},
		},
		{
			name: "a new challenger restarts the streak",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   1, // the second candidate's streak builds
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond), declared(mint(3, 8, 8, fresh), 50*time.Millisecond)},
					wantPick:   1, // the third candidate takes the lead, from one
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond), declared(mint(3, 8, 8, fresh), 50*time.Millisecond)},
					wantPick:   3,
					wantSwitch: true,
				},
			},
		},
		{
			name: "challengers alternating the lead never reach the threshold",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(3, 6, 8, fresh), 60*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(2, 6, 8, fresh), 70*time.Millisecond)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, declared(mint(3, 6, 8, fresh), 60*time.Millisecond)},
					wantPick:   1,
				},
			},
		},
		{
			name: "a declared incumbent never yields to an undeclared challenger",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{incumbent100},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, mint(2, 1, 4, fresh)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{incumbent100, mint(2, 1, 4, fresh)},
					wantPick:   1,
				},
			},
		},
		{
			name: "an incumbent without a declared sum yields through the streak alone",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{mint(1, 2, 4, fresh)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{mint(1, 2, 4, fresh), declared(mint(2, 6, 8, fresh), 500*time.Millisecond)},
					wantPick:   1, // no ratio applies: the streak alone
				},
				{
					candidates: []scion.Candidate{mint(1, 2, 4, fresh), declared(mint(2, 6, 8, fresh), 500*time.Millisecond)},
					wantPick:   2,
					wantSwitch: true,
				},
			},
		},
		{
			name: "neither side declaring picks by the default rank at once",
			windows: []pickWindow{
				{
					candidates: []scion.Candidate{mint(1, 5, 6, fresh)},
					wantPick:   1,
				},
				{
					candidates: []scion.Candidate{mint(1, 5, 6, fresh), mint(2, 2, 4, fresh)},
					wantPick:   2,
					wantSwitch: true,
				},
				{
					candidates: []scion.Candidate{mint(1, 5, 6, fresh), mint(2, 2, 4, fresh)},
					wantPick:   2,
				},
			},
		},
		{
			name:    "a window that composes nothing picks nothing",
			windows: []pickWindow{{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var choice routeChoice
			for i, w := range tc.windows {
				pick, next, switched := pickRoute(w.candidates, choice)
				choice = next
				if w.wantPick == 0 {
					if pick != nil {
						t.Fatalf("window %d picked candidate %d, want none",
							i+1, pick.Links[0].IfID)
					}
					continue
				}
				if pick == nil {
					t.Fatalf("window %d picked nothing, want candidate %d", i+1, w.wantPick)
				}
				if got := pick.Links[0].IfID; got != w.wantPick {
					t.Errorf("window %d picked candidate %d, want %d", i+1, got, w.wantPick)
				}
				if switched != w.wantSwitch {
					t.Errorf("window %d switched = %v, want %v", i+1, switched, w.wantSwitch)
				}
			}
		})
	}
}

// routeOf snapshots the peer's route choice.
func routeOf(s *meshSocket, ia addr.IA) routeChoice {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.routes[ia]
}

// pathOf snapshots the peer's cached path.
func pathOf(s *meshSocket, ia addr.IA) *spath.Decoded {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.paths[ia]
}

// landAll enumerates through the socket's provider and lands the pick,
// reporting whether a switch landed.
func landAll(t *testing.T, s *meshSocket, dest addr.IA) bool {
	t.Helper()
	candidates, err := s.provider.Enumerate(context.Background(), dest)
	if err != nil {
		t.Fatalf("enumerating %s: %v", dest, err)
	}
	_, switched := s.landRoute(dest, candidates)
	return switched
}

// routeTopology names the socket route tests' two routes: the destination
// they reach and each route's link identity.
type routeTopology struct {
	dest                  addr.IA
	incumbent, challenger []segment.LinkID
}

// routeSocket builds the socket route tests' network: two four-hop routes to
// the destination through different cores, every traversed edge declaring
// its one-way delay, so the incumbent route sums 50ms and the challenger
// 10ms — a fifth of it, past the switch ratio. The provider serves the
// incumbent's segments alone; the returned closure offers both routes.
func routeSocket(t *testing.T) (*meshSocket, *routeTopology, func()) {
	t.Helper()
	leaf := addr.MustIAFrom(20, 1) // testMeshSocket's provider IA
	core1, core2 := addr.MustIAFrom(20, 0xff0000000351), addr.MustIAFrom(20, 0xff0000000352)
	dest := addr.MustIAFrom(20, 0xff0000000353)
	tp := &routeTopology{dest: dest}
	tp.incumbent = []segment.LinkID{
		{IA: core1, IfID: 11}, {IA: leaf, IfID: 12},
		{IA: core1, IfID: 13}, {IA: dest, IfID: 14},
	}
	tp.challenger = []segment.LinkID{
		{IA: core2, IfID: 21}, {IA: leaf, IfID: 22},
		{IA: core2, IfID: 23}, {IA: dest, IfID: 24},
	}
	now := time.Now()
	up1 := declaredSeg(t, pathdb.SegmentTypeUp, now, core1, leaf, 11, 12, 20*time.Millisecond)
	down1 := declaredSeg(t, pathdb.SegmentTypeDown, now, core1, dest, 13, 14, 30*time.Millisecond)
	up2 := declaredSeg(t, pathdb.SegmentTypeUp, now, core2, leaf, 21, 22, 4*time.Millisecond)
	down2 := declaredSeg(t, pathdb.SegmentTypeDown, now, core2, dest, 23, 24, 6*time.Millisecond)
	db := &memDB{segs: []*pathdb.Segment{up1}}
	downs := []*pathdb.Segment{down1}
	socket, _ := testMeshSocket(t, db)
	socket.provider.Lookup = func(_ context.Context, dst addr.IA) []*pathdb.Segment {
		if !dst.Equal(dest) {
			return nil
		}
		return downs
	}
	offerChallenger := func() {
		db.segs = []*pathdb.Segment{up1, up2}
		downs = []*pathdb.Segment{down1, down2}
	}
	return socket, tp, offerChallenger
}

// TestMeshSocketLandsRoute checks the warm loop's landing through the
// socket: the incumbent route is held while the challenger's streak builds,
// displaced on the second window with the counter counting, and a pick that
// keeps the route still refreshes the cache with the recomposition.
func TestMeshSocketLandsRoute(t *testing.T) {
	socket, tp, offerChallenger := routeSocket(t)

	// The first window lands the only route; a fresh landing is no switch.
	if landAll(t, socket, tp.dest) {
		t.Error("the first landing counted a switch")
	}
	first := pathOf(socket, tp.dest)
	if first == nil || len(first.HopFields) != 4 {
		t.Fatalf("the first window cached %v, want the composed 4-hop route", first)
	}
	if choice := routeOf(socket, tp.dest); !slices.Equal(choice.incumbent, tp.incumbent) ||
		choice.challenger != nil || choice.streak != 0 {
		t.Fatalf("route state after the first window = %+v, want the route alone", choice)
	}

	// The challenger appears and the streak builds while the incumbent
	// serves: the cache refreshes with the recomposition of the same
	// stretch, and the route state names the challenger.
	offerChallenger()
	if landAll(t, socket, tp.dest) {
		t.Error("the streak's first window counted a switch")
	}
	if second := pathOf(socket, tp.dest); second == first {
		t.Error("the kept route's cache entry was not refreshed with the recomposition")
	}
	choice := routeOf(socket, tp.dest)
	if !slices.Equal(choice.incumbent, tp.incumbent) {
		t.Fatalf("the streak displaced the incumbent: %+v", choice)
	}
	if !slices.Equal(choice.challenger, tp.challenger) || choice.streak != 1 {
		t.Fatalf("route state while the streak builds = %+v, want the challenger at 1", choice)
	}
	if got := socket.cnt.routeSwitches.Load(); got != 0 {
		t.Errorf("route switches after one streak window = %d, want 0", got)
	}

	// The second window of the same challenger lands the switch: the cache
	// carries the challenger's path, the route state the challenger as
	// incumbent, and the counter the replacement.
	if !landAll(t, socket, tp.dest) {
		t.Fatal("the sustained challenger never switched")
	}
	path := pathOf(socket, tp.dest)
	if path == nil || path.HopFields[0].ConsIngress != 22 {
		t.Fatalf("the switched cache entry = %v, want the challenger's route", path)
	}
	if choice := routeOf(socket, tp.dest); !slices.Equal(choice.incumbent, tp.challenger) ||
		choice.challenger != nil || choice.streak != 0 {
		t.Fatalf("route state after the switch = %+v, want the challenger as incumbent", choice)
	}
	if got := socket.cnt.routeSwitches.Load(); got != 1 {
		t.Errorf("route switches = %d, want 1", got)
	}
}

// TestMeshSocketEvictionsClearRoute checks that every eviction clears the
// route entry with the cache entry — the send-time seed, the failed send's
// invalidation, the interface-down signal's drop — so the next warm window
// picks best at once, never hysteresis between a dead route and its
// replacement.
func TestMeshSocketEvictionsClearRoute(t *testing.T) {
	socket, tp, offerChallenger := routeSocket(t)
	if landAll(t, socket, tp.dest) {
		t.Fatal("the first landing counted a switch")
	}
	offerChallenger()
	if landAll(t, socket, tp.dest) {
		t.Fatal("the streak's first window counted a switch")
	}

	// noRouteState fails the test unless the eviction left no route state.
	noRouteState := func(what string) {
		t.Helper()
		if choice := routeOf(socket, tp.dest); choice.incumbent != nil ||
			choice.challenger != nil || choice.streak != 0 {
			t.Errorf("%s left the route state %+v", what, choice)
		}
	}
	// pickedBest fails the test unless the next window landed the best route
	// at once — no incumbent to displace, no switch counted.
	pickedBest := func(what string) {
		t.Helper()
		if landAll(t, socket, tp.dest) {
			t.Errorf("the window after %s counted a switch", what)
		}
		if choice := routeOf(socket, tp.dest); !slices.Equal(choice.incumbent, tp.challenger) {
			t.Errorf("the window after %s landed %v, want the best route at once",
				what, choice.incumbent)
		}
		if got := socket.cnt.routeSwitches.Load(); got != 0 {
			t.Errorf("route switches after %s = %d, want 0", what, got)
		}
	}

	// The send-time seed: a cached path past the margin makes the send seed
	// from the endpoint's carried arrival path, and no route facts survive a
	// path the warm loop did not choose.
	socket.mtx.Lock()
	socket.expiry[tp.dest] = time.Now().Add(-time.Hour)
	socket.mtx.Unlock()
	candidates, err := socket.provider.Enumerate(context.Background(), tp.dest)
	if err != nil {
		t.Fatal(err)
	}
	peer := &meshEndpoint{addr: scion.Addr{
		IA:   tp.dest,
		Addr: netip.MustParseAddrPort("127.0.0.1:40001"),
		Path: candidates[0].Path,
	}}
	if err := socket.send(peer, [][]byte{[]byte("datagram")}); err != nil {
		t.Fatalf("the seeded send: %v", err)
	}
	if seeded := pathOf(socket, tp.dest); seeded != candidates[0].Path {
		t.Fatalf("the seed cached %v, want the arrival path", seeded)
	}
	noRouteState("the send-time seed")
	pickedBest("the send-time seed")

	// The failed send: a closed socket fails the send, and the invalidation
	// clears the route entry with the cached path it drops.
	_ = socket.conn.Close()
	peer = &meshEndpoint{addr: scion.Addr{
		IA:   tp.dest,
		Addr: netip.MustParseAddrPort("127.0.0.1:40001"),
	}}
	if err := socket.send(peer, [][]byte{[]byte("datagram")}); err == nil {
		t.Fatal("sending over a closed socket succeeded")
	}
	if path := pathOf(socket, tp.dest); path != nil {
		t.Errorf("the failed send left the cache entry %v", path)
	}
	noRouteState("the failed send")
	pickedBest("the failed send")

	// The interface-down signal: the quoted destination's drop clears the
	// route entry with the cached path.
	socket.dropPathOf(scion.InterfaceDownSignal{IA: tp.dest, IfID: 1, Dst: tp.dest})
	if path := pathOf(socket, tp.dest); path != nil {
		t.Errorf("the interface-down signal left the cache entry %v", path)
	}
	noRouteState("the interface-down signal")
	pickedBest("the interface-down signal")
}

// TestWireguardWarmMeshPaths checks the warm loop's discipline: a peer whose
// enumeration composes nothing keeps its cache and route state with a warn,
// and a peer with declared candidates gets the ranked pick in its cache.
func TestWireguardWarmMeshPaths(t *testing.T) {
	leaf := addr.MustIAFrom(20, 0xff0000000361)
	core := addr.MustIAFrom(20, 0xff0000000362)
	dest := addr.MustIAFrom(20, 0xff0000000363)
	a, _ := newTestWireguard(t, leaf, &flippableTrustDB{})
	now := time.Now()
	up := declaredSeg(t, pathdb.SegmentTypeUp, now, core, leaf, 34, 35, 4*time.Millisecond)
	down := declaredSeg(t, pathdb.SegmentTypeDown, now, core, dest, 31, 32, 6*time.Millisecond)
	db := &memDB{}
	downs := []*pathdb.Segment{down}
	a.cfg.Provider.DB = db
	a.cfg.Provider.Lookup = func(_ context.Context, dst addr.IA) []*pathdb.Segment {
		if !dst.Equal(dest) {
			return nil
		}
		return downs
	}
	a.applyDirectory(Directory{Nodes: []Entry{{
		IA:        dest,
		PublicKey: mustPubKey(0x36),
		Overlay:   netip.MustParsePrefix("100.64.36.0/24"),
	}}})

	// No up segments are stored yet: the enumeration composes nothing, and
	// nothing lands.
	a.warmMeshPaths(context.Background())
	if path := pathOf(a.mesh, dest); path != nil {
		t.Fatalf("an empty enumeration landed %v", path)
	}
	if choice := routeOf(a.mesh, dest); choice.incumbent != nil {
		t.Fatalf("an empty enumeration landed the route state %+v", choice)
	}

	// The up segment arrives declaring its egress link's one-way delay; the
	// pick lands in the cache.
	db.segs = []*pathdb.Segment{up}
	a.warmMeshPaths(context.Background())
	path := pathOf(a.mesh, dest)
	if path == nil || len(path.HopFields) != 4 {
		t.Fatalf("the declared candidates landed %v, want the composed 4-hop route", path)
	}
	want := []segment.LinkID{
		{IA: core, IfID: 34}, {IA: leaf, IfID: 35},
		{IA: core, IfID: 31}, {IA: dest, IfID: 32},
	}
	if choice := routeOf(a.mesh, dest); !slices.Equal(choice.incumbent, want) {
		t.Errorf("landed route = %v, want %v", choice.incumbent, want)
	}
	if got := a.cnt.routeSwitches.Load(); got != 0 {
		t.Errorf("route switches = %d, want 0 for a fresh landing", got)
	}

	// The up segments leave the store — the enumeration composes nothing
	// again — and the cache keeps the landed pick with its route state.
	db.segs = nil
	a.warmMeshPaths(context.Background())
	if kept := pathOf(a.mesh, dest); kept != path {
		t.Error("an empty enumeration evicted the cached pick")
	}
	if choice := routeOf(a.mesh, dest); !slices.Equal(choice.incumbent, want) {
		t.Errorf("an empty enumeration dropped the route state: %+v", choice)
	}
}
