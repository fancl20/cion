// Package testnetwork holds the e2e labs: nodes booted through the node's
// own assembly, services.BootApp, on the loopback hosts the labs draw,
// beside the fixtures every lab package shares — the nodes' boots, the
// bubbles, the address draws, and the polls; the test WebPKI standing in for
// the core's certificate authority comes from pkg/core/webpki/webpkitest.
// The labs import the node's assembly, so no package under pkg can host
// them.
package testnetwork

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// Test intervals, fast enough for the integration tests to watch the loops.
const (
	Propagation  = 100 * time.Millisecond
	Registration = 200 * time.Millisecond
	EnrollRetry  = 100 * time.Millisecond
	TestTimeout  = 20 * time.Second
	// RestartTimeout budgets the restart lab's convergence: the reboot puts
	// the joiner's loop through serial stages — re-rendezvous, a fresh
	// prompt, the press, the chain — whose wall-clock pacing stretches
	// several-fold on a loaded runner under the race detector, where the
	// fixed TestTimeout missed a pipeline still progressing.
	RestartTimeout = 3 * TestTimeout
)

// FreeUDPAddrOn returns a free UDP address on the given host.
func FreeUDPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().String()
}

// The pinned port band: the addresses a node rebinds — a link-set's pinned
// locals, the internal link — are drawn from below the kernel's ephemeral
// range, where no bind(:0), the node's own control conns included, ever
// lands. A rebound address drawn from the ephemeral range instead is free
// at the draw yet any later bind(:0) can take it, and the node's own
// rebind then fails.
const (
	pinnedPortBase = 20000
	pinnedPortSpan = 5000
)

// pinnedPortDraws names the band's next port, so concurrent draws differ.
var pinnedPortDraws atomic.Uint32

// PinnedTCPAddrOn returns a TCP address on the given host for a listener to
// bind: the band's next free port, probed by listening on it and released
// for the listener's own bind, safe for the same reason as PinnedUDPAddrOn.
func PinnedTCPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	for range pinnedPortSpan {
		addr := netip.AddrPortFrom(ip, pinnedPortBase+uint16(pinnedPortDraws.Add(1)%pinnedPortSpan))
		l, err := net.Listen("tcp4", addr.String())
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		return addr.String()
	}
	t.Fatalf("the pinned port band on %v is drawn dry", ip)
	return ""
}

// PinnedUDPAddrOn returns a UDP address on the given host for the node to
// rebind: the band's next free port, probed by binding it and released for
// the node's own bind. The release is safe — nothing that binds :0 draws
// from the band.
func PinnedUDPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	for range pinnedPortSpan {
		addr := netip.AddrPortFrom(ip, pinnedPortBase+uint16(pinnedPortDraws.Add(1)%pinnedPortSpan))
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		return addr.String()
	}
	t.Fatalf("the pinned port band on %v is drawn dry", ip)
	return ""
}

// Poll waits for cond to hold, failing the test at the timeout.
func Poll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	PollFor(t, TestTimeout, what, cond)
}

// PollErr waits for attempt to return nil, failing the test at the timeout
// with the last error attempt returned.
func PollErr(t *testing.T, what string, attempt func() error) {
	t.Helper()
	var last error
	deadline := time.Now().Add(TestTimeout)
	for time.Now().Before(deadline) {
		if last = attempt(); last == nil {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

// PollFor is Poll under an explicit budget, for labs whose convergence
// outgrows TestTimeout on a loaded runner.
func PollFor(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// virtualPollInterval spaces a virtual-time poll's checks: under the
// daemon's own pacing nothing a lab watches moves within a second.
const virtualPollInterval = time.Second

// PollVirtual is PollFor inside a synctest bubble: the budget is virtual
// time, spent at no wall-clock cost but the work it carries, and each check
// runs once every other goroutine in the bubble has parked.
func PollVirtual(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	if !pollUntil(budget, cond) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

// pollUntil reports whether cond held at one of the checks the budget
// spans, a virtual second apart: the first at once, the last at the
// budget's end. Each check waits for the bubble to park, so it reads the
// state every timer due at its instant left.
func pollUntil(budget time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(budget)
	for {
		synctest.Wait()
		if cond() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(virtualPollInterval)
	}
}

// poolSize is the pool's size: the 127.0.X.Y loopback space above the
// reserved /24, X from 1, Y skipping the all-zero and all-one bytes that
// read as network and broadcast.
const poolSize = 255 * 254

// hostDraws counts the pool's draws; the counter never resets and never
// wraps, so a host is never reissued within a process. A node's sockets can
// outlive its test — the failed-boot proof's endpoint socket, which
// releases with the process rather than the failed setup, the standing
// example — so a repeated run must draw fresh hosts rather than find its
// fixed ports held for the wrong reason.
var hostDraws atomic.Uint32

// HostSlot draws the next loopback host of the pool the process's labs
// share, so two labs overlap freely, a repeated run draws fresh hosts, and
// no two draws name one host. The pool starts at 127.0.1.1, above
// 127.0.0.0/24 — that /24 belongs to the other packages' fixed loopback
// mounts, and go test runs the packages' processes in parallel — and a draw
// past the pool's end refuses instead of wrapping. The behavior labs'
// process draws the same hosts as names on fabrics, where no kernel socket
// binds them.
func HostSlot(t *testing.T) netip.Addr {
	t.Helper()
	ip, ok := poolHost(int(hostDraws.Add(1)))
	if !ok {
		t.Fatalf("the pool of %d loopback hosts is drawn dry", poolSize)
	}
	return ip
}

// poolHost returns the n-th draw's host of the pool, n counted from one,
// and whether the pool holds it.
func poolHost(n int) (netip.Addr, bool) {
	if n > poolSize {
		return netip.Addr{}, false
	}
	n--
	return netip.AddrFrom4([4]byte{127, 0, byte(n/254 + 1), byte(n%254 + 1)}), true
}
