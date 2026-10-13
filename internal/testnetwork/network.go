// Package testnetwork holds the integration labs: nodes booted through the
// node's own assembly, services.BootApp, on the loopback hosts the labs
// draw, beside the fixtures they share — the address draws and the polls;
// the test WebPKI standing in for the core's certificate authority comes
// from pkg/webpki/webpkitest. The labs import the node's assembly, so no
// package under pkg can host them.
package testnetwork

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
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
