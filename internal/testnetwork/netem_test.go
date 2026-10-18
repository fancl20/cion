package testnetwork

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

// netnsEnv names the test a re-executed test binary runs inside its own
// user and network namespace; netnsSkipEnv names the file the inner run
// writes its skip's reason to, which the outer run reports as its own.
const (
	netnsEnv     = "CION_TEST_NETNS"
	netnsSkipEnv = "CION_TEST_NETNS_SKIP"
)

// The loopback's shaping bands, as qdisc handles: the added bands of a
// prio root qdisc, each a netem child — three one-way delays and a total
// loss. Unclassified traffic keeps the default band.
const (
	band1ms  = 0x10004 // 1:4
	band15ms = 0x10005 // 1:5
	band40ms = 0x10006 // 1:6
	bandLoss = 0x10007 // 1:7
)

// ownNetns runs the calling test in a fresh user and network namespace with
// the namespace's loopback raised, where the test owns the loopback and
// shapes it without touching the host's. The outer run starts the test
// binary again for this test alone, then turns the test parallel and
// reports false, failing the test with the inner run's output when the
// inner run fails and skipping with the reason the inner run wrote when it
// skipped; the inner run reports true, past the loopback's raise, and the
// test proceeds alone. The inner run starts before the test turns
// parallel: until its exec, the fork holds every descriptor the test process
// has open, so a fork beside running tests would keep bound a socket one of
// them closed to rebind its address. A host that blocks unprivileged user
// namespaces, or grants the namespace but declines administering its
// interfaces, skips the test.
func ownNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(netnsEnv) == t.Name() {
		raiseLoopback(t)
		return true
	}
	args := []string{"-test.run=^" + t.Name() + "$", "-test.count=1", "-test.v"}
	if deadline, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout="+time.Until(deadline).String())
	}
	var out bytes.Buffer
	skip := filepath.Join(t.TempDir(), "skip")
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), netnsEnv+"="+t.Name(), netnsSkipEnv+"="+skip)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("the host blocks unprivileged user namespaces: %v", err)
		}
		t.Fatalf("starting %s in its own network namespace: %v", t.Name(), err)
	}
	t.Parallel()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("running %s in its own network namespace: %v\n%s", t.Name(), err, out.Bytes())
	}
	if reason, err := os.ReadFile(skip); err == nil && len(reason) > 0 {
		t.Skipf("%s", reason)
	}
	return false
}

// The flag ioctls and the request they carry — the kernel's interface for
// setting an interface's flags, the operation beneath the ip tool's
// link-set, which the standard library exports no request numbers for.
const (
	siocgifflags = 0x8913 // SIOCGIFFLAGS
	siocsifflags = 0x8914 // SIOCSIFFLAGS
)

// ifreq is the interface request the flag ioctls carry: the interface's
// name beside its flags, padded to the kernel's forty-byte struct.
type ifreq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

// raiseLoopback brings the namespace's loopback up from Go — a fresh
// network namespace's loopback starts down, and every lab's netns dials
// ride it — so a refusal names the step the kernel denied rather than a
// tool's transcript.
func raiseLoopback(t *testing.T) {
	t.Helper()
	if lo, err := net.InterfaceByName("lo"); err == nil && lo.Flags&net.FlagUp != 0 {
		return
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening the interface socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var req ifreq
	copy(req.Name[:], "lo")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		siocgifflags, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		refuse(t, "reading lo's flags", errno)
	}
	req.Flags |= syscall.IFF_UP
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		siocsifflags, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		refuse(t, "raising lo", errno)
	}
}

// refuse skips the lab when the kernel declined the interface step — EPERM,
// a namespace held without the administration its interfaces need — with
// the reason written where the outer run reads it, and fails the test on
// any other errno, which the lab's own code owns.
func refuse(t *testing.T, step string, errno syscall.Errno) {
	t.Helper()
	if errno != syscall.EPERM {
		t.Fatalf("%s: %v", step, errno)
	}
	reason := fmt.Sprintf("the host declines administering the namespace's interfaces: %s: %v", step, errno)
	if path := os.Getenv(netnsSkipEnv); path != "" {
		if err := os.WriteFile(path, []byte(reason), 0o600); err != nil {
			t.Fatalf("writing the skip's reason: %v", err)
		}
	}
	t.Skipf("%s", reason)
}

// openTrafficControl opens the rtnetlink socket the lab shapes the
// loopback through — the kernel's own traffic-control interface, so the
// lab leans on no external tool — and looks up the loopback it shapes,
// closing the socket with the test.
func openTrafficControl(t *testing.T) (*tc.Tc, uint32) {
	t.Helper()
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		t.Fatalf("opening the traffic-control socket: %v", err)
	}
	t.Cleanup(func() { _ = tcnl.Close() })
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("looking up the loopback: %v", err)
	}
	return tcnl, uint32(lo.Index)
}

// u32Terminal is the selector flag — the kernel's TC_U32_TERMINAL, which
// go-tc does not export — that ends the classifier's walk on a match: a
// non-terminal match keeps walking the hash chain, fails, and falls back
// to the default band.
const u32Terminal = 0x1

// netemTick is the unit netem's latency field counts: 64 nanoseconds, the
// kernel's PSCHED tick.
const netemTick = 64 * time.Nanosecond

// shapeLoopback installs the shaping bands beneath a prio root qdisc on
// the loopback ownNetns raised: seven bands, four of them netem children,
// and the zero priomap riding every priority in the default band, so the
// filters alone route traffic into the shaped bands. Netem prices loss as
// a fraction of 2³².
func shapeLoopback(t *testing.T) {
	t.Helper()
	tcnl, lo := openTrafficControl(t)
	root := tc.Object{
		Family:  unix.AF_UNSPEC,
		Ifindex: lo,
		Handle:  core.BuildHandle(1, 0),
		Parent:  tc.HandleRoot,
		Kind:    "prio", Prio: &tc.Prio{Bands: 7},
	}
	if err := tcnl.Qdisc().Add(&root); err != nil {
		t.Fatalf("adding the prio root qdisc: %v", err)
	}
	for band, shape := range map[uint32]tc.NetemQopt{
		band1ms:  {Latency: uint32(1 * time.Millisecond / netemTick), Limit: 1000},
		band15ms: {Latency: uint32(15 * time.Millisecond / netemTick), Limit: 1000},
		band40ms: {Latency: uint32(40 * time.Millisecond / netemTick), Limit: 1000},
		bandLoss: {Loss: math.MaxUint32, Limit: 1000},
	} {
		child := tc.Object{
			Family: unix.AF_UNSPEC, Ifindex: lo, Parent: band,
			Kind:  "netem",
			Netem: &tc.Netem{Qopt: shape},
		}
		if err := tcnl.Qdisc().Add(&child); err != nil {
			t.Fatalf("adding band %#x's netem child: %v", band, err)
		}
	}
}

// steer sends both directions between two hosts into the band through u32
// filters of the given priority, one group per priority: the lowest number
// matches first.
func steer(t *testing.T, prio int, band uint32, a, b netip.Addr) {
	t.Helper()
	tcnl, lo := openTrafficControl(t)
	for _, pair := range [][2]netip.Addr{{a, b}, {b, a}} {
		classID := band
		filter := tc.Object{
			Family:  unix.AF_UNSPEC,
			Ifindex: lo,
			Parent:  core.BuildHandle(1, 0),
			Info:    core.FilterInfo(uint16(prio), unix.ETH_P_IP),
			Kind:    "u32",
			U32: &tc.U32{
				ClassID: &classID,
				Sel: &tc.U32Sel{
					Flags: u32Terminal,
					NKeys: 2,
					Keys: []tc.U32Key{
						{Mask: 0xffffffff, Val: nativeWord(pair[0]), Off: 12}, // the IP source
						{Mask: 0xffffffff, Val: nativeWord(pair[1]), Off: 16}, // the IP destination
					},
				},
			},
		}
		if err := tcnl.Filter().Add(&filter); err != nil {
			t.Fatalf("steering %s↔%s into band %#x: %v", pair[0], pair[1], band, err)
		}
	}
}

// nativeWord reads an address's four bytes as the native-endian word the
// u32 keys carry: the kernel matches the marshaled bytes against the
// packet's own.
func nativeWord(addr netip.Addr) uint32 {
	as4 := addr.As4()
	return binary.NativeEndian.Uint32(as4[:])
}

// lift deletes a filter group — the handle-less delete the kernel takes
// as the whole priority — so its pairs fall to the groups below it.
func lift(t *testing.T, prio int) {
	t.Helper()
	tcnl, lo := openTrafficControl(t)
	group := tc.Object{
		Family:  unix.AF_UNSPEC,
		Ifindex: lo,
		Parent:  core.BuildHandle(1, 0),
		Info:    core.FilterInfo(uint16(prio), unix.ETH_P_IP),
		Kind:    "u32",
	}
	if err := tcnl.Filter().Delete(&group); err != nil {
		t.Fatalf("lifting the priority-%d filters: %v", prio, err)
	}
}
