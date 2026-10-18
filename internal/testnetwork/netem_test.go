package testnetwork

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// netnsEnv names the test a re-executed test binary runs inside its own
// user and network namespace; netnsSkipEnv names the file the inner run
// writes its skip's reason to, which the outer run reports as its own.
const (
	netnsEnv     = "CION_TEST_NETNS"
	netnsSkipEnv = "CION_TEST_NETNS_SKIP"
)

// The loopback's shaping bands: the added bands of a prio root qdisc, each a
// netem child — three one-way delays and a total loss. Unclassified traffic
// keeps the default bands.
const (
	band1ms  = "1:4"
	band15ms = "1:5"
	band40ms = "1:6"
	bandLoss = "1:7"
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
	refuse(t, "reading lo's flags", errno)
	req.Flags |= syscall.IFF_UP
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		siocsifflags, uintptr(unsafe.Pointer(&req)))
	refuse(t, "raising lo", errno)
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

// shapeLoopback installs the shaping bands beneath a prio root qdisc on
// the loopback ownNetns raised.
func shapeLoopback(t *testing.T) {
	t.Helper()
	runTool(t, "tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "7")
	for band, netem := range map[string][]string{
		band1ms:  {"delay", "1ms"},
		band15ms: {"delay", "15ms"},
		band40ms: {"delay", "40ms"},
		bandLoss: {"loss", "100%"},
	} {
		runTool(t, "tc", append([]string{"qdisc", "add", "dev", "lo", "parent", band, "netem"},
			netem...)...)
	}
}

// steer sends both directions between two hosts into the band through u32
// filters of the given priority, one group per priority: the lowest number
// matches first.
func steer(t *testing.T, prio int, band string, a, b netip.Addr) {
	t.Helper()
	for _, pair := range [][2]netip.Addr{{a, b}, {b, a}} {
		runTool(t, "tc", "filter", "add", "dev", "lo", "parent", "1:",
			"protocol", "ip", "prio", strconv.Itoa(prio), "u32",
			"match", "ip", "src", pair[0].String()+"/32",
			"match", "ip", "dst", pair[1].String()+"/32",
			"flowid", band)
	}
}

// lift deletes a filter group: its pairs fall to the groups below it.
func lift(t *testing.T, prio int) {
	t.Helper()
	runTool(t, "tc", "filter", "del", "dev", "lo", "parent", "1:", "prio", strconv.Itoa(prio))
}

// runTool runs a networking tool, failing the test with its output.
func runTool(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
