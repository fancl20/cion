package testnetwork

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// netnsEnv names the test a re-executed test binary runs inside its own
// user and network namespace.
const netnsEnv = "CION_TEST_NETNS"

// The loopback's shaping bands: the added bands of a prio root qdisc, each a
// netem child — three one-way delays and a total loss. Unclassified traffic
// keeps the default bands.
const (
	band1ms  = "1:4"
	band15ms = "1:5"
	band40ms = "1:6"
	bandLoss = "1:7"
)

// ownNetns runs the calling test in a fresh user and network namespace,
// where the test owns the loopback and shapes it without touching the
// host's. The outer run starts the test binary again for this test alone,
// then turns the test parallel and reports false, failing the test with the
// inner run's output when the inner run fails; the inner run reports true
// and the test proceeds alone. The inner run starts before the test turns
// parallel: until its exec, the fork holds every descriptor the test process
// has open, so a fork beside running tests would keep bound a socket one of
// them closed to rebind its address. A host without unprivileged user
// namespaces fails the test rather than skipping it.
func ownNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(netnsEnv) == t.Name() {
		return true
	}
	args := []string{"-test.run=^" + t.Name() + "$", "-test.count=1", "-test.v"}
	if deadline, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout="+time.Until(deadline).String())
	}
	var out bytes.Buffer
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), netnsEnv+"="+t.Name())
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s in its own network namespace: %v", t.Name(), err)
	}
	t.Parallel()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("running %s in its own network namespace: %v\n%s", t.Name(), err, out.Bytes())
	}
	return false
}

// shapeLoopback brings the namespace's loopback up and installs the shaping
// bands beneath a prio root qdisc.
func shapeLoopback(t *testing.T) {
	t.Helper()
	runTool(t, "ip", "link", "set", "lo", "up")
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
