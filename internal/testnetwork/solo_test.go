package testnetwork

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// soloEnv names the test a re-executed test binary runs alone; soloBase
// names the loopback-host draw the inner run's pool starts at, so the
// processes never draw one host — a fabric node holds no underlay port,
// but its resident applications still bind their fixed ports on the kernel
// loopback the processes share.
const (
	soloEnv  = "CION_TEST_SOLO"
	soloBase = "CION_TEST_SOLO_HOST_BASE"
)

// soloBands widths the band of host draws each re-executed run claims
// above the outer run's last draw at its exec: the n-th inner run's band
// starts a full width above whatever the outer and every earlier inner can
// reach, so the draws never meet — the outer draws a few hundred hosts in
// a whole suite, each inner a dozen, and the pool holds sixty-four
// thousand.
const soloBands = 1000

// soloDraws counts the bands the re-executed runs have claimed.
var soloDraws atomic.Uint32

// solo runs the calling test alone in a fresh process of the test binary —
// no namespace, no privileges, only the process isolation the heaviest
// labs need beside the race detector: a lab that boots a full tier crawls
// late in a suite process that has already hosted every other lab's nodes
// under race's shadow, and a fresh process runs it at its own pace. The
// outer run starts the test binary again for this test alone, then turns
// the test parallel and reports false, failing with the inner run's output
// when the inner run fails; the inner run reports true, and the test
// proceeds. The inner run starts before the test turns parallel: until its
// exec, the fork holds every descriptor the test process has open, so a
// fork beside running tests would keep bound a socket one of them closed
// to rebind its address.
func solo(t *testing.T) bool {
	t.Helper()
	if os.Getenv(soloEnv) == t.Name() {
		return true
	}
	args := []string{"-test.run=^" + t.Name() + "$", "-test.count=1", "-test.v"}
	if deadline, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout="+time.Until(deadline).String())
	}
	var out bytes.Buffer
	cmd := exec.Command(os.Args[0], args...)
	// The inner dies with the outer: a suite run that times out would
	// otherwise leave it holding its band of the loopback against whatever
	// runs next, and the namespace that once made such orphans harmless is
	// gone.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(),
		soloEnv+"="+t.Name(),
		soloBase+"="+strconv.FormatUint(
			uint64(hostDraws.Load()+soloDraws.Add(soloBands)), 10),
	)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s in its own process: %v", t.Name(), err)
	}
	t.Parallel()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("running %s in its own process: %v\n%s", t.Name(), err, out.Bytes())
	}
	return false
}
