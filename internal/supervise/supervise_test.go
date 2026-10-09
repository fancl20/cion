package supervise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/google/go-cmp/cmp"
)

var (
	errBoom  = errors.New("boom")
	errStore = errors.New("store fault")
)

// newGroup returns a group whose log the returned recorder keeps.
func newGroup() (*Group, context.Context, *recorder) {
	rec := &recorder{}
	g, ctx := New(context.Background())
	g.log = slog.New(rec)
	return g, ctx, rec
}

// recorder is a slog handler keeping every record's level, message, and
// attributes.
type recorder struct {
	mu      sync.Mutex
	records []record
}

// record is one kept log record.
type record struct {
	Level   slog.Level
	Message string
	Attrs   map[string]string
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	attrs := make(map[string]string)
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record{Level: rec.Level, Message: rec.Message, Attrs: attrs})
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *recorder) WithGroup(string) slog.Handler { return r }

// find returns the kept records carrying the message.
func (r *recorder) find(msg string) []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found []record
	for _, rec := range r.records {
		if rec.Message == msg {
			found = append(found, rec)
		}
	}
	return found
}

// TestFatalErrorStopsGroup checks a Fatal loop's error: the group's context
// ends, so the sibling returns, and Wait returns the error wrapped with the
// loop's name, joined with the releases' errors.
func TestFatalErrorStopsGroup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, rec := newGroup()
		siblingReturned := false
		g.Go("sibling", Degrade, func(ctx context.Context) error {
			<-ctx.Done()
			siblingReturned = true
			return ctx.Err()
		})
		g.Go("beaconer", Fatal, func(context.Context) error { return errBoom })
		g.Own("store", func() error { return errStore })

		err := g.Wait()
		if !errors.Is(err, errBoom) || !errors.Is(err, errStore) {
			t.Errorf("Wait = %v, want the loop's error joined with the release's", err)
		}
		if want := "beaconer: boom\nreleasing store: store fault"; err == nil || err.Error() != want {
			t.Errorf("Wait = %q, want %q", err, want)
		}
		if !siblingReturned {
			t.Error("the sibling still runs once Wait has returned")
		}
		want := []record{{
			Level:   slog.LevelError,
			Message: "Loop failed; stopping",
			Attrs:   map[string]string{"loop": "beaconer", "err": "boom"},
		}}
		if diff := cmp.Diff(want, rec.find("Loop failed; stopping")); diff != "" {
			t.Errorf("failure records (-want +got):\n%s", diff)
		}
	})
}

// TestDegradeLogsAndServesOn checks a Degrade loop's panic and error: each
// is logged with the loop's name, the panic with its stack, and the group
// runs on until Stop.
func TestDegradeLogsAndServesOn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, ctx, rec := newGroup()
		g.Go("panicker", Degrade, func(context.Context) error { panic("bad pass") })
		g.Go("exiter", Degrade, func(context.Context) error { return errBoom })
		g.Go("sibling", Fatal, func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		})
		synctest.Wait()
		if ctx.Err() != nil {
			t.Fatalf("the group stopped on a degraded loop: %v", context.Cause(ctx))
		}
		if err := g.Stop(); err != nil {
			t.Errorf("Stop = %v, want nil", err)
		}

		panics := rec.find("Loop panicked")
		if len(panics) != 1 || !strings.Contains(panics[0].Attrs["stack"], "supervise_test.go") {
			t.Fatalf("panic records = %v, want one carrying the panicking frame's stack", panics)
		}
		delete(panics[0].Attrs, "stack")
		want := []record{{
			Level:   slog.LevelError,
			Message: "Loop panicked",
			Attrs:   map[string]string{"loop": "panicker", "panic": "bad pass"},
		}}
		if diff := cmp.Diff(want, panics); diff != "" {
			t.Errorf("panic records (-want +got):\n%s", diff)
		}
		want = []record{{
			Level:   slog.LevelError,
			Message: "Loop exited",
			Attrs:   map[string]string{"loop": "exiter", "err": "boom"},
		}}
		if diff := cmp.Diff(want, rec.find("Loop exited")); diff != "" {
			t.Errorf("exit records (-want +got):\n%s", diff)
		}
	})
}

// TestFatalCompletionKeepsGroupRunning checks a Fatal loop's nil return:
// logged as completion, with the group running on.
func TestFatalCompletionKeepsGroupRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, ctx, rec := newGroup()
		g.Go("certificates", Fatal, func(context.Context) error { return nil })
		synctest.Wait()
		if ctx.Err() != nil {
			t.Fatalf("the group stopped on a completed loop: %v", context.Cause(ctx))
		}
		want := []record{{
			Level:   slog.LevelInfo,
			Message: "Loop completed",
			Attrs:   map[string]string{"loop": "certificates"},
		}}
		if diff := cmp.Diff(want, rec.find("Loop completed")); diff != "" {
			t.Errorf("completion records (-want +got):\n%s", diff)
		}
		if err := g.Stop(); err != nil {
			t.Errorf("Stop = %v, want nil", err)
		}
	})
}

// TestErrorAfterStopIsNoCause checks an error a loop returns once the group
// has stopped: the stop's own echo, logged at debug level and not the
// group's result.
func TestErrorAfterStopIsNoCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, rec := newGroup()
		g.Go("endpoint", Fatal, func(ctx context.Context) error {
			<-ctx.Done()
			return fmt.Errorf("reading: %w", net.ErrClosed)
		})
		if err := g.Stop(); err != nil {
			t.Errorf("Stop = %v, want nil", err)
		}
		want := []record{{
			Level:   slog.LevelDebug,
			Message: "Loop returned after the stop",
			Attrs: map[string]string{
				"loop": "endpoint",
				"err":  "reading: use of closed network connection",
			},
		}}
		if diff := cmp.Diff(want, rec.find("Loop returned after the stop")); diff != "" {
			t.Errorf("echo records (-want +got):\n%s", diff)
		}
	})
}

// TestReleasesRunInReverseAfterLoops checks the stack: the releases run in
// reverse order of registration, after the loops have returned.
func TestReleasesRunInReverseAfterLoops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, _ := newGroup()
		var order []string
		g.Go("loop", Degrade, func(ctx context.Context) error {
			<-ctx.Done()
			order = append(order, "loop returned")
			return nil
		})
		for _, name := range []string{"A", "B", "C"} {
			g.Own(name, func() error {
				order = append(order, name)
				return nil
			})
		}
		if err := g.Stop(); err != nil {
			t.Errorf("Stop = %v, want nil", err)
		}
		if diff := cmp.Diff([]string{"loop returned", "C", "B", "A"}, order); diff != "" {
			t.Errorf("order (-want +got):\n%s", diff)
		}
	})
}

// TestStopReleasesOnce checks Stop on a group no loop joined: it releases at
// once, and a second Stop returns the same result and releases nothing
// again.
func TestStopReleasesOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, _ := newGroup()
		calls := 0
		g.Own("store", func() error {
			calls++
			return errStore
		})
		first := g.Stop()
		if !errors.Is(first, errStore) || calls != 1 {
			t.Fatalf("first Stop = %v after %d releases, want the release's error after one",
				first, calls)
		}
		if second := g.Stop(); second != first || calls != 1 {
			t.Errorf("second Stop = %v after %d releases, want %v after one", second, calls, first)
		}
	})
}

// TestReleaseErrors checks the releases' errors: a net.ErrClosed is
// dropped, and any other joins the result, named by its resource.
func TestReleaseErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, _, _ := newGroup()
		g.Own("conn", func() error { return fmt.Errorf("closing: %w", net.ErrClosed) })
		g.Own("store", func() error { return errStore })
		if err, want := g.Stop(), "releasing store: store fault"; err == nil || err.Error() != want {
			t.Errorf("Stop = %v, want %q", err, want)
		}
	})
}

// crashEnv marks the test binary's run that executes the crashing loop.
const crashEnv = "CION_SUPERVISE_CRASH"

// TestFatalPanicCrashes checks a Fatal loop's panic crashes the process:
// the test binary runs again for the panicking case alone, and it exits
// non-zero with the panic's value in its output. Until its exec, the fork
// holds every descriptor the test process has open, and no test in the
// package rebinds an address, so the fork keeps no sibling's socket bound.
func TestFatalPanicCrashes(t *testing.T) {
	if os.Getenv(crashEnv) != "" {
		g, _ := New(context.Background())
		g.Go("beaconer", Fatal, func(context.Context) error { panic("supervise test crash") })
		_ = g.Wait()
		return
	}
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestFatalPanicCrashes$", "-test.count=1", "-test.timeout=1m")
	cmd.Env = append(os.Environ(), crashEnv+"=1")
	out, err := cmd.CombinedOutput()
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Fatalf("the crashing run = %v, want a non-zero exit\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("panic: supervise test crash")) {
		t.Errorf("the crashing run's output lacks the panic's value:\n%s", out)
	}
}
