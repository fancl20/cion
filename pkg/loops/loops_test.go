package loops

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
)

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

// recordLogs makes a recorder the default logger until the test ends.
func recordLogs(t *testing.T) *recorder {
	rec := &recorder{}
	previous := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return rec
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

// kept returns the records kept so far.
func (r *recorder) kept() []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.records)
}

// TestPanicIsAbsorbed checks a loop's panic: it is logged once, with the
// loop's name and the panicking frame's stack, and the sibling runs on until
// the context ends.
func TestPanicIsAbsorbed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := recordLogs(t)
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		siblingReturned := make(chan struct{})
		Go(ctx, &wg, "panicker", func(context.Context) { panic("bad pass") })
		Go(ctx, &wg, "sibling", func(ctx context.Context) {
			<-ctx.Done()
			close(siblingReturned)
		})
		synctest.Wait()
		select {
		case <-siblingReturned:
			t.Fatal("the sibling returned before the context ended")
		default:
		}
		cancel()
		wg.Wait()

		got := rec.kept()
		if len(got) != 1 || !strings.Contains(got[0].Attrs["stack"], "loops_test.go") {
			t.Fatalf("records = %v, want one carrying the panicking frame's stack", got)
		}
		delete(got[0].Attrs, "stack")
		want := []record{{
			Level:   slog.LevelError,
			Message: "Loop panicked",
			Attrs:   map[string]string{"loop": "panicker", "panic": "bad pass"},
		}}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("records (-want +got):\n%s", diff)
		}
	})
}

// TestEarlyReturnIsLogged checks a loop that returns before its context
// ends: the return is logged with the loop's name, and a return once the
// context has ended is not.
func TestEarlyReturnIsLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := recordLogs(t)
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		Go(ctx, &wg, "quitter", func(context.Context) {})
		Go(ctx, &wg, "server", func(ctx context.Context) { <-ctx.Done() })
		synctest.Wait()
		cancel()
		wg.Wait()

		want := []record{{
			Level:   slog.LevelError,
			Message: "Loop exited",
			Attrs:   map[string]string{"loop": "quitter"},
		}}
		if diff := cmp.Diff(want, rec.kept()); diff != "" {
			t.Errorf("records (-want +got):\n%s", diff)
		}
	})
}

// TestWaitJoinsTheLoops checks the wait group: once the context ends, Wait
// returns only after every loop has returned, a loop still finishing its
// pass holding it.
func TestWaitJoinsTheLoops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		finish := make(chan struct{})
		Go(ctx, &wg, "prompt", func(ctx context.Context) { <-ctx.Done() })
		Go(ctx, &wg, "finishing", func(ctx context.Context) {
			<-ctx.Done()
			<-finish
		})
		waited := make(chan struct{})
		go func() {
			wg.Wait()
			close(waited)
		}()
		cancel()
		synctest.Wait()
		select {
		case <-waited:
			t.Fatal("Wait returned while a loop was finishing its pass")
		default:
		}
		close(finish)
		<-waited
	})
}

// TestSleep checks the pause in a fake-time bubble: a pause under a live
// context runs its full duration and reports true, a context ending midway
// cuts it short and reports false, and an ended context reports false even
// for a zero pause, whose timer is ready at once.
func TestSleep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		if !Sleep(t.Context(), time.Second) {
			t.Fatal("a pause under a live context reported false")
		}
		if got := time.Since(start); got != time.Second {
			t.Errorf("the pause took %v, want 1s", got)
		}

		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(time.Second/2, cancel)
		start = time.Now()
		if Sleep(ctx, time.Second) {
			t.Error("a pause whose context ended midway reported true")
		}
		if got := time.Since(start); got != time.Second/2 {
			t.Errorf("the cut pause took %v, want 500ms", got)
		}

		for range 100 {
			if Sleep(ctx, 0) {
				t.Fatal("a zero pause under an ended context reported true")
			}
		}
	})
}
