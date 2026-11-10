package services

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/google/go-cmp/cmp"

	"github.com/fancl20/cion/pkg/libs/bus"
)

// TestLogChanges checks the change log: each change logged once, as the line
// at Info it renders, those appended before the log started included, and a
// warning that counts the changes gone unread.
func TestLogChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && len(groups) == 0 {
					return slog.Attr{}
				}
				return a
			},
		}))
		changes := new(bus.Journal[bus.Change])
		for i := range bus.JournalKept + 3 {
			changes.Append(change{"Moved", strconv.Itoa(i)})
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			logChanges(ctx, changes, log)
			close(done)
		}()
		synctest.Wait()
		want := []string{`level=WARN msg="Changes went unlogged" changes=3`}
		for i := 3; i < bus.JournalKept+3; i++ {
			want = append(want, fmt.Sprintf("level=INFO msg=Moved subject=%d", i))
		}
		if diff := cmp.Diff(want, lines(&buf)); diff != "" {
			t.Errorf("the lines of the changes before the log (-want +got):\n%s", diff)
		}

		changes.Append(change{"Moved again", "a"})
		synctest.Wait()
		if diff := cmp.Diff([]string{`level=INFO msg="Moved again" subject=a`}, lines(&buf)); diff != "" {
			t.Errorf("the lines after the next change (-want +got):\n%s", diff)
		}
		cancel()
		<-done
	})
}

// change is a test's change: its message and subject.
type change struct{ msg, subject string }

func (c change) LogLine() (string, []slog.Attr) {
	return c.msg, []slog.Attr{slog.String("subject", c.subject)}
}

// lines returns the buffer's lines and empties it.
func lines(buf *bytes.Buffer) []string {
	s := strings.TrimSuffix(buf.String(), "\n")
	buf.Reset()
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
