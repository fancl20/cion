package evidence

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestRecordLogLine checks a record's log line: its change the message, then
// its subject, options, why, the line when there is one, a negative one
// included, and each estimate weighed with the bounds it has, grouped apart
// from the options of the same names.
func TestRecordLogLine(t *testing.T) {
	ms := time.Millisecond
	bounded := Estimate{Value: 30 * ms, Lo: 25 * ms, Hi: 35 * ms, HasLo: true, HasHi: true, Answered: 5, Sent: 6}
	unbounded := Estimate{Value: 10 * ms, Answered: 2, Sent: 2}
	for _, tc := range []struct {
		name string
		r    Record
		want string
	}{{
		name: "a move weighed",
		r: Record{Change: "Lease moved", Subject: "1-ff00:0:1", From: "a", To: "b", Why: "a reason", Line: 4 * ms,
			Weighed: []Weighed{{Name: "from", Estimate: unbounded}, {Name: "to", Estimate: bounded}}},
		want: `level=INFO msg="Lease moved" subject=1-ff00:0:1 from=a to=b why="a reason" line=4ms ` +
			`weighed.from.value=10ms weighed.from.answered=2 weighed.from.sent=2 ` +
			`weighed.to.value=30ms weighed.to.lo=25ms weighed.to.hi=35ms weighed.to.answered=5 weighed.to.sent=6`,
	}, {
		name: "room allowed",
		r:    Record{Change: "Link promoted", Subject: "s", To: "b", Why: "w", Line: -5 * ms},
		want: `level=INFO msg="Link promoted" subject=s from="" to=b why=w line=-5ms`,
	}, {
		name: "a first read",
		r:    Record{Change: "Lease moved", Subject: "s", To: "b", Why: "w"},
		want: `level=INFO msg="Lease moved" subject=s from="" to=b why=w`,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if a.Key == slog.TimeKey && len(groups) == 0 {
						return slog.Attr{}
					}
					return a
				},
			}))
			msg, attrs := tc.r.LogLine()
			log.LogAttrs(context.Background(), slog.LevelInfo, msg, attrs...)
			if got := strings.TrimSuffix(buf.String(), "\n"); got != tc.want {
				t.Errorf("line:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}
