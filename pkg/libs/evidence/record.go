package evidence

import (
	"log/slog"
	"time"
)

// Record is one change a decision made, an entry of the node's journal of
// changes: the change, its subject, the option left and the one taken, why,
// and the line and the estimates the decision weighed, each estimate named.
type Record struct {
	// At is when the change was made.
	At time.Time
	// Change names the change, the message its log line carries.
	Change string
	// Subject is what the decision is about, such as a lease's destination.
	Subject string
	// From and To are the options left and taken, empty for none.
	From, To string
	// Why is the reason the decision gives.
	Why string
	// Line is the margin the decision weighed against; zero for none.
	Line time.Duration
	// Weighed are the estimates the decision weighed.
	Weighed []Weighed
}

// Weighed is one estimate a decision weighed, by the name its record gives
// it.
type Weighed struct {
	Name string
	Estimate
}

// LogLine returns the record's log line: its change as the message, then its
// subject, the options left and taken, why, the line when there is one, and
// the estimates weighed, grouped apart from the record's own attributes,
// each a group of its value, the bounds it has, and its samples answered
// and sent.
func (r Record) LogLine() (string, []slog.Attr) {
	attrs := []slog.Attr{
		slog.String("subject", r.Subject),
		slog.String("from", r.From),
		slog.String("to", r.To),
		slog.String("why", r.Why),
	}
	if r.Line > 0 {
		attrs = append(attrs, slog.Duration("line", r.Line))
	}
	weighed := make([]slog.Attr, 0, len(r.Weighed))
	for _, w := range r.Weighed {
		group := []slog.Attr{slog.Duration("value", w.Value)}
		if w.HasLo {
			group = append(group, slog.Duration("lo", w.Lo))
		}
		if w.HasHi {
			group = append(group, slog.Duration("hi", w.Hi))
		}
		group = append(group, slog.Int("answered", w.Answered), slog.Int("sent", w.Sent))
		weighed = append(weighed, slog.GroupAttrs(w.Name, group...))
	}
	return r.Change, append(attrs, slog.GroupAttrs("weighed", weighed...))
}
