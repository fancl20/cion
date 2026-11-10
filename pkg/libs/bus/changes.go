package bus

import "log/slog"

// Change is one change the node made to its state, an entry of its journal
// of changes, which renders its own log line.
type Change interface {
	// LogLine returns the change's log line: its message and attributes.
	LogLine() (msg string, attrs []slog.Attr)
}
