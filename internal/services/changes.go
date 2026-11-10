package services

import (
	"context"
	"log/slog"

	"github.com/fancl20/cion/pkg/libs/bus"
)

// logChanges logs each change the node's journal of changes keeps, once, as
// the line at Info the change renders. Changes that went unread before it
// reached them log a warning with their count. It returns once ctx ends.
func logChanges(ctx context.Context, changes *bus.Journal[bus.Change], log *slog.Logger) {
	var next uint64
	for range changes.Subscribe(ctx) {
		entries, dropped := changes.Since(next)
		if dropped > 0 {
			log.Warn("Changes went unlogged", "changes", dropped)
		}
		for _, c := range entries {
			msg, attrs := c.LogLine()
			log.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
		}
		next += dropped + uint64(len(entries))
	}
}
