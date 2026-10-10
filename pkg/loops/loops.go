// Package loops runs a library's long-lived loops under the caller's wait
// group with the posture the node's supervisor gives a Degrade loop: a panic
// is absorbed and logged with its stack, and a return before the context
// ends is logged, each with the loop's name. No pkg/ package imports the
// supervisor, so the topology provider and the resident applications start
// their loops here. A goroutine started per peer, connection, or flow ends
// with what it serves, so it joins the wait group through the group's own Go.
package loops

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
)

// Go runs fn in its own goroutine under wg, passing it ctx. A panic in fn is
// absorbed and logged with the stack, and a return before ctx ends is logged:
// a loop runs until ctx ends.
func Go(ctx context.Context, wg *sync.WaitGroup, name string, fn func(context.Context)) {
	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Loop panicked", "loop", name, "panic", r,
					"stack", string(debug.Stack()))
			}
		}()
		fn(ctx)
		if ctx.Err() == nil {
			slog.Error("Loop exited", "loop", name)
		}
	})
}
