// Package supervise runs a node's loops as one group and releases the
// resources they use once every loop has returned.
//
// Each loop runs under a policy. A Fatal loop's error stops the group and
// becomes its result, and its panic crashes the process: an ordered stop
// would wait on loops that may block on state the panicking goroutine left
// behind. A Degrade loop's panic and error are logged, and its siblings
// serve on. A stop the parent context or Stop brings runs the group's
// drains first, while the loops still serve. The boot registers each
// resource where it acquires it, and the resources release in reverse order
// of registration after the last loop has returned, on a failed boot as on
// a stop.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Policy is how a loop's failure bears on its group.
type Policy int

const (
	// Fatal stops the group on an error the loop returns before the group's
	// context ends, the error becoming the group's result. A nil return is
	// completion, and the group runs on. A panic crashes the process.
	Fatal Policy = iota
	// Degrade logs a panic, with its stack, and a return before the group's
	// context ends; the group runs on, and nothing restarts the loop.
	Degrade
)

// DrainTimeout bounds a stop's drains: their context ends this long after
// the stop began.
const DrainTimeout = 2 * time.Second

// Group is a set of loops under one context, the drains a stop runs before
// that context ends, and the stack of resources the loops use. The boot
// starts the loops and registers the drains and the resources before it
// waits on the group or stops it.
type Group struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	log    *slog.Logger
	loops  sync.WaitGroup

	mu     sync.Mutex
	owned  []resource
	drains []drain

	// stopping marks the stop claimed: the first caller of stop runs it,
	// and the others return at once, Wait waiting on the context.
	stopping atomic.Bool
	released sync.Once
	result   error
}

// resource is one registered release, named for the errors it returns.
type resource struct {
	name    string
	release func() error
}

// drain is one registered drain, named for the panic it logs.
type drain struct {
	name string
	run  func(context.Context)
}

// loopError is a Fatal loop's failure as the group's cancellation cause,
// which tells it apart from a stop the parent context or Stop brought.
type loopError struct {
	loop string
	err  error
}

func (e *loopError) Error() string { return e.loop + ": " + e.err.Error() }

func (e *loopError) Unwrap() error { return e.err }

// New returns an empty group and its context, which ends once the parent
// context ends or the group is stopped, after the group's drains, and at
// once when a Fatal loop fails.
func New(parent context.Context) (*Group, context.Context) {
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	g := &Group{ctx: ctx, cancel: cancel, log: slog.Default()}
	context.AfterFunc(parent, g.stop)
	return g, ctx
}

// Go runs fn in its own goroutine under the group's context and the
// policy. An error fn returns after the group's context has ended is the
// stop's own echo — a socket closed beneath a read — logged at debug level
// and never the group's result.
func (g *Group) Go(name string, policy Policy, fn func(context.Context) error) {
	g.loops.Go(func() {
		if policy == Degrade {
			defer func() {
				if r := recover(); r != nil {
					g.log.Error("Loop panicked", "loop", name, "panic", r,
						"stack", string(debug.Stack()))
				}
			}()
		}
		g.settle(name, policy, fn(g.ctx))
	})
}

// settle applies the loop's policy to what it returned.
func (g *Group) settle(name string, policy Policy, err error) {
	switch {
	case g.ctx.Err() != nil:
		if err != nil {
			g.log.Debug("Loop returned after the stop", "loop", name, "err", err)
		}
	case err == nil:
		g.log.Info("Loop completed", "loop", name)
	case policy == Fatal:
		g.log.Error("Loop failed; stopping", "loop", name, "err", err)
		g.cancel(&loopError{loop: name, err: err})
	default:
		g.log.Error("Loop exited", "loop", name, "err", err)
	}
}

// Own registers a resource's release where the boot acquires the resource.
func (g *Group) Own(name string, release func() error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.owned = append(g.owned, resource{name: name, release: release})
}

// Drain registers fn to run when the parent context ends or Stop is called,
// before the group's context ends, so the loops still serve while it runs.
// The drains run at once, each with a context that ends DrainTimeout after
// the stop began, and the group's context ends once every drain has
// returned; a panic in one is logged. A Fatal loop's failure ends the
// context without them.
func (g *Group) Drain(name string, fn func(context.Context)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.drains = append(g.drains, drain{name: name, run: fn})
}

// stop runs the drains, unless a Fatal loop's failure ended the group's
// context already, and then ends the context. Only its first call does: a
// later one returns at once.
func (g *Group) stop() {
	if !g.stopping.CompareAndSwap(false, true) {
		return
	}
	if g.ctx.Err() == nil {
		g.mu.Lock()
		drains := g.drains
		g.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(g.ctx), DrainTimeout)
		var wg sync.WaitGroup
		for _, d := range drains {
			wg.Go(func() {
				defer func() {
					if r := recover(); r != nil {
						g.log.Error("Drain panicked", "drain", d.name, "panic", r,
							"stack", string(debug.Stack()))
					}
				}()
				d.run(ctx)
			})
		}
		wg.Wait()
		cancel()
	}
	g.cancel(nil)
}

// Wait blocks until the group's context ends, waits for every loop, and runs
// the releases in reverse order of registration. It returns the Fatal
// failure that stopped the group, wrapped with its loop's name, joined with
// the releases' errors. A release's net.ErrClosed is dropped: a socket its
// loop closed on the stop is closed again by its release, harmlessly. Every
// call returns the same result.
func (g *Group) Wait() error {
	<-g.ctx.Done()
	g.loops.Wait()
	g.released.Do(func() {
		var errs []error
		if failure, ok := context.Cause(g.ctx).(*loopError); ok {
			errs = append(errs, failure)
		}
		g.mu.Lock()
		owned := g.owned
		g.mu.Unlock()
		for _, o := range slices.Backward(owned) {
			if err := o.release(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("releasing %s: %w", o.name, err))
			}
		}
		g.result = errors.Join(errs...)
	})
	return g.result
}

// Stop runs the group's drains, cancels the group, and returns what Wait
// returns. It is idempotent, and on a failed boot it releases what the boot
// acquired.
func (g *Group) Stop() error {
	g.stop()
	return g.Wait()
}
