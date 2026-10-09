// Package supervise runs a node's loops as one group and releases the
// resources they use once every loop has returned.
//
// Each loop runs under a policy. A Fatal loop's error stops the group and
// becomes its result, and its panic crashes the process: an ordered stop
// would wait on loops that may block on state the panicking goroutine left
// behind. A Degrade loop's panic and error are logged, and its siblings
// serve on. The boot registers each resource where it acquires it, and the
// resources release in reverse order of registration after the last loop
// has returned, on a failed boot as on a stop.
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

// Group is a set of loops under one context and the stack of resources they
// use. The boot starts the loops and registers the resources before it
// waits on the group or stops it.
type Group struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	log    *slog.Logger
	loops  sync.WaitGroup

	mu    sync.Mutex
	owned []resource

	released sync.Once
	result   error
}

// resource is one registered release, named for the errors it returns.
type resource struct {
	name    string
	release func() error
}

// loopError is a Fatal loop's failure as the group's cancellation cause,
// which tells it apart from a stop the parent context or Stop brought.
type loopError struct {
	loop string
	err  error
}

func (e *loopError) Error() string { return e.loop + ": " + e.err.Error() }

func (e *loopError) Unwrap() error { return e.err }

// New returns an empty group and its context, which ends when the parent
// context does, when the group is stopped, or when a Fatal loop fails.
func New(ctx context.Context) (*Group, context.Context) {
	ctx, cancel := context.WithCancelCause(ctx)
	return &Group{ctx: ctx, cancel: cancel, log: slog.Default()}, ctx
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

// Stop cancels the group and returns what Wait returns. It is idempotent,
// and on a failed boot it releases what the boot acquired.
func (g *Group) Stop() error {
	g.cancel(nil)
	return g.Wait()
}
