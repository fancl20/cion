# Lease each peer's path

This proposal implements
[ADR-0035](/docs/adrs/0035-choose-paths-by-measured-health.md)'s decision 5
but for near-best spreading, decision 4's callers' reports, and decision 6's
confirmations. The SCION library keeps one lease per peer, which holds a
path while it serves; the WireGuard mesh and relay, the RPC clients that
resolve their paths, punch, and ping ride leases, and report what their
traffic saw. The labs' judging of leases and the topology selection's route
requests land through proposals of their own.

[TOC]

## Summary

Today:

*   **Picks are per call.** `Choose` and `LocalPath` pick by health at each
    call and keep nothing
    ([proposal 0105](/docs/proposals/0105-pick-paths-by-measured-health.md)).
    Each consumer holds a path on its own terms:
    *   WireGuard caches a path per peer. A warm loop replaces it every 30
        seconds by its own rank and hysteresis, a challenger a fifth faster
        across two windows, blind to health; a signal quoting the peer drops
        it; and a send with nothing cached resolves `LocalPath`
        ([bind.go](/pkg/apps/wireguard/bind.go),
        [route.go](/pkg/apps/wireguard/route.go)). The relay shares the
        cache.
    *   The control plane's peer client and the WireGuard directory client
        resolve `LocalPath` when they dial, and keep the connection until a
        sweep ten minutes on or five seconds of silence
        ([client.go](/pkg/libs/scionrpc/client.go)).
    *   Punch resolves `Choose` per request, ping once per run.
*   **Only probes measure.** A completed call or echo shows that its path
    delivers, and a connection gone dark that it may not; neither reaches
    health. The prober heartbeats a path in use every five seconds whatever
    its traffic shows.

## Motivation

### Goals

*   Every flow to a peer rides one path. The path keeps serving while it is
    not ejected and is left at once when it is, within a heartbeat and a
    burst of its failure, by every consumer.
*   A cheaper path takes over only once it stayed cheaper beyond the band
    for a heartbeat, so near-equal paths do not flap.
*   Traffic counts as evidence: a delivered exchange confirms its path, a
    connection gone dark doubts it. A node without the ping application
    leaves a path its callers find dead.
*   The prober skips the heartbeat of a path traffic confirmed, and a peer
    whose tunnel only keeps alive costs no probes.

### Non-goals

*   Near-best spreading: no caller asks for it.
*   Callers' round trips: probes price paths.
*   WireGuard's reports: what a node receives rides its peer's path, and a
    handshake every two minutes adds little to the heartbeat.
*   The WebPKI client, which dials the founder's route as the locator gives
    it, and the clients that ride one-hop paths.
*   Removing the ten-second hold: health, composition's `Crossing`, the
    topology selection, and the prober still read it.

## Proposal

*   **A lease per peer** ([lease.go](/pkg/libs/scion/lease.go)).
    `PathProvider.Lease(dst)` returns the destination's lease, one for every
    caller. `Path` returns the leased path and its ID. It evaluates the
    lease at most once a second, from local state and the lookups' held
    answers alone, and never waits, so a send or a dial may read it. `Await`
    waits on the destination's lookup while nothing composes, for punch and
    ping. A lease nothing read for ten minutes is dropped. With nothing
    composed, a lease serves the bootstrap route, as `LocalPath` does.
*   **What keeps and moves a lease.** Each evaluation refreshes the leased
    path to its freshest composition, then:
    *   keeps it while it composes and is not ejected, a suspect path
        included;
    *   moves to the best path at once when the leased path is ejected, no
        longer composes, or its hop fields lapse within thirty seconds;
    *   moves to a healthy path cheaper beyond the band once it was so at
        two evaluations five seconds apart.
*   **Requests.** Each evaluation updates the leases' entries for the
    destination as `Choose` does for its pick, about the leased path: in
    use, with when a caller last confirmed it and last doubted it, then its
    standby, suspect, and half-open. Their pick time is the lease's last use.
    A read that carries no payload, such as a WireGuard keepalive or
    handshake, is no use: a peer kept alive but idle lapses, unprobed.
*   **Callers' reports.** `Delivered(id)` and `Lost(id)` record what a
    caller's traffic over a path saw, a refusal counting as a delivery.
    Health counts a delivery as an answer, and a delivery after a lost burst
    lifts the ejection. A loss newer than the path's last answer makes it
    suspect, and three losses within the trust window since its last answer
    eject it.
*   **The prober** ([prober.go](/pkg/apps/ping/prober.go)) skips the
    heartbeat of a path in use a caller confirmed within it, and calls a
    burst for a path a caller doubted since its last answer.
*   **WireGuard** ([bind.go](/pkg/apps/wireguard/bind.go)). A send reads its
    peer's lease, a data packet as a use; while nothing composes, the
    endpoint's reversed arrival path serves. The path cache, the warm loop's
    route pick and hysteresis, the signal drops, and the `LocalPath`
    resolution go. The warm loop reads every directory peer's lease without
    use, so the lookups a first send needs are held. `route_switches_total`
    counts the moves sends see, and `path_refreshes_total` goes.
*   **RPC clients** ([client.go](/pkg/libs/scionrpc/client.go)). A client
    dials over its peer's lease in place of `PathTo`. Before a request, a
    connection dialed over a path the lease left, or whose hop fields lapse
    within thirty seconds, closes, and the request dials anew; requests in
    flight on it fail. Each connection reports on the path it was dialed
    over: a completed handshake and every response delivered, an idle or a
    handshake timeout lost, a refused handshake delivered. The age sweep
    goes. The control plane's peer client, the WireGuard directory client,
    and the puncher's per-request client ride leases.
*   **ping** ([pinger.go](/pkg/apps/ping/pinger.go)) reads its
    destination's lease per echo, reporting a reply delivered and an echo it
    waited out lost. A signal quoting an echo ends its wait and reports
    nothing.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/libs/bus` | Confirmations and doubts in path requests |
| `pkg/libs/scion` | Leases, callers' reports, health from reports |
| `pkg/libs/scionrpc` | Dials over leases, reports per connection |
| `pkg/apps/ping` | Heartbeats skip confirmed paths; the pinger rides the lease |
| `pkg/apps/wireguard` | Sends ride leases; the route cache goes |
| `pkg/apps` | The environment's paths offer leases |
| `pkg/modules/topology/impl/measured` | Punch rides the lease |
| `internal/services` | The peer client's leases |

## Compatibility

Nothing on the wire changes. WireGuard's `path_refreshes_total` metric goes.

## Test plan

*   **Leases.** A lease keeps a suspect path, moves at once off an ejected,
    vanished, or expiring one, and moves to a healthy path cheaper beyond
    the band only at the second evaluation five seconds on; a path within
    the band never takes over. Reads within a second share one evaluation;
    `Path` never waits and `Await` does; a lease falls back on the bootstrap
    route; an unread lease is dropped.
*   **Requests.** An evaluation writes the leased path in use with its
    confirmation and doubt, and its standby, suspect, and half-open; a read
    without use leaves the pick time.
*   **Reports.** A delivery makes a path healthy and lifts a burst's
    ejection; a newer loss makes it suspect; three losses eject it, and an
    answer resets them.
*   **The prober.** A confirmed path in use skips its heartbeat; a doubt
    calls a burst once.
*   **WireGuard.** Sends ride the lease and fall back on the arrival path; a
    keepalive does not count as use; a move counts a route switch.
*   **RPC clients.** A request after a lease move redials over the new path;
    a connection over an expiring path redials; handshakes, responses, and
    idle timeouts report.
*   **ping and punch** ride the lease and report.
*   **End to end.** On the fabric lab, A's lease to D leaves the cut link
    within a heartbeat and a burst, and returns once its path is cheaper
    beyond the band; between near-equal paths it stays put.
*   **The labs and benchmarks** pass, the regions cut benchmark among them.
