# Stabilize the tests by convergence and consolidation

This proposal spends an audit. The suite passes — every package green under
`-race -count=2` — but its waits are durations the runner must out-guess,
its harness leaks past the tests that spawned it, its ports bind
conventions where the number is not the proposition, four labs run
serialized under a header that promises parallel, a handful of seams carry
no episode at all, and the setups the labs share are copy-pasted wherever
a lab needs them. The change is mechanical and test-only: every wait
states its condition or runs on fake time; the harness's goroutines join
and log off `t`; a test binds a conventional port only where the number is
the proposition; the serialized labs take the marker their header already
claims; the uncovered seams — the beaconing loop's absorbed panic first —
get their first episodes; and each repeated double becomes one helper. No
production source moves.

[TOC]

## Summary

The audit's census, and what each class becomes:

| Class | Today | After |
| :--- | :--- | :--- |
| Waits | forty-three `time.Sleep` sites in twenty-three files — pacing multiples, alignment spins, settle loops | a polled condition, a fake clock, or a named negative window |
| The harness's afterlife | daemon goroutines that log through `t` and outlive their tests | goroutines joined or bounded, logging off `t` |
| Ports | conventional numbers bound where the number says nothing | ephemeral binds; the convention held only where the number is the proposition |
| Parallelism | four labs serialized against their own header's promise | the marker the header already claims |
| Coverage | five seams with no episode, the newest behavior change among them | five first episodes |
| Doubles | boot closures, topologies, settle loops, and stores copy-pasted per file | one helper each, beside the suites that already share |

None of this is a rewrite. The suite's architecture — the pure-unit tier,
the synctest bubbles, the per-package doubles, the integration labs, and
the contract suites
([walk_test.go](/pkg/modules/walk_test.go) enforcing them) — stands as the
audit found it; this proposal tightens the bolts the audit found loose.

## Motivation

The house rule against sleeping already exists: the coding style calls
`time.Sleep` unreliable and prescribes `testing/synctest`, and the unit
tier obeys — every clock-driven, socket-free test already runs its sleeps
inside a bubble. What the rule never reached is the rest of the tree. The
labs sleep pacing multiples and hope the system settled
([join_test.go](/internal/testnetwork/join_test.go) waits three
transmission intervals for verdicts it could read); the dataplane's cap
episode aligns itself to a wall-clock second boundary by spinning; the
SOCKS fragment episode sleeps a fixed hundred milliseconds and asserts an
exact counter across two asynchronous netstacks. Each is green today
because the runner is fast; each is a flake report waiting for a loaded
CI hour — and the integration suite already measures ninety-plus seconds,
so the loaded hour is not hypothetical.

The harness has its own two hazards. Its daemon goroutines — the HTTP/3
server and the application loops
([network.go](/internal/testnetwork/network.go)) — report their exit
errors through `t.Logf`, and a goroutine that lands after its test's
cleanups finish panics the whole binary: one scheduling gap converts one
lab's noise into every lab's failure. And several spawned loops are
cancelled but never joined — the enrollment core's server
([enroll_test.go](/pkg/controlplane/enroll_test.go)), the SOCKS lab's
client pump ([app_test.go](/pkg/apps/socks/app_test.go)), the dataplane
and SCION serve loops — so a hung loop outlives its test silently, and
the SOCKS pump leaks once per lab, doubled under `-count=2`.

Coverage has one glaring hole and four quiet ones. The most recent
behavioral change on main — the beaconing loop absorbing a panicked round
instead of dying — is protected by no test: no test in the package calls
`Run` at all. Beside it sit the path provider's bootstrap arm
([provider.go](/pkg/scion/provider.go)), the verifier's empty-answer
caching seam ([lookup.go](/pkg/controlplane/lookup.go)), the peer
middleware's unidentified-request tolerance
([peeria.go](/pkg/peeria/peeria.go)), and the ACME HTTP-01 challenge
server ([tls.go](/pkg/webpki/tls.go)) — each a behavior the code states
and no episode pins.

And the suite pays rent on copy-paste. The static lab's boot closure
exists three times nearly verbatim; the three-node line topology is
rebuilt in four files; the dataplane's metrics settle loop is duplicated
between two episodes; three packages carry independent in-memory
directory-store doubles. Every copy is a place the next pacing change
lands twice or not at all.

### Goals

*   **Waits that converge:** the fork episode's unguarded leg polls its
    path before running
    ([ping_test.go](/internal/testnetwork/ping_test.go)); the join
    episode polls the monitor's verdict instead of sleeping transmission
    intervals; the fragment and cap episodes assert bounds their own
    pacing states; the idle sweep's survive branch drives the synthetic
    now its expire branch already drives; the approval-latency episode
    drops its wall-clock bound for the ordering it already proves.
*   **A harness that outlives nothing:** daemon exits log through the
    package logger, never `t`; every spawned loop joins or is bounded by
    the cleanup that cancels it; the SOCKS client pump closes with its
    lab; the enrollment server joins; the configuration episode closes
    the store it opens
    ([wireguard_test.go](/internal/services/wireguard_test.go)); the
    process fixture's dead defer goes
    ([main_test.go](/internal/testnetwork/main_test.go)).
*   **Ports the number owns:** the SCION conn episodes' 30044 literals
    become ephemeral picks
    ([conn_test.go](/pkg/scion/conn_test.go),
    [conn_parse_test.go](/pkg/scion/conn_parse_test.go)); the WireGuard
    validation episode binds ephemeral where the default is asserted as a
    parse, not a bind ([app_test.go](/pkg/apps/wireguard/app_test.go));
    the measured mounts hold the conventional rendezvous port on loopback
    hosts the convention allots that package
    ([provider_test.go](/pkg/modules/topology/impl/measured/provider_test.go)).
*   **The parallel back:** the coordination open-join and the three
    admission labs take `t.Parallel()`, each already holding its own host
    range ([coordination_test.go](/internal/testnetwork/coordination_test.go),
    [admission_test.go](/internal/testnetwork/admission_test.go)).
*   **The first episodes:** the beaconing loop absorbs a seeded panic and
    keeps stepping, on the shape the sweep loop's episode already sets
    ([lifecycle_test.go](/pkg/controlplane/lifecycle_test.go)); the
    bootstrap arm, the empty-answer seam, the unidentified request, and
    the HTTP-01 challenge each get their pin.
*   **One of each double:** the static boot closure, the line topology,
    the settle loop, the MAC helper, the directory-store double, the
    fixture loaders, and the database adapters' `Prepare` each become one
    shared helper beside the suites that already share.
*   **Claims that hold:** the pending-join episode asserts the transport
    state its comment claims or loses the claim; the tailnet echo's
    non-blocking check blocks on its own timeout
    ([coordination_test.go](/internal/testnetwork/coordination_test.go));
    the duplicated validation rows keep the suite nearest the validator;
    the stale comments and the one proposal citation in a test comment
    restated or go ([ifdown_test.go](/pkg/scion/ifdown_test.go),
    [conn_zero_test.go](/pkg/scion/conn_zero_test.go)).

### Non-goals

*   No production change of any kind: not the limiter's clock, not the
    monitor's seams, not the dialer — where an episode's honest fix would
    touch a production source, the episode asserts a bound instead, and
    the seam's own proposal is the place a clock ever gets injected.
*   No warm-dial signal: the node's coordination client gaining a
    session-established observable would delete the labs' warm-up loops,
    but it is a production surface bought for the harness — its own
    proposal if the wall clock demands it, and the deserialized labs
    overlap most of the cost until then.
*   No synctest for the real-socket tiers: the bubbles freeze on live
    sockets; the labs keep deadlines and polls, and the telegram double's
    real-time windows stay, named as the exception the socket forces.
*   No new scenarios: the audit found seams without episodes, not
    episodes without stories — the suite's breadth stands, and no lab is
    added beyond the five pins.
*   No episode deletions beyond the duplicated rows: the static BFD
    parity episode and the two-layer enrollment refusals stay — the audit
    judged them defensible, and consolidation reaches their setups, not
    their assertions.
*   No CI or tooling: no flake budgets, no retry wrappers, no load
    harnesses — the fixes are in the tests, or they are not fixes.

## Proposal

### The waits state their conditions

The rule the unit tier already obeys extends to every tier, with the
primitive each tier can carry:

*   **Where nothing real rides, the clock stays fake.** The SOCKS idle
    sweep's survive branch joins its expire branch on the synthetic now
    the episode already drives — the real-elapsed comparison against a
    hundred-millisecond bound goes with it.
*   **Where sockets ride, the condition is polled.** The fork episode's
    second leg gains the guard its sibling already carries: every pinger's
    path polled before `ping.Run` runs, because resolution does not
    retry. The join episode's verdict wait becomes a poll on the
    monitor's own state — the condition it actually wants — instead of a
    fixed multiple of the transmission interval. The largest negative
    window, the denied candidate's retirement, polls for the retirement
    the pacing schedules rather than sleeping a fixed multiple above the
    window that forces it.
*   **Where a count crosses an asynchronous boundary, the assertion is
    the bound the mechanism states.** The fragment episode waits for the
    counter its drop increments and asserts the drop happened — not the
    exact instant. The cap episode sends a fixed burst it reads to
    completion, keeps its burst inside one window of its own choosing,
    and asserts the cap's contract as a bound: at least one answer, no
    more than the cap. The approval-latency episode drops its
    wall-clock upper bound — the ordering is already proven by the prompt
    consumed and the chain held; slowness under `-race` is not a
    regression.
*   **What remains is named.** The negative windows that prove absence —
    the unjoined candidate, the silent peer, the unadmitted enrollment —
    keep their real-time sleeps, bounded by the mechanism's own pacing
    and commented as absence proofs. They are the honest residue, and the
    census says so.

### The harness outlives nothing

Two rules, both mechanical:

*   **Nothing logs through `t` that outlives the test.** The harness's
    daemon goroutines and the enrollment core's server report through the
    package logger; `t` remains for the test's own thread. The
    log-after-completion panic class deletes with the move.
*   **Everything spawned joins or is bounded.** The serve loops gain the
    done-channel join the dataplane's serve episode already practices;
    the SOCKS lab's client link closes with the lab; the enrollment
    server's cleanup waits for its exit; the wireguard configuration
    episode closes the store the constructor opens. A hung loop becomes a
    test failure with a stack, not a silent tenant — and the process
    fixture's dead defer, skipped by `os.Exit` since the day it was
    written, goes, the CA directory's lifetime stated as the fixture's
    own choice.

### Ports the number owns

A conventional port in a test says one of two things: the number is the
proposition — the default parses, the ladder binds, the acceptor answers
on its conventional slot — or the number says nothing, and a fixed bind
is pure collision exposure under package-parallel runs. The audit found
the second kind wearing the first kind's clothes: the SCION conn
episodes' 30044 literals assert wire formats that never read the number;
the WireGuard validation episode binds 51820 to validate a configuration
the parse suite already asserts as a default. These become ephemeral.
The measured provider's mounts keep the rendezvous constant — the
conventional slot is part of what the episode mounts — but hold it on
loopback hosts the fixed-slot convention allots that package, out of the
shared first host's way. The reserve-release picks stay as they are: the
kernel's answer to a probe-and-rebind is a window the audit ranks
tolerable, and closing it would cost the servers a listener seam they do
not have.

### The labs take their parallel back

The coordination file's header already states the design — each lab holds
its own loopback pair, so the labs run parallel — and four episodes
simply lack the marker: the open-join and the three admission labs, each
on a host range the convention allots them alone. The markers land; the
header stops overclaiming; the serialized head of the integration run
overlaps. Nothing else moves — the host-byte convention is verified
disjoint today, and the fixed slots it protects are exactly why these
labs can parallelize at all.

### The seams without episodes

Five pins, each the first coverage of a stated behavior:

*   **The absorbed round.** The beaconing loop gains the episode the
    sweep loop already has: a round seeded to panic, the loop absorbing
    and logging it, the next round stepping — the regression guard for
    the newest behavior change on main, on the bubble-and-cancel shape
    its sibling set.
*   **The bootstrap arm.** The path provider's local resolution gains the
    bootstrap case — a node mid-enrollment composing over what the core
    route carries, the arm the composition table never exercised.
*   **The empty answer.** The lookup cache's refusal to cache an empty
    fetch — the seam whose comment cites a real ping regression — gets
    the episode that keeps the next refactor from re-importing it.
*   **The unidentified request.** The peer middleware's tolerance branch:
    a request with no peer chain authenticates nothing and proceeds
    unidentified — the security-relevant default, pinned as behavior
    rather than accident.
*   **The HTTP-01 challenge.** The ACME arm the static-cert episodes
    route around gains its answer episode: the challenge server solving
    on its port and the extension the certificate carries.

### One of each double

The consolidation the audit priced, each helper landing beside the suite
that already shares its kind:

*   The static lab's boot closure — three near-verbatim copies — becomes
    one builder the static and BFD episodes call.
*   The three-node line topology — four constructions — becomes one
    builder over the harness's placement, the episodes keeping the
    invariants that differ.
*   The dataplane's metrics settle loop — two copies — becomes one helper
    the batch and serve episodes share; the MAC helper folds its two
    byte-identical implementations into the bench harness that owns the
    fixture.
*   The directory-store doubles — three in-memory implementations and a
    triplicated key-minting helper — fold to one double in the shared
    test package the store's contract suite already names.
*   The trust database's fixture loaders join the contract suite's; the
    three database adapters' `Prepare` variants — same job, three
    hand-rolled shapes — become one helper with the reopen behavior each
    adapter actually has.

### Claims that hold

The small truths, each one line of cleanup: the pending-join episode
asserts the transport state its comment promises or the comment narrows
to what the episode shows; the tailnet echo's completion check blocks on
its own timeout instead of a `select` whose empty default usually
decides it; the host-port validation proposition keeps the suite nearest
the validator and the duplicate row leaves the command suite; the ping
command's foreign-argument refusal keeps the shared matrix and leaves
its own copy; the cache helper's stale lifetime comment and the test
comment citing a proposal restate to what the code does.

## Test plan

*   **The waits:** each converted episode passes `-race -count=2` and a
    deliberately loaded runner — the converted conditions hold under CPU
    contention that would have failed the sleeps they replace, and the
    named negative windows keep their comments.
*   **The harness:** the integration suite passes with the daemon loops
    logging off `t` and every spawned loop joined — a lab whose loop
    hangs fails that lab, not the binary; `-count=2` leaks no goroutine
    the `-count=1` run did not.
*   **The ports:** `go test ./...` passes package-parallel — the
    conventional binds that remain are the ones whose episodes assert
    the number, verified by a run with the integration suite beside the
    packages whose slots they once shared.
*   **The parallel:** the four marked labs run beside their siblings —
    the suite's wall clock drops by the serialized head's overlap,
    measured at landing against the ninety-second-plus baseline.
*   **The pins:** each new episode fails against the behavior it guards
    — the absorbed-panic episode against a loop that propagates, the
    empty-answer episode against a cache that stores nothing — by
    construction or by the mutation that proves it.
*   **The doubles:** the consolidated helpers leave no copy behind —
    the audit's census of duplicated setups re-run clean — and every
    episode that moved to a helper passes unchanged.

## Implementation history
