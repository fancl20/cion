# Move a peer between tiers only on confidence

This proposal implements
[ADR-0040](/docs/adrs/0040-decide-from-measured-evidence-in-one-library-and-record-every-change.md)'s
decision 2 for the topology selection's tiers: the walk that classes the
peers by direct round trip moves a peer across its line only once the
evidence library's comparison decides, the bounds of the peer and of the
tier's median both counted, and an undecided comparison keeps the peer on
the side the last window's tiers held it. With it, every decision ADR-0040
lists weighs its evidence through the library, and the ADR is accepted.

[TOC]

## Summary

Today
([tiers.go](/pkg/modules/topology/impl/measured/tiers.go)):

*   **The walk classes by values,** as
    [ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md)'s
    decision 3 has it: walked ascending by direct round trip, a peer opens
    the next tier when its reading exceeds `TierGap` times the median of
    the tier as walked. Each window derives its tiers from that window's
    readings alone.
*   **A peer near the line can change tier from one window to the next.**
    Its reading is the 80th percentile of five minutes of probes, and
    jitter carries it across twice the median and back. The tier's route
    count, its price, the members its useless tests weigh, and the harm
    that orders eviction and retirement move with it.
*   **The link changes taken on the tiers wait for their verdicts to
    hold,** so a change of tier that reverts within a hold delays a link
    change rather than causing one. A reading drifts slowly, though —
    consecutive windows share 27 of a neighbor's 30 probes — so a change
    of tier can outlast a hold.

## Motivation

### Goals

*   A peer changes tier only on confidence: it leaves its tier once its
    round trip lies past the line with the bounds' confidence, and joins
    one once it lies within.
*   An undecided comparison keeps the peer on the side the last window
    held it.
*   The line stays the walk's: `TierGap` times the median of the tier as
    walked.
*   The tiers stay runs of the peers walked ascending by direct round
    trip.
*   ADR-0040 is accepted.

### Non-goals

*   A hold on a change of tier: it changes no link, and the link changes
    that read the tiers hold their verdicts.
*   Records of tier changes: a tier is a class the window's decisions
    read, as a path's health is, not a change the node makes; the link
    changes it leads to record what they weighed.
*   The picks' ranking: it orders paths by the values of the library's
    estimates, to choose what a lease weighs and what the prober measures,
    and changes no state; the decision taken on it, a lease's move,
    decides on confidence.

## Proposal

### The line and its reason

| Decision | Better when | Line | Reason |
| :-- | :-- | :-- | :-- |
| A peer opens the next tier | the median member of the tier as walked beats the peer | `TierGap` less one times the median's value | a peer past twice the median sits in another latency class |

*   **Better** opens the next tier, and **not better** joins the current
    one.
*   **Undecided** keeps the side the last window held the peer on.
*   **The estimates** are the direct sides' bounds estimates, the 80th
    percentile of the last `scion.BoundSamples` probes within
    `scion.BoundSpan` at `scion.BoundConfidence`: the median's as well as
    the peer's, so the median's own jitter moves no peer across.

### The side a peer held

*   **Each tier continues one of the last window's.** The first continues
    its first peer's; one a peer opens continues that peer's when it came
    from a tier above, else the one after the tier it leaves.
*   **A peer from the tier being walked, or from below it, joins** unless
    the comparison finds it better; **one from a tier above opens the
    next** unless the comparison finds it not better.
*   **A later peer's place decides an earlier one's.** The tiers are runs
    of the walk: a peer from above left undecided joins when the first
    later peer not so left joins, and opens the next tier otherwise. A
    peer whose round trip fell into the tier below thus joins it, rather
    than cutting it in two.
*   **A peer the last window did not class** — every peer of a node's
    first window, a new peer, one whose probes the last window heard
    nothing from — is placed by its reading's value, as today.

### What a move takes

Over thirty probes, a peer's lower bound is its twentieth round trip and
its upper bound its twenty-eighth. A peer leaves its tier once eleven of
its last thirty probes lie past the line, about two minutes for a
neighbor probed three times a window, and joins a tier once twenty-eight
lie within it, about five minutes. The median's bounds widen both.

### Packages touched

| Package | Change |
| :-- | :-- |
| `pkg/modules/topology/impl/measured` | The walk weighs each step through `evidence.Beats` and reads the last window's tiers |
| `docs/adrs` | ADR-0040 accepted |

## Compatibility

Nothing on the wire changes. Tiers stay decision labels local to the node,
recomputed each window, never protocol state and never exchanged; the
walk also reads the last window's tiers. A peer near the line keeps its
tier until its bounds clear the line, where it changed tier with its
reading. A node's first window classes its peers as today.

## Test plan

*   **The walk.** A peer past the line by its value but not by its bounds
    keeps its tier, and one whose lower bound clears the line opens the
    next; a peer from a tier above joins only once its upper bound lies
    within; the median's bounds count; a peer the last window did not
    class is placed by its value; the first tier continues its first
    peer's, and a tier a peer opens continues that peer's or the one after;
    a peer whose round trip fell into the tier below joins it whole.
*   **The selection.** A peer's tier carries from window to window, and two
    peers trading places at the line settle in one window and stay.
*   **The labs.** The labs pass, and the benchmarks run against the commit
    before: the settled labs, the jitter sweeps across the network and on
    one link, the cuts, and the delay changes.
