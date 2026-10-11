# Draw link ports from a band below the ephemeral range

This proposal hardens decision 15 of
[ADR-0017](/docs/adrs/0017-form-topology-with-measured-neighbor-utility.md),
under which each link's underlay address is part of the link's state, bound
identically by every data plane generation. It draws the measured
provider's link ports from a fixed band below the kernel's ephemeral range,
in place of the ephemeral port that
[proposal 0008](/docs/proposals/0008-measured-neighbor-selection.md)
allocates, and has the link store refuse two live entries with one local
address. No run argument or wire message changes.

[TOC]

## Summary

`AllocateLinkAddr` binds port 0 on the control host, keeps the port the
kernel picked, and closes the socket
([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)). The
entry records the address, and each generation binds it again
([dataplane.go](/internal/services/dataplane.go)). Nothing holds the port
at three moments:

*   Between the allocation and the first generation that serves the entry.
*   During each generation swap, which closes the serving sockets before
    the replacement binds them.
*   Across a restart, until the boot's first generation binds it.

At each of these moments, any bind of port 0 on the host can take the
port, because the kernel draws both from its ephemeral range. The node
itself binds port 0 on the control host all the time: its rendezvous client
and its SCION connections, which carry its control plane's QUIC clients. A
boot opens its SCION connections before its first generation binds the
recorded links, and a boot whose first generation fails to bind does not
start. A swap retries its binds for one second and then stops the data
plane loop, whose failure stops the node. Two labs failed on
`bind: address already in use`. `TestJoinByRendezvous` failed at its bare
restart. `TestStrandedTierHeals` failed at a joiner's first generation, in a
network namespace of its own, where only the node's own sockets ran.

Two allocations can also draw one port: the kernel may hand a released port
to the next bind of port 0, another allocation among them, before the first
entry's generation binds it. The link store promises that it never holds a
link set the data plane refuses ([links.go](/pkg/modules/links/links.go)),
but it checks neighbors and remote addresses only. The data plane then
refuses the second bind, and no generation builds.

## Motivation

A generation swap stays invisible to the peer only if the replacement binds
the link's address again. A port that another socket takes turns a routine
swap or restart into a stopped node. The labs' harness met the same race and
moved the addresses it pins to a band below the ephemeral range
([network.go](/internal/testnetwork/network.go)). The node's own allocation
needs the same protection.

### Goals

*   No bind of port 0 on the host, the node's own included, can take a link
    port the measured provider allocates, from the allocation through every
    swap and restart.
*   The link store never holds two live entries with one local address.
*   A revived entry serves on an address that no live entry holds.
*   The measured provider's link ports lie in one documented band, which an
    operator's firewall can allow.

### Non-goals

*   No run argument: the band is fixed, like the node's other ports.
*   No migration: entries recorded before the change keep their ports until
    they retire.
*   No runtime check of the kernel's ephemeral range. The band's constants
    document what the host must keep.
*   The file provider keeps the addresses the operator writes, and the swap
    keeps its close-then-rebind and its retry.

## Proposal

### Link ports come from a fixed band

The measured provider's new constants `LinkPortBase` (31000) and
`LinkPortSpan` (1000) name the band 31000–31999. The band joins the node's
port block of
[proposal 0030](/docs/proposals/0030-assign-the-ports-by-convention-and-stability.md)
as ports no party addresses by number: a peer learns a link's address from
the exchange that establishes it. The band lies above the node's fixed
ports, 30041 to 30044, and below Linux's default ephemeral range
(32768–60999) and the IANA dynamic range (49152–65535) that macOS and
Windows use. It is apart from the labs' pinned band (20000–24999).

No bind of port 0 lands in the band unless the host's ephemeral range
reaches into it. A Linux host whose `ip_local_port_range` does can reserve
the band through `ip_local_reserved_ports`, and the constants' comment says
so.

`AllocateLinkAddr(host, entries)` draws from the band. It starts at a
random offset and walks the band once. It skips the local addresses of the
live entries it is given and the ports whose probe bind fails with
`EADDRINUSE`, and it releases and returns the first port that binds. A band
with no free port fails the allocation, and the writer fails that
establishment, as it does on an allocation error today. The probe's release
is safe, because nothing that binds port 0 draws from the band.

Each writer allocates against the table it reads:

*   The rendezvous acceptor, the in-band link service, and the selection's
    `recordEntry` read the table's entries before they allocate.
*   `Seed` allocates against the table as its earlier seeds left it, so two
    seeds never draw one port.
*   A first start's bootstrap allocates before the store opens, against no
    entries: a first start's table is empty.

### The store refuses two live entries with one local address

`links.Check` gains a third rule. A write that would leave two live entries
with one local address is refused with `ErrDuplicateLocal`, inside the
write, by both stores. The rule reads live entries, not serving ones: a
seeded entry holds its local address before its remote arrives, so a race
is caught at the second insert rather than at the seed's retarget.

The rules report in order: neighbor, remote, local. A writer that lost a
neighbor race reuses the winner's entry, and a claim on a held remote is
refused whatever its local address. The rendezvous acceptor, the link
service, and the selection retry once on `ErrDuplicateLocal`, as they do on
`ErrDuplicateNeighbor`. The retry draws again, and the winner's port is now
held.

The file provider's reconciliation retires the entries the file no longer
names before it records the named ones
([provider.go](/pkg/modules/topology/impl/file/provider.go)). An edit that
moves an address from a removed link to a new one then lands in one pass;
today an edit that moves a remote address this way fails on the remote
rule. A link set that names one local address twice is refused at the
write, where the data plane refused it at the bind. An edit that swaps two
kept links' local addresses is refused, as one that swaps their remote
addresses is today.

### A revival keeps its address unless a live entry holds it

A stranded node's revival re-dials with the retired entry's local address
([provider.go](/pkg/modules/topology/impl/measured/provider.go)). Retired
entries hold no port, so a later allocation can draw a retired entry's
port. The revival keeps its address when no live entry holds it. Otherwise
it allocates a fresh one before the re-dial, so the re-dial claims the
address the entry will serve. A revival whose update loses the port to
another writer waits for the next pass, as one answered for a live neighbor
does.

### Steps

1.  The store's rule, the writers' retry, the file provider's order, and
    the revival's fresh address, still on the kernel's ephemeral ports.
2.  The band, the allocation against the table, the lab's band check, and
    the Implementation history.

## Test plan

*   **Unit, the store's rule:** the contract suite runs it on both stores. A
    second live entry with one local address is refused with
    `ErrDuplicateLocal` and changes nothing, on insert and on update. A
    retired entry's address is free for a new entry, and an entry's update
    of its other fields keeps its address. A write that also breaks the
    neighbor rule reports the neighbor's error, and one that also breaks the
    remote rule reports the remote's.
*   **Unit, the writers:** the rendezvous acceptor, the link service, and
    the selection each lose the race for the port they drew: a store
    records another entry on that address just before the writer's insert.
    Each writer lands its entry on another address, and the winner's entry
    stands.
*   **Unit, the revival:** a retired entry whose address a live entry now
    holds revives on a fresh address, which its re-dial claims. One whose
    address is free revives on it.
*   **Unit, the file provider:** an edit that moves an address from a
    removed link to a new one lands in one reconciliation. An edit that
    names one local address twice is refused and leaves the stored set as
    it was.
*   **Unit, the band:** the episodes run on the package's own loopback
    host. Every allocation lands in the band. On Linux, the band lies below
    the range that `/proc/sys/net/ipv4/ip_local_port_range` reads; the check
    is skipped where the file is unreadable. With the table holding every
    port of the band but two and a socket holding one of the two, the
    allocation takes the other; with both held, it fails. Two seeds over a
    band with two free ports take both.
*   **Integration:** in the restart lab, `TestJoinByRendezvous`, every
    entry's local port lies in the band before and after the bare restart.

## Implementation history

*   Landed in two commits, one per step: 3282206, the store's rule in
    `links.Check` ([links.go](/pkg/modules/links/links.go)), the writers'
    retry, the file provider's order, and the revival's fresh address,
    whose check is `localHeld`
    ([provider.go](/pkg/modules/topology/impl/measured/provider.go)); and
    the commit that draws link ports from the band and appends this record.
    The band's constants and `AllocateLinkAddr` moved to
    [linkports.go](/pkg/modules/topology/impl/measured/linkports.go).
*   The race episodes run over `squattedStore`, which records a seeded
    entry on the drawn address before the writer's insert. The band's
    episodes bind on 127.0.0.123, and the kernel's range is checked by a
    test of its own; the seeds' episode repeats over ten draws, whose
    offsets are random. The restart lab checks every node's entries
    through `linkPortsInBand`
    ([join_test.go](/internal/testnetwork/join_test.go)).
