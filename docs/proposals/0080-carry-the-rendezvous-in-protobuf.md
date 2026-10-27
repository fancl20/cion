# Carry the rendezvous in protobuf

This proposal moves the rendezvous request and reply to protobuf: a datagram
is one message, read by a generated parser. The hand-written format goes,
and a node of an earlier release can no longer rendezvous with this one.

[TOC]

## Summary

The acceptor and its dialers write and parse the rendezvous messages by
hand ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)):
`Marshal` and `Parse` for each, over a reader that records truncation. A
two-byte version leads each datagram, and the reply's reflexive address
trails the form every version shares. Every other message the node defines,
the link service's and the directory's among them, is protobuf, and the
binding request that hole punching needs would grow the hand-written parser
again, over input from anyone on the underlay.

## Motivation

### Goals

*   The rendezvous messages are protobuf, read by a generated parser.
*   The exchange's behavior, admission, and records stay as they are.

### Non-goals

*   No new fact: the binding request lands with hole punching.
*   No compatibility with the hand-written format: the network is
    pre-production.

## Proposal

### The wire

`proto/node/v1/rendezvous.proto` defines the two messages:

*   `RendezvousRequest`: `nonce` (16 bytes), `isd_as`, and `link_addr`, the
    claimed link address as `host:port`.
*   `RendezvousReply`: `nonce`, `link_addr`, `if_id`, `isd_as`, and
    `reflexive_addr`, empty when the reply echoes none.

A datagram is one message, with nothing before it. A fact the exchange
gains is a field, which a reader that predates it skips.

### The codec

`RendezvousRequest` and `RendezvousReply` keep their Go shape. `Marshal`
returns the message's wire form, or the error protobuf reports;
`ParseRendezvousRequest` and `ParseRendezvousReply` refuse a malformed
message, a nonce of another length, and an address that does not parse.
The hand-written reader goes.

### Packages touched

| Package                              | Change                       |
| :----------------------------------- | :--------------------------- |
| `proto/node/v1`                      | The two rendezvous messages  |
| `pkg/modules/topology/impl/measured` | The codec over the messages  |

## Compatibility

A node of an earlier release sends the hand-written format, which this
release refuses: its leading version is no valid protobuf field. The earlier
release refuses this release's datagrams as another version. The two
neither join through nor probe each other.

## Test plan

*   **The wire:** each message round-trips, a reply without a reflexive
    address included, and a field a later release adds is skipped. A
    datagram of the hand-written format, a truncated one, an empty one, one
    with a nonce of another length, and one whose address does not parse are
    refused.
*   **The exchange:** the acceptor's and the dialers' tests pass, and so do
    the labs.

## Implementation history

*   Landed as proposed: the two messages
    ([rendezvous.proto](/proto/node/v1/rendezvous.proto)) and the codec over
    them ([rendezvous.go](/pkg/modules/topology/impl/measured/rendezvous.go)).
