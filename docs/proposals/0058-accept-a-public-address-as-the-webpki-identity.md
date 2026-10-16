# Accept a public address as the WebPKI identity

This proposal widens the identity
[ADR-0003](/docs/adrs/0003-bootstrap-trust-with-self-issuing-core.md) stands
behind the core endpoint: beside a DNS domain, a public IP address. Let's
Encrypt — the CA the ACME machinery already defaults to — has certified
addresses since its January 2026 general availability, under its `shortlived`
profile alone, and the two challenges that validation allows are the two the
node already answers. The address flows everywhere the domain flows — the
founder's certificate, the endpoint's demux, the joiner's client, the
founder's published host, the tailnet's name — under one grammar the run
arguments carry. No identifier changes name; no wire message, store format,
or SCION PKI fact changes.

[TOC]

## Summary

The identity is one string, `--trust.domain`, with five readers:

*   [tls.go](/pkg/core/webpki/tls.go): `TLSCertConfig.Domain` —
    `PrepareTLSCert` stands certmagic on it and `Manage` maintains it.
*   [mtls.go](/pkg/libs/scionrpc/mtls.go): `EndpointTLSConfig.Domain` — the
    demux that hands a ClientHello the WebPKI or the native configuration.
*   [remote.go](/pkg/core/webpki/remote.go): `CoreClientConfig.Domain` — the
    joiner's server name and the URL its client carries.
*   [provider.go](/pkg/modules/topology/impl/measured/provider.go): the
    founder's `Domain`, which `domainHost` resolves to the published host.
*   [app.go](/pkg/apps/coordination/app.go): `Config.Domain` — the tailnet's
    own name and the relay `HostName` default.

An address meets three frictions among the five. The CA's: the default
profile rejects an `ip` identifier, so the issuer must select `shortlived`.
The handshake's: Go's client omits the SNI extension for an address-shaped
name — RFC 6066 admits DNS names alone — so the bootstrap client's
ClientHello arrives nameless and the SNI demux would hand it the native
channel. The URL's: an IPv6 literal needs brackets.

The library work beneath is the pinned versions' own: certmagic v0.25.4
routes a literal subject into the CSR's `IPAddresses`, keys the TLS-ALPN
challenge by the address, and carries the profile seam on its issuer; acmez
v3.1.7 emits the `ip` identifier RFC 8738 defines. What lands is the profile
selection, the demux's nameless arm, the URL's brackets, the literal's
published host, and the refusals that keep a misgiven address from reaching
the CA at all: an address no public CA validates, and an address that is
not the control host's own.

## Motivation

The domain is the one artifact a founder must own before its first boot: a
name at a registrar and a mapping at a provider, renewed on the registrar's
clock. An operator holding a public address and no name stands no core
today — the static files assume a certificate from somewhere, and the ACME
arm takes a domain alone.

An address serves the identity's role exactly because the design never
resolved the domain. ADR-0003: "The domain is a TLS identity, not a locator
— a fresh node never resolves it; the node's locator is the SCION link."
The X.509 SAN grammar carries addresses beside names, and Go's verifier
matches them against `ServerName`; only the CA's policy and the
handshake's SNI rule made the domain the sole grammar, and the first
changed in January 2026.

The CA's facts bound the design, so they are the design's:

*   Addresses certify under the `shortlived` profile alone: 160 hours. The
    maintenance loop that already retries issuance renews at a third of the
    lifetime remaining — about every four days — far inside the fifty
    certificates the CA allows an address a week.
*   Validation is http-01 or tls-alpn-01, the two challenges the node
    answers on ports 80 and 443 already; no third port opens.
*   Global unicast addresses alone: private, shared, and special-purpose
    ranges are the CA's refusals, and the node's with them.
*   The chain roots in the CA's standing hierarchy — the joiner's
    system-root verification changes nothing.

### Goals

*   `--trust.domain` and every `Domain` field accept a public address
    beside a DNS name; no identifier changes name.
*   `PrepareTLSCert` selects the issuer's profile by the grammar — the
    default for a name, `shortlived` for an address — and refuses an
    address no public CA validates, naming the static files' fallback.
*   The endpoint's demux answers a nameless ClientHello with the WebPKI
    configuration when the identity is an address; a domain identity keeps
    its rule.
*   The joiner's client names the bare literal in `ServerName` and brackets
    it in the URL when it is IPv6.
*   The founder's published host is the literal; the tailnet's name and the
    relay's `HostName` carry the identity's grammar unchanged.
*   On the founding core, the config resolution refuses an address identity
    that is not the control host's own.

### Non-goals

*   No new run argument and no rename: `--trust.domain` keeps its name; its
    help widens to say the address.
*   No NAT'd address identity: the HTTPS server binds the control host, and
    the address the CA validates must be the address the server holds — a
    founder whose public face differs from its control host keeps a domain
    or the static files.
*   No certificate carries both grammars: one identity per core, as today.
*   No live-CA episode: the first issuance against the real Let's Encrypt
    stands untested, as proposal 0023 left it.
*   No change to the SCION PKI, the TRC, or the enrollment policy — the
    WebPKI stays the bootstrap-only anchor
    [security.md](/docs/design/security.md) draws.

## Proposal

### The identity's grammar

`TLSCertConfig.Domain`'s document widens: the DNS domain or the public
address the certificate answers for — still a TLS identity, never resolved.
`PrepareTLSCert` parses the value where it enters. A name stands as it
does. An address selects the `shortlived` profile on the issuer — the one
the CA certifies `ip` identifiers under — and refuses the ranges no public
CA validates: private, loopback, link-local, shared, unspecified. The
refusal fails the boot rather than the maintenance's retries, for an
address that cannot certify would retry forever under `supervise.Degrade`,
and the message names the static files the offline deployment uses.

### The endpoint's nameless handshake

Go's client omits the SNI extension when `ServerName` is an address
literal, so against an address identity the bootstrap client's ClientHello
carries no name, and the demux's rule — the offered name equals the
identity — would hand it the native channel. The arm: when the identity is
an address, the nameless ClientHello takes the WebPKI configuration. No
ambiguity arises, for the native channel's clients always name their peer
— the ISD-AS is the connection's name, set on every dial — so a nameless
ClientHello is a bootstrap client's alone. A domain identity keeps the
rule exactly as it is.

### The joiner's client

`CoreClientConfig.Domain` carries the literal bare in `ServerName` — the
verifier matches it against the certificate's IP addresses, and a bracketed
name would parse as neither an address nor a name — and brackets it in the
base URL when it is IPv6, RFC 3986's authority grammar. The transport's
dial ignores the URL's address; the locator routes, so the brackets are
the URL's alone.

The grammar decides by parsing, the same parse everywhere it is read: a
value that parses as an address is an address to the demux, the client,
and the founder's published host alike, and a value that does not behaves
as the domain does today.

### The founder's published host

`domainHost` answers the literal directly: parsed once at construction, no
lookup and no memoization for a value that cannot change. The founder's
entry publishes the identity's own address, and the family check falls
away — the resolution's refusal already pins the identity to the control
host's own address. Joiners are untouched: they learn their published
hosts from the rendezvous exchange, as they do.

### The assembly and the run arguments

The founding core's resolution refuses an address identity that is not the
control host's own address: the HTTPS server binds the control host at
443, and the address the CA validates — port 443 of the identity itself —
must be the port the server holds. One address, one fact. A joiner's
`--trust.domain` names the network's core identity, whatever its grammar;
no control host of its own is asked.

The flag's help widens — the founding core's own domain or public address
without a neighbor, else the network's core identity — and the
coordination application's `Config.Domain` carries the grammar unchanged:
one name the certificate answers for, the tailnet's own and the relay's
`HostName` alike. A host dials the relay by the name; an address answers
the resolver and the certificate verification both.

### The tests

*   [webpkitest](/pkg/core/webpki/webpkitest/webpkitest.go) mints the
    address-shaped certificate beside the domain's: SANs carrying the
    loopback address alone, the common name omitted — the shape the
    `shortlived` profile issues.
*   The demux: a nameless ClientHello against an address identity takes
    the WebPKI configuration and completes its handshake; against a domain
    identity it still takes the native channel.
*   The challenge: the TLS-ALPN episode seeds an `ip` identifier the way
    the distributed solve stores it and answers on the node's HTTPS
    server — the challenge store certmagic keys by the reversed literal.
*   The client: an IPv6 identity builds its bracketed URL and verifies the
    bare literal; an IPv4 one answers the same episodes without brackets.
*   The refusals: a private address identity at `PrepareTLSCert`; a
    founder's address that is not the control host's own, at the
    resolution — each with its message.

### The documents

The architecture overview's joiner sentence — two facts, the neighbor's
address and the core's domain — says the core's identity, as does
security.md's first-fetch anchor. No ADR is edited: ADR-0003's identity
concept widens by its own letter, and the narrowing is recorded here
alone.

The change lands in one commit.

## Test plan

*   **The identity:** the profile selection and the range refusal pin
    `PrepareTLSCert`'s address arm; the static-file and domain arms pass
    unchanged.
*   **The endpoint:** the nameless-ClientHello episodes on both grammars;
    the `ip`-identifier challenge answered on the node's HTTPS server.
*   **The client:** the bracketed URL and the bare-literal verification,
    both families.
*   **The assembly:** the address refusal at the resolution with its
    message; the integration suites with an address identity standing
    where the lab's domain stands — the joiner enrolls, fetches the TRC,
    and the coordination lab's client engine joins through the login and
    exchanges traffic through the mesh, the tailnet named by the address
    and the relay dialed by it. This episode decides the vendored client
    engine's tolerance of an address-shaped tailnet name; a refusal there
    scopes the coordination surface back to a domain in a follow-up, not
    silently.
*   **Renewal shape:** the maintenance loop's cadence is the standing
    cache's own; no episode stands up the live CA, as 0023 recorded.

## Implementation history

None yet.
