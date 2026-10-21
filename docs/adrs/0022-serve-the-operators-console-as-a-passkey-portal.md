# Serve the Operator's Console as a Passkey Portal

*   Status: accepted
*   Date: 2026-10-21

[TOC]

## Context and problem statement

[ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
made admission a plugin's decision, and
[ADR-0011](/docs/adrs/0011-serve-hosts-with-a-tailscale-coordination-service.md)
put the plugin's instruments beside it: the operator's channel is the
console, the auth keys the plugin mints are the plugin's own, and the
network's mechanism holds no credential and serves no administrative
surface. One console exists, the Telegram plugin's chat: a prompt per new
identity with an approve and a deny button, and two slash commands that
mint and retire auth keys.

The chat answers the question it is asked and no other. It holds the asks
it sent, not the network's records: which nodes hold a chain, which hosts
hold an address, which node's slice an address came from — the issued
chains and the registry answer those, and no console reads them. An
operator who wants to know who is in reads the state directory's
databases.

And the records only grow. ADR-0011 left host admission durable until "a
later milestone adds removal": every admitted host holds one of its owning
node's 253 addresses for good. A client reinstalled, a phone replaced, a
laptop retired — each registers again under a fresh key or never returns,
and the address it held stays issued. A slice fills with addresses nothing
will use again, and nothing releases them.

Nodes need no such release. An AS certificate lives three days and renews
only while its node runs; a node that goes offline stops renewing and its
chain expires — the security model's bounds rather than revocation. What
the operator lacks there is the view, not a removal.

The chat's own costs stand as ADR-0010 recorded them: an external service
in the trust path, admission failing closed while the service is
unreachable, the bot's token in the process list. A deployment that
declines Telegram has the CIDR posture, which has no console at all.

This ADR decides what the operator's console is, how it authenticates its
one operator, what it may read and change in the network's records, and
what it shows of a joiner beyond the facts the seam verifies.

## Decision drivers

*   **Instruments in the Plugin:** ADR-0011's placement holds — the
    decisions and the auth keys live with the policy, and the coordination
    service gains no administrative logic.
*   **Surfaces Through the Seam:** what the node serves for its operator
    arrives the way every application's surface does
    ([ADR-0014](/docs/adrs/0014-select-resident-applications-by-name.md)),
    and adding it touches the assembly not at all.
*   **Records Stay Their Owners':** the issued chains are the trust
    service's and the registry is the coordination application's; a
    console reads them and asks the owner to change one, never writes
    beneath it.
*   **No External Service in the Trust Path:** admission is available
    whenever the core is.
*   **Phishing-Resistant Authentication:** the console faces the internet
    on the core's domain; its credential must be neither replayable nor
    phishable, and the core must store nothing that impersonates the
    operator.
*   **Almost-Zero Config:** no account to create, no password to choose,
    no file to edit before the first login.
*   **Bounds Rather Than Revocation:** the security model's stance stands;
    nothing is built to revoke what expiry already retires.
*   **Verified Facts Only:** ADR-0010's rule — a verdict rests on what the
    exchange proves; anything else shown to a human is shown as a claim.
*   **Non-Scalable by Choice:** one operator, and a fleet a person can
    read on one page.

## Considered options

Where the console lives:

*   **The Chat, as Today:** the Telegram plugin's prompts and commands.
*   **A Command-Line Console:** subcommands on the core, speaking to the
    running daemon over a local socket.
*   **A Web Console in the Coordination Application:** headscale's shape,
    an administrative surface beside the client protocol.
*   **A Web Console as an Admission Plugin:** a third method, its surface
    served on the core's HTTPS server.
*   **A Web Console as an Application Paired with a Plugin:** a third
    method holding the asks and the auth keys, and a resident application
    serving the console that decides them.

How the operator authenticates:

*   **Passkeys:** WebAuthn credentials bound to the core's domain.
*   **A Password with a Second Factor:** a stored verifier and a one-time
    code seed.
*   **TLS Client Certificates:** a certificate the core issues and the
    browser presents.
*   **An Identity Provider:** OpenID Connect against an account the
    operator already holds.

How the first credential is enrolled:

*   **A Token the Core Prints:** minted in memory at a boot with no
    credential and shown in the log.
*   **A Token a Command Mints:** a subcommand writes it into the state
    directory for the daemon to read.
*   **First Come, First Served:** the first registration on an empty
    console wins.

How passkeys are verified:

*   **A Maintained WebAuthn Library.**
*   **A Verifier Written for the Console:** the subset passkeys need, over
    a CBOR decoder the tree already carries.

What the console may remove:

*   **Nothing:** a read-only view.
*   **Hosts:** releasing the addresses they hold.
*   **Hosts and Nodes:** nodes by forgetting their chains, so the next
    renewal asks the policy again.

## Decision outcome

Chosen options: **a web console as an application paired with a
plugin**, **passkeys**, **a token the core prints**, **a maintained
WebAuthn library**, and **hosts** as what it may remove — realized as
follows:

1.  **The portal is a method and an application.** The method is the
    third admission method. It answers every boundary as the Telegram
    plugin does — a new identity pends, the operator approves or rejects
    it, and the joiner's own retry carries the wait — and exactly one
    method loads, as ADR-0010 left it: the portal combines with neither
    the CIDR nor the Telegram posture. Its decisions live in memory, as
    ADR-0010's did: an approval stands long enough for the joiner's next
    retry and a rejection stands a day, so a stranger retrying every few
    seconds does not return to the list on every window; a restart
    forgets both. The console is a resident application paired with the
    method: it decides the method's asks and mints its keys through an
    operator surface the admission seam declares, and the two load
    together — either without the other refuses the boot.
2.  **The console mounts on the node's HTTPS server by path.** The
    founding core's HTTPS server — the one that already holds internet
    HTTPS's port for the coordination endpoint — serves the console under
    a path of its own on the core's domain, with the certificate the core
    already maintains. The server mounts every application's handlers at
    patterns of their own, the coordination endpoint's among them, where
    it mounted one application at its root. This narrows ADR-0011's
    administrative-surface clause: the policy keeps its decisions and its
    credentials, and the surface that operates them is an application
    paired with it — never the coordination service. A passkey binds to a
    domain, so the console needs a DNS name identity and refuses to load
    on an address identity.
3.  **One operator, passkeys alone.** No username and no password: the
    operator holds one or more discoverable passkeys bound to the core's
    domain, each login verified with user verification required, and the
    core stores their public keys. Sessions live in memory; a restart
    signs the operator out.
4.  **The core prints the first credential's token.** A boot with no
    passkey mints a one-time token in memory and prints a setup link in
    the log; the token is never stored, the first registration consumes
    it, and a restart prints a fresh one. Recovery from losing every
    passkey is the operator deleting the console's passkey record and
    restarting.
5.  **A maintained library verifies the ceremonies.** WebAuthn is verified
    by a widely deployed library rather than a verifier written for one
    console. This departs from the Telegram plugin's no-SDK practice on
    purpose: the Bot API is a handful of JSON calls, while WebAuthn is a
    security protocol whose edge cases — attestation formats, signature
    encodings, counters, origins — are a library's whole work.
6.  **The console reads the records and releases hosts.** It lists the
    chains the founder issued that are valid now, beside each node's
    directory entry, and the registry's hosts, beside the presence the
    coordination application observes on its map streams. Removing a host
    deletes its registry entry through the coordination application, the
    record's owner: the address returns to the allocator, and the owning
    node drops the peer at its next directory fetch. Removal is cleanup,
    not revocation — a removed client that still runs asks again at its
    next login, and the policy decides as it would for any joiner. This is
    the removal ADR-0011 deferred, for hosts. Nodes are not removed: an
    offline node's chain expires within the certificate's lifetime, and
    the list follows it. A core that serves no hosts still lists and
    decides its nodes.
7.  **The method keeps the auth keys.** It mints, lists, and retires its
    own keys — one-use or reusable, each with an expiry — and keeps
    digests rather than keys, each key shown once at its minting; the
    console asks it to. ADR-0011's placement is unchanged: the keys are
    the policy's, and the coordination service holds none.
8.  **What a joiner says of itself is shown, never decided on.** A
    registration carries the client's own hostname and operating system.
    The seam hands them to the plugin beside the verified facts, marked
    as the joiner's claim; the registry records them with the entry on
    the core alone — the directory does not carry them to other nodes —
    and the console labels them claimed. No plugin decides on them. This
    narrows ADR-0011's "nothing else considered" to nothing else decided
    on.

### Positive consequences

*   The operator reads membership and the open asks on one page: who
    holds a chain, who holds an address, who is asking, each with its
    facts.
*   Admission leaves the external service: the console is available
    whenever the core is, and no token rides the process list.
*   Slices stop filling with dead clients; an address is released as
    easily as it was issued.
*   The console's credential cannot be phished or replayed, and nothing
    the core stores for it impersonates the operator.
*   The first login needs no command and no file: a link in the log of the
    process the operator is starting anyway.
*   The console touches the assembly not at all: the method loads where
    every method loads, the console where every application loads, and
    the HTTPS server mounts applications alone.

### Negative consequences

*   The core serves an administrative surface to the internet: whoever
    holds a registered passkey admits, releases, and mints at will — the
    total authority ADR-0011 recorded for the chat's channel, now one web
    origin.
*   Until the first passkey is registered, the log is the credential:
    whoever reads it first claims the console.
*   The console needs a DNS name identity; a deployment whose identity is
    an address keeps the CIDR or Telegram posture.
*   The portal is two halves that load together: a selection naming one
    without the other refuses the boot, and the admission seam declares an
    operator surface one method implements.
*   The library and the modules it requires enter the vendored tree — JWT
    and TPM attestation parsing and a serialization library among them —
    one more upstream to track.
*   Decisions and sessions are in memory: a restart forgets pending,
    approved, and rejected asks and signs the operator out.
*   A released address is issued again: a later host can inherit an
    earlier one's address.
*   Nodes cannot be removed: a node that must leave while it runs waits
    out its chain, and an offline node's directory entry stays as it does
    today.
*   The registry keeps data no verdict uses: the joiner's own description,
    kept for a human.

## Pros and cons of the options

### The chat, as today

*   Good, because it is built, and the operator's phone is always at hand.
*   Bad, because it shows the asks it sent and nothing of the records.
*   Bad, because it places an external service and a bearer token in the
    trust path.

### A command-line console

*   Good, because it needs no internet-facing surface: the operator's
    shell on the core is the authentication.
*   Bad, because it is a second front door into the daemon — a local
    socket, a protocol, a client — for a person who must first reach the
    core's shell.
*   Bad, because a fleet with its presence is a table a browser renders
    better than a terminal.

### A web console in the coordination application

*   Good, because it is headscale's proven shape.
*   Bad, because it re-grows in the service what ADR-0011 stripped from
    it — a credential store and an administrative surface.
*   Bad, because node enrollment, which the coordination application never
    sees, stays outside the console.

### A web console as an admission plugin

*   Good, because the plugin already answers every boundary: one console
    sees node enrollment, host registration, and the founder's vote alike.
*   Good, because ADR-0011's placement holds — the policy keeps its
    instruments, its surface, and its credentials.
*   Bad, because a plugin owns a web surface the node serves, and the
    node's HTTPS server mounts a policy beside an application.
*   Bad, because the plugin reads and changes records the applications own
    through a view the assembly builds and attaches for it alone.

### A web console as an application paired with a plugin

*   Good, because the plugin still answers every boundary: one console
    sees node enrollment, host registration, and the founder's vote alike.
*   Good, because the policy keeps its decisions and its keys, while the
    console is an application like any other — its mount, its borrows,
    and its state arriving through the seam every application uses.
*   Bad, because two halves must load together, and the admission seam
    declares an operator surface for one method.

### Passkeys

*   Good, because the credential is bound to the domain — a phishing page
    cannot use it — and the core keeps only public keys.
*   Good, because a platform authenticator makes the login one gesture.
*   Bad, because the relying party must be a domain name, and a browser
    and an authenticator stand between the operator and every login.

### A password with a second factor

*   Good, because every browser and every person already knows it.
*   Bad, because the core stores a verifier and a seed that impersonate
    the operator if read, and both factors are phishable.

### TLS client certificates

*   Good, because the TLS stack the core already runs verifies them.
*   Bad, because issuing, installing, and renewing a browser certificate
    is the ceremony the almost-zero-config driver rules out.

### An identity provider

*   Good, because an account the operator already holds vouches, with its
    own second factors.
*   Bad, because it puts an external provider back in the console's path
    and a client registration in the core's configuration — the side door
    ADR-0011 declined for admission.

### A token the core prints

*   Good, because the operator is starting the process and reading its log
    already: no command, no file, no state.
*   Good, because a missed token costs a restart, not a recovery
    procedure.
*   Bad, because the log is a credential until the first registration.

### A token a command mints

*   Good, because the token never enters a log.
*   Bad, because it adds a subcommand, and a file the daemon must read,
    for one moment in a deployment's life — and the file is a credential
    at rest until it is used.

### First come, first served

*   Good, because it needs nothing at all.
*   Bad, because the console faces the internet from its first second, and
    the first registration need not be the operator's.

### A maintained WebAuthn library

*   Good, because the ceremonies' edge cases are verified by code many
    deployments exercise.
*   Bad, because it and the modules it requires enter the vendored tree.

### A verifier written for the console

*   Good, because it adds no module the tree does not already carry.
*   Bad, because a security protocol's verification becomes code one
    deployment exercises, and every authenticator's quirk is found in
    production.

### Nothing

*   Good, because a read-only console changes no record and needs no owner
    to act.
*   Bad, because it shows a slice filling and offers no release.

### Hosts

*   Good, because it is the release the records lack: an address returns
    to the allocator.
*   Good, because the owners already serve the consequences — the map
    stream closes on a vanished registration, and a node's fetch drops a
    departed peer.
*   Bad, because a released address is issued again.

### Hosts and nodes

*   Good, because an operator could push a running node out before its
    chain expires.
*   Bad, because it builds removal for nodes that expiry already retires,
    and a forget racing a renewal must be serialized with issuance to
    stick.
