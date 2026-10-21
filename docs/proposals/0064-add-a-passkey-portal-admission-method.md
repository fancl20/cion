# Add a passkey portal admission method

This proposal implements
[ADR-0022](/docs/adrs/0022-serve-the-operators-console-as-a-passkey-portal.md):
a third `--trust.enroll-auth` method, `portal`, paired with a resident
application of the same name — the operator's console, which the founding
core serves at `https://<trust.domain>/admin/`. The method holds the asks
of every admission boundary and the auth keys; the console decides the
asks, mints and revokes the keys, lists the nodes holding a chain and the
hosts holding an address, and releases hosts, behind passkeys the single
operator registers with a token the core prints at a boot with no passkey.

[TOC]

## Summary

The admission seam is one call
([admission.go](/pkg/modules/enrollauth/admission.go)): the trust service
asks it at first issuance, the coordination application at registration,
and the TRC decision before the founder's sensitive vote.
[enrollauth.go](/internal/services/enrollauth.go) builds the one method
`--trust.enroll-auth` names, `method=spec` parsed once at boot, and hands
the assembly the authorizer beside the method's own loops. The Telegram
method ([telegram.go](/pkg/modules/enrollauth/impl/telegram/telegram.go))
is the console that exists: asks held in memory on a window, unspent auth
keys persisted under `<state>/enrollauth/`.

The portal keeps Telegram's shape for the asks and the auth keys and
splits the console out as an application:

*   the method, `pkg/modules/enrollauth/impl/portal`, answers the
    boundaries, holds the asks and the auth keys, and implements an
    operator surface the module's root declares;
*   the application, `pkg/apps/portal`, serves the page and its JSON API,
    holds the passkeys and the sessions, and reads the records through an
    interface its table entry adapts — the founder's issued chains, the
    WireGuard directory, the coordination registry, and the presence the
    coordination application observes;
*   one write into a record: releasing a host, which the coordination
    application performs on its registry under its own admission lock.

Two seams of the applications' table generalize for it: the HTTPS surface
becomes path-scoped — each application mounts its handlers at patterns of
its own through the environment, where one application mounted a handler
at the server's root ([https.go](/internal/services/https.go)) — and an
entry pairs with the admission method it decides for.

Beside them, the seam's facts gain the joiner's own description — a
registration's hostname and operating system — and the registry records
it with the host entry, outside the directory's wire form.

## Motivation

ADR-0022 decides the console and its boundaries; this plan grounds them in
the packages they touch. The pieces it builds on are in place: the HTTPS
server already holds the core's port and identity for the coordination
endpoint, the coordination application already closes a map stream whose
registration vanished
([netmap.go](/pkg/apps/coordination/netmap.go)), and every node's
directory sync already removes a departed host peer
([app.go](/pkg/apps/wireguard/app.go)). What is missing is the console,
the release, and the view — and a way for a second application to serve
on the HTTPS server beside the coordination endpoint.

### Goals

*   `--trust.enroll-auth=portal` loads the method on the founding core
    beside the portal application; the application refuses an address
    identity at boot.
*   The method answers enrollment, registration, and voting: an ask
    pends, an approval stands ten minutes, a rejection twenty-four hours,
    all in memory; a registration presenting an active auth key is
    admitted with the key's note.
*   The operator signs in with a passkey verified by
    `github.com/go-webauthn/webauthn`; the first passkey is registered with
    a token minted in memory and logged at a boot with no passkey.
*   The page serves the Nodes, Hosts, Auth keys, and Settings views, and a
    JSON API carries every action.
*   Removing a host deletes its registry entry and frees its address; its
    map stream closes and its owning node drops the peer.
*   A registration's claimed hostname and operating system reach the
    plugin and the registry, labeled, and decide nothing.
*   The applications mount their HTTPS handlers by path, and the node's
    assembly holds no code of the console's.

### Non-goals

*   No node removal (ADR-0022, decision 6): the trust service, the trust
    database, and the directory's publish path are untouched.
*   No change to the CIDR and Telegram methods; the Telegram prompt does
    not show the joiner's label.
*   No combination of methods: `portal` loads alone, as every method does.
*   No persisted presence and no sweep of offline nodes' directory
    entries.
*   No ephemeral or tagged auth keys, no ACLs, and no interactive login
    URL in the registration response.

## Proposal

### The method's selection

`loadEnrollAuth` cuts the spec at its first `=` and switches on the
method, the `=` itself optional: `portal` takes no spec, so the bare
`portal` and `portal=` both select it, and a non-empty spec refuses at
boot. It returns the method beside its loop, and `resolve` hands the
selected method's name — the spec up to its first `=` — to `apps.Select`,
which pairs the application with it.

The founder check in [run.go](/cmd/cion/run.go) and the flag's help in
[run_core.go](/cmd/cion/run_core.go) name the method beside `cidrs` and
`telegram`: `portal` serves a passkey console at
`https://<domain>/admin/`.

### The pairing

`apps.Entry` gains one field, and `Select` takes the selected method:

```go
// Admission names the admission method the entry pairs with: the entry
// loads exactly when --trust.enroll-auth selects the method — the
// inference regime loads it beside the method and skips it without, and
// a list refuses either without the other. "" when the entry loads
// under any method.
Admission string
```

The portal entry is core-only, pairs with `portal`, and requires no other
application: a core that serves no hosts runs the console for its nodes.
A list naming `portal` without the method refuses — "--applications names
portal, which pairs with --trust.enroll-auth=portal" — and the method
with a list leaving `portal` out refuses — "--trust.enroll-auth=portal
pairs with the portal application, which --applications leaves out". The
entry sits last in the table, after the applications it borrows.

### The HTTPS seam

`apps.Application` drops `HTTPSHandler`, and the environment carries the
mount the control endpoint's already has:

```go
// MountHTTPS mounts one of the application's handlers on the founding
// core's HTTPS server, beside the ACME challenge, at a pattern no other
// application mounts — a pattern mounted twice refuses the boot.
MountHTTPS func(pattern string, handler http.Handler)
```

The node records the mounts while the applications construct, and
`assembleHTTPS` builds one mux from them, refusing a pattern mounted
twice before the port binds; it binds when anything mounted or the
identity is ACME-managed, as before. The coordination application's
configuration gains `MountHTTPS`, and `New` mounts `/ts2021`, `/derp`,
and `/key` through it; the WireGuard, SOCKS, and voting applications drop
their nil handlers.

### The seam's label

`enrollauth.AdmissionFacts` gains one field, and its comment says that
the field stands apart from the verified facts:

```go
// Label is the joiner's own description of itself — a registration's
// claimed hostname and operating system, empty at the other boundaries —
// shown to a human beside the facts and decided on by no implementation.
Label string
```

The coordination application fills it from the registration's
`Hostinfo`: the hostname and the operating system, each capped at 64
bytes.

### The operator surface

The module's root declares, in `operator.go`, what a console decides
through:

```go
// Operator is the surface an operator's console decides through: the asks
// a method holds pending, the decisions on them, and the auth keys the
// method mints and retires.
type Operator interface {
	Asks(boundaries ...Boundary) []Ask
	Decide(id string, approve bool) bool
	MintKey(req KeyRequest) (string, AuthKey, error)
	Keys() []AuthKey
	RevokeKey(id string) (bool, error)
}
```

`Ask` carries an ask's ID, its latest facts — boundary, claim, keys,
label, source — whether it carried a credential matching nothing, its
first and last sighting and attempts, and the standing verdict with the
moment it lapses. `KeyRequest` carries a key's description, its reusable
flag, and its lifetime in days, between `MinKeyDays` (1) and `MaxKeyDays`
(90); `AuthKey` carries a key's listing — never the key — with its
`KeyState`: active, spent, revoked, or expired. The console reaches the
surface by asserting the environment's authorizer to it; the pairing
guarantees the assertion.

### The method package

`pkg/modules/enrollauth/impl/portal`:

*   `portal.go` — `Config`, which names the state directory, `New`, and
    `Run`, which sweeps lapsed asks and expired keys each minute in the
    role's `enrollment authorizer` slot.
*   `asks.go` — `Authorize`, the ask table and its windows, `Asks`, and
    `Decide`.
*   `authkeys.go` — minting, spending, listing, revoking, and persisting.

The constants: an approval stands 10 minutes, a rejection 24 hours; the
ask table holds 256 asks.

### The asks

`Authorize` answers in order:

1.  A registration whose credential matches an active auth key — the
    SHA-256 digests compared in constant time — is allowed with the note
    `portal auth key <id>`; a one-use key is spent. A credential matching
    nothing falls through: a stale key fails toward the human, as
    Telegram's does.
2.  Facts presenting no keys are denied — the contract suite's
    undecidable facts.
3.  A standing decision inside its window answers its verdict; an
    approval carries the note `portal operator`.
4.  Otherwise the ask is recorded or refreshed — boundary, claim, keys,
    label, source, whether a credential was presented, first and last
    seen, attempts — and pends. Past 256 asks, the one seen least recently
    leaves.

An ask's identity is Telegram's: the boundary, the claim, and a digest of
the registration's machine key, the enrollment's subject key, or the
vote's added keys. The operator surface names an ask by that identity, hex
encoded. Approving a rejected ask replaces the rejection.

### Auth keys

A key reads `cion-auth-<id>-<secret>`: an 8-character hex ID the console
lists and a 32-character hex secret. `<state>/enrollauth/portal-auth-keys.json`
holds, per key, the ID, the SHA-256 digest of the whole key, the
description, the reusable flag, the creation and the expiry, the use
count, and whether it is spent or revoked, written whole. The mint
answers the key, the one time it leaves the core; a key leaves the file
at its expiry.

### The console application

`pkg/apps/portal` holds its files side by side:

*   `app.go` — `Config`, `New`, `SetupLink`, `Run`, and `Close`.
*   `passkeys.go` — the relying party, the credential record, the setup
    token, ceremonies, and sessions.
*   `api.go` — the HTTP surface.
*   `records.go` — the interface the console reads the records through.
*   `index.html`, `portal.js`, `portal.css` — the page, embedded with
    `//go:embed`.

```go
// Config configures the application.
type Config struct {
	// Domain is the relying party: the core's WebPKI identity, a DNS name.
	Domain string
	// Origin is the console's origin: "https://" and the domain, with the
	// HTTPS server's port when it is not 443.
	Origin string
	// StateDir persists the application's passkeys.
	StateDir string
	// Operator is the admission method the console decides for.
	Operator enrollauth.Operator
	// Records is the network's records the console lists, and the release
	// it asks.
	Records Records
	// MountHTTPS mounts the console's surface on the node's HTTPS server.
	MountHTTPS func(pattern string, handler http.Handler)
}
```

`New` refuses a domain that parses as an address — a passkey binds to a
domain — loads the passkey record, mints the setup token when the record
holds no credential — 32 bytes from `crypto/rand`, hex encoded, held in
memory alone — and mounts its surface at `/admin/`. `Run` logs the setup
link once — `https://<domain>/admin/setup#<token>`, the token in the
fragment so no request line carries it — then sweeps expired ceremonies
and sessions each minute until the context ends.

A ceremony lives 5 minutes and a session 12 hours.

### Passkeys and sessions

*   **The relying party:** `webauthn.New` with the domain as `RPID`, the
    origin as the one entry of `RPOrigins`, and `CION` as the display name.
*   **The operator:** one `webauthn.User` whose handle is 64 random bytes,
    minted with the first credential and persisted beside the credentials.
*   **Registration:** `BeginRegistration` with one
    `WithAuthenticatorSelection` requiring a resident key and user
    verification — one option, for it replaces whatever selection an
    option before it set — beside
    `WithConveyancePreference(protocol.PreferNoAttestation)` and
    `WithExclusions` naming the stored credentials; `FinishRegistration`
    verifies the response. The first registration presents the setup
    token, compared in constant time and consumed on success; every later
    one requires a session.
*   **Login:** `BeginDiscoverableLogin` with
    `WithUserVerification(protocol.VerificationRequired)`, then
    `FinishPasskeyLogin`, whose handler answers the operator for the
    stored handle and refuses every other. A credential the library flags
    with `CloneWarning` is refused; the stored credential's counter and
    last use update.
*   **Ceremonies:** the library's `SessionData` waits in memory under a
    random ceremony ID that the begin response sets as the
    `__Host-cion-ceremony` cookie, for 5 minutes and one use.
*   **Sessions:** 32 random bytes in the `__Host-cion-session` cookie —
    `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` — held in memory for
    12 hours; signing out ends one.
*   **The record:** `<state>/portal/passkeys.json` holds the user handle
    and each credential in the library's JSON form beside its name, its
    creation, and its last use, written whole through `statefile.Write`.
    Deleting the file is the recovery ADR-0022 names: the next boot finds
    no credential and logs a setup link.

### The HTTP surface

The console's mux answers beneath `/admin/`. Every response carries
`Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. The
API sits behind `http.CrossOriginProtection`, reads JSON bodies capped at
64 KiB, and answers 401 without a session outside setup and login; setup
and login admit one request per second per source address through
`ratelimit.Keyed`. A minting's lifetime is checked against the contract's
bounds before the method is asked.

| Route | Requires | Purpose |
|---|---|---|
| `GET /admin/{,nodes,hosts,keys,settings,setup}` | — | the page |
| `GET /admin/portal.js`, `GET /admin/portal.css` | — | the page's assets |
| `GET /admin/api/session` | — | signed in, and whether setup is open |
| `POST /admin/api/setup/{begin,finish}` | the setup token | the first passkey |
| `POST /admin/api/login/{begin,finish}` | — | sign in |
| `POST /admin/api/logout` | a session | sign out |
| `GET /admin/api/nodes` | a session | nodes, beside the node and vote asks |
| `GET /admin/api/hosts` | a session | hosts, beside the registration asks |
| `POST /admin/api/asks/{id}/{approve,reject}` | a session | decide an ask |
| `DELETE /admin/api/hosts/{key}` | a session | release a host |
| `GET /admin/api/keys`, `POST /admin/api/keys` | a session | list, mint |
| `DELETE /admin/api/keys/{id}` | a session | revoke |
| `GET /admin/api/passkeys`, `POST /admin/api/passkeys/{begin,finish}` | a session | list, add |
| `DELETE /admin/api/passkeys/{id}` | a session | delete; the last refuses |

The page is plain JavaScript with no build step. It polls the list
endpoints every five seconds while visible and renders every
joiner-supplied string as text:

*   **Nodes:** the node and vote asks with Approve and Reject, then the
    nodes — ISD-AS and role, key fingerprint, overlay, host endpoint,
    issued addresses out of 253, and the certificate's expiry, marked as
    not renewing below 23 hours, an hour past the renewal threshold — then
    the rejected asks with Approve.
*   **Hosts:** the registration asks, then the hosts — address beside the
    claimed hostname and operating system, node and machine keys, owning
    node, the approving note, and presence — each with Remove.
*   **Auth keys:** a dialog minting a key with its description, reusable
    flag, and expiry, the key shown once; the list with Revoke.
*   **Settings:** the passkeys, with Add and Delete, and sign-out.

### The records

`records.go` declares what the console reads and the one write it makes:

```go
// Records is the network's records as the console reads them, and the one
// write the console makes: releasing a host's address.
type Records interface {
	// Nodes lists the nodes holding a chain valid now, newest per ISD-AS.
	Nodes(ctx context.Context) ([]Node, error)
	// Hosts lists the registry's hosts with their presence.
	Hosts(ctx context.Context) ([]Host, error)
	// RemoveHost deletes the host holding the node key.
	RemoveHost(ctx context.Context, nodeKey string) error
}
```

`Node` carries the ISD-AS, the newest chain's subject key fingerprint and
expiry, the role — founding core, core, or node — and, when the directory
holds the node's entry, its overlay, host endpoint, and issued count.
`Host` carries the address, the node and machine keys, the owning node,
the approving note, the claimed hostname and operating system, and the
presence. `Hosts` and `RemoveHost` answer `ErrNoCoordination` when the
coordination application did not load, and the Hosts view says so.

The table's entry, [portal.go](/pkg/apps/portal.go), implements the
interface over two new environment fields — `IssuedChains`, the chains
valid now that the trust database holds, and `HTTPSOrigin`, the console's
origin — and over the applications it borrows where they loaded:

*   **Nodes:** `IssuedChains`, the newest chain kept per ISD-AS; the role
    from the founder's own ISD-AS and the cores `Engine.CoreASes` names;
    the overlay, endpoint, and issued count from the WireGuard registry's
    `List` when the WireGuard application loaded.
*   **Hosts:** the registry's `List` beside the coordination application's
    `Presence`, the presence's latest hostname and operating system
    standing over the registry's.
*   **RemoveHost:** the coordination application's `RemoveHost`.

The assembly fills `IssuedChains` with a `trustDB.Chains` query whose
validity window is now, and `HTTPSOrigin` with `https://<domain>`, the
port of the harness's HTTPS placement joining it when it names one other
than 443.

### The coordination application

*   **The release:** `RemoveHost(ctx, wireguard.PublicKey) error` takes
    `admissionMtx`, so the delete interleaves with no admission, deletes
    through `Store.DeleteHost`, and logs the release. An open map stream
    closes at its next re-read, as for any vanished registration.
*   **The map path's write:** the one write `handleMap` can make —
    binding a record from before the machine claim to its first machine —
    takes the same lock and re-reads the record before it writes, so a
    release is never undone by a rebinding that read the record first.
*   **Presence:** `handleMap` records the node key's last map request,
    with the hostname and operating system its `Hostinfo` claims, and
    holds a count of open streams while it streams. `Presence` returns a
    snapshot keyed by node key, in memory; an entry leaves with its
    registration.
*   **The label:** `handleRegister` fills `AdmissionFacts.Label`, and on
    allow records the hostname and operating system in the host entry.
*   **The store:** the application's `Store` interface gains `DeleteHost`.

### The WireGuard registry

*   `HostEntry` gains `Hostname` and `OS`, the client's claims recorded at
    admission. The directory's wire form omits both, so they stay on the
    core.
*   `DirectoryStore` and `Registry` gain `DeleteHost(ctx, PublicKey)
    error`; deleting an absent key succeeds.
*   The bbolt store's `wireHostEntry` gains `hostname` and `os`, omitted
    when empty, and `DeleteHost` deletes the key from the hosts bucket;
    the dbtest `MemStore` follows, and the contract suite gains the case.

### The dependency and the documentation

`github.com/go-webauthn/webauthn` v0.18.2 enters `go.mod` as a direct
requirement, with the modules it requires — `go-webauthn/x`,
`golang-jwt/jwt/v5`, `google/go-tpm`, `go-viper/mapstructure/v2`, and
`tinylib/msgp`; `fxamacker/cbor/v2` and `google/uuid` are in the graph
already.

The implementing commit updates the
[architecture](/docs/design/architecture.md) — the enrollment
authorizer's methods and the applications name the portal — and flips
ADR-0022 to accepted.

## Test plan

A software authenticator in `internal/passkeytest` answers creation and
assertion options with an ES256 key, so the console's tests and the lab
drive real ceremonies without a browser.

*   **Unit, the asks (decision 1):** the contract suite passes with facts
    presenting no keys; an ask pends and refreshes its last seen on
    retry; an approval answers allow within ten minutes and pends past
    them; a rejection answers deny within twenty-four hours; approving a
    rejected ask allows; the table evicts the ask seen least recently past
    256; a restart forgets every decision.
*   **Unit, the method and its pairing (decisions 1 and 2):** `portal`
    loads alone, offers the operator surface, and `portal=x` refuses; the
    inference loads the application exactly beside the method, with or
    without the hosts' applications; a list naming either without the
    other refuses; the console refuses an address identity; the origin
    carries a non-443 port and omits 443.
*   **Unit, the HTTPS seam (decision 2):** the coordination application's
    paths and another application's pattern answer side by side and an
    unmounted path is not found; a pattern mounted twice refuses before
    the port binds; a founder under `portal` loads the console and binds
    for it with a static-file identity and nothing else mounted.
*   **Unit, passkeys (decisions 3 and 5):** a registration and a login
    complete through the software authenticator; the library refuses a
    wrong origin, a wrong relying party, a missing user-verification flag,
    a replayed or expired ceremony, and a signature under an unknown key;
    a clone warning refuses the login; the session cookie carries its
    attributes; the last passkey refuses deletion.
*   **Unit, the setup token (decision 4):** a console with no passkey
    mints a token and logs one link; the first registration consumes it
    and a second presenting it refuses; a new console over the same state
    mints a different token; a console with a passkey mints none; no file
    under the state directory holds the token.
*   **Unit, the HTTP surface:** the API answers 401 without a session; a
    cross-origin POST refuses; the security headers ride every response;
    setup and login refuse past their rate; decisions, mintings, and
    revocations reach the operator surface, a lifetime outside the bounds
    refused before it.
*   **Unit, auth keys (decision 7):** a one-use key admits once and then
    falls through to an ask; a reusable key counts its uses; an expired or
    revoked key falls through and lists in its standing; the keys survive
    a restart; the file holds digests and never a key.
*   **Unit, the label (decision 8):** a registration's hostname and
    operating system reach the facts and the host entry; the directory's
    wire form omits them; the method's verdict on two facts differing in
    the label alone is the same.
*   **Unit, the release (decision 6):** `RemoveHost` deletes the entry and
    closes an open map stream at its next re-read; the freed address
    allocates to the next registration; the removed key's next
    registration asks the policy again; a release racing the map path's
    rebinding of a record from before the machine claim stays released;
    presence shows a stream open while it streams and its last seen
    after.
*   **Unit, the view (decision 6):** the adapter lists one node per
    ISD-AS, its newest chain's key and expiry; roles follow the founder's
    ISD-AS and the TRC's cores; `Hosts` and `RemoveHost` answer
    `ErrNoCoordination` without the application.
*   **Unit, the store:** the contract suite's `DeleteHost` case passes on
    the bbolt store and the `MemStore`; deleting an absent key succeeds.
*   **The roofs:** the modules walk passes — the composition root the
    method's only production importer — and the applications walk passes:
    the console has its entry and imports no sibling.
*   **Integration, the console:** a lab boots a founder under `portal`
    and drives the JSON API with the software authenticator through the
    harness's HTTPS placement: the first passkey registers with the logged
    token; a joining node's enrollment pends and completes on approval; a
    host registers with a minted auth key; removing the host closes its
    stream and its owning node drops the peer.

## Implementation history

*   The HTTPS seam landed first, in a commit of its own: the environment's
    mount, the node's recorded mounts, and the coordination application's
    three paths
    ([https.go](/internal/services/https.go),
    [apps.go](/pkg/apps/apps.go),
    [app.go](/pkg/apps/coordination/app.go)).
*   The console landed as planned in [portal](/pkg/apps/portal) beside the
    method in [portal](/pkg/modules/enrollauth/impl/portal), the page a
    plain script and style embedded beside the Go files. Its ceremonies
    read and parse the request body before they take the console's lock
    and verify with the library's `CreateCredential` and
    `ValidatePasskeyLogin`, the same verification `FinishRegistration` and
    `FinishPasskeyLogin` run, so no network read waits under the lock
    ([passkeys.go](/pkg/apps/portal/passkeys.go)). The setup token is
    checked when the ceremony begins, and the first passkey's registration
    closes setup whichever ceremony completes first.
*   A one-use key binds to the machine that first presents it rather than
    spending at that first answer: the coordination application can still
    refuse an admitted registration — the lab caught one arriving before
    any node had published a slice to allocate in — and a key spent at the
    answer stranded the client's retry behind an operator's approval. The
    holder's retries pass on the key until their admission lands, and no
    other machine's do; the state file records the holder
    ([authkeys.go](/pkg/modules/enrollauth/impl/portal/authkeys.go)).
*   Three bounds the plan left open: a pending ask lapses after ten
    minutes without a retry, and an approval its joiner's retry consumed
    leaves the list and refuses a second decision
    ([asks.go](/pkg/modules/enrollauth/impl/portal/asks.go)); the
    ceremonies and the sessions each hold at most 64 entries, the soonest
    to expire leaving past the bound
    ([passkeys.go](/pkg/apps/portal/passkeys.go)). The rate cap keys on
    the route beside the source, so a begin and its finish within one
    second both pass ([api.go](/pkg/apps/portal/api.go)).
*   The lab reads the setup link where an operator reads the log: the
    application exports `SetupLink`, the line `Run` logs
    ([app.go](/pkg/apps/portal/app.go),
    [portal_test.go](/internal/testnetwork/portal_test.go)). The software
    authenticator encodes its COSE key and attestation with
    `fxamacker/cbor/v2`, which becomes a direct requirement
    ([passkeytest.go](/internal/passkeytest/passkeytest.go)).
*   The coordination application's release and presence live in
    [register.go](/pkg/apps/coordination/register.go) and
    [presence.go](/pkg/apps/coordination/presence.go). The release's
    stream test runs on the real clock: a map frame's zstd encoder outlives
    its test in a process-wide pool, and one a fake-time bubble created
    fails the next test that encodes outside the bubble
    ([release_test.go](/pkg/apps/coordination/release_test.go)).
