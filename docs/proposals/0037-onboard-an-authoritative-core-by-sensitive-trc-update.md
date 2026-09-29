# Onboard an authoritative core by sensitive TRC update

This proposal implements the join seam of
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md):
a second core joins the ISD over the network as `ASTypeAuthoritative`,
its regular voting certificate carried into a sensitive TRC update the
founder casts and the joiner co-signs. The update path the join needs —
predecessor-aware verification, newest-TRC discovery, enrollment routed
to issuers — lands here because without it no second core can join at
all. The rotation and path-segment decisions the same ADR records ride
their own proposals on top of what this one builds.

[TOC]

## Summary

The authoritative tier exists as a parsed enumeration and nothing more.
`ASTypeAuthoritative`'s comment promises it behaves like a normal node
in this milestone, and its parser has no caller
([astype.go](/pkg/trust/astype.go)); the node's role is binary —
`ASTypeCore` when the core flag is set, `ASTypeNormal` otherwise
([node.go](/internal/services/node.go)) — and the core role refuses a
neighbor outright: "the founding core takes no --topology.neighbor:
nodes join it" ([config.go](/internal/services/config.go)). The run
command agrees: `cion run core` registers the founder's arguments and
no neighbor ([run_core.go](/cmd/cion/run_core.go)) — the neighbor flag
belongs to `cion run local` alone
([run_local.go](/cmd/cion/run_local.go)). A multi-core TRC exists only
as the harness's crutch: genesis lists fellow cores beside the founder,
named without voting certificates
([genesis.go](/pkg/trust/genesis.go)) — a name with no key behind it,
fixed at deploy time, which is the thing ADR-0015 decides to stop
needing.

The update machinery the join needs is present and unwired. cppki
ships the rules — `ValidateUpdate` checks the serial increment, the
quorum, and who may cast the votes, and `SignedTRC.Verify` against a
predecessor verifies the votes and every new voter's proof of
possession — and nothing in the repository calls either. The fetch
rejects what it most needs to accept: a fetched TRC is verified with
`Verify(nil)`, and a non-base TRC fails there for want of a
predecessor — the provider's own doc comment reads "updates are not
supported yet" ([network.go](/pkg/trust/network.go)). Every trust read
names the base TRC's exact ID — the chain verification in `GetChains`
and `RenewChain`, the signer's cited TRC, and the core lists the path
layer enumerates ([network.go](/pkg/trust/network.go),
[engine.go](/pkg/trust/engine.go)) — while the numbers-less request
the draft defines for discovery is already served end to end: the
handler maps it to the latest version
([trustservice.go](/pkg/controlplane/trustservice.go)) and the store
answers it with its last key
([db.go](/pkg/modules/trustdb/impl/bbolt/db.go)). No code asks it.

The enrollment seam asks whether, not what.
[ADR-0010](/docs/adrs/0010-gate-enrollment-with-a-pluggable-authorizer.md)
built the authorizer's question on the facts one exchange proves —
keys, source, claim — and a joiner presenting a voting certificate is
a fact that seam has no field for
([admission.go](/pkg/modules/enrollauth/admission.go)). And the route
enrollment takes would misfire the moment the successor TRC spreads:
the one-hop shortcut returns any core the pinned TRC names that is a
direct neighbor with its verdict up
([controlplane.go](/internal/services/controlplane.go)), while a core
that issues nothing answers a chain renewal with Unimplemented
([trustservice.go](/pkg/controlplane/trustservice.go)) — onboarding
without an issuer signal turns every neighbor of the new core into a
node that can never enroll.

## Motivation

ADR-0015 lands through proposals split along its seams, and the join
seam carries the others. Rotation needs the update path this proposal
builds — one mechanism, two needs, the ADR's own driver — and nothing
else it builds; the path-layer behaviors need the named core this
proposal adds, and bring their origination, termination, and lookup
duties on top of it. Build the trust path first and the later
proposals are landings on a working mechanism; build any of them first
and they stand on a TRC that cannot change.

The issuer signal belongs here rather than with the path work because
its failure mode is enrollment's, not beaconing's: the moment core
lists read the newest TRC — the read that makes onboarding visible at
all — the shortcut becomes able to land on a core that holds no CA
keys, and the node behind that link stops enrolling. The root
certificate the TRC already carries is the signal, exactly as the ADR
decides it.

### Goals

*   `cion run core --topology.neighbor <addr>` joins the neighbor's
    ISD as an authoritative core: the refusal lifts, the command takes
    the neighbor flag, and neighbor presence is what separates a
    joining core from a founding one. No new command, no new role
    argument.
*   The joining core generates its regular voting key on first start
    and nothing else — no sensitive, root, or CA key. Its self-signed
    regular voting certificate is created once the provisional
    identity completes and persists beside the key, so retries,
    restarts, and operators all see the same bytes.
*   The enrollment request carries the certificate, and the
    authorizer's facts carry what the joiner asks to be admitted as.
    Open enrollment admits a core joiner exactly as it admits any
    node; the gate stays opt-in.
*   The founder casts the sensitive update: serial incremented on the
    same base, the joiner's AS added to the core and authoritative AS
    lists, its regular voting certificate added to the set, quorum and
    `noTrustReset` untouched. The founder's sensitive key casts the
    vote; the joiner's regular key signs the proof of possession the
    draft requires of every new voter (PKI draft, Section 3.5.6); the
    completed TRC is verified with cppki against the pinned
    predecessor before anything pins or serves it.
*   A fetched non-base TRC verifies against its pinned predecessor —
    fail-closed, the posture the base fetch already holds.
*   The newest pinned TRC becomes the one nodes use: signers cite it,
    chain verification anchors in its root pool, core lists read it,
    and a holder of an older TRC discovers the successor through the
    IDs its signed messages already carry — the discovery duties of
    the draft's Section 4.1.2.
*   Both core-route paths select cores whose root certificate the
    newest TRC carries — exactly the nodes that can issue chains.

### Non-goals

*   No rotation: the founder's voting and root certificates are
    carried into the successor unchanged, so the successor's validity
    is bounded by the earliest expiry among them — and rolling any of
    them arrives in its own proposal, on the path this one builds.
*   No path-layer core behavior: the authoritative originates no
    beacons, terminates no core beacons into core segments, serves no
    core lookup, and registers its down segments no differently than a
    normal node — the `Core` and `IsCore` selections keep selecting
    the founding tier until the path proposal widens them.
*   No second sensitive voter and no CA keys on the authoritative —
    ADR-0015's own non-goals. The quorum stays one; the founder stays
    the ISD's issuer; the sensitive key stays online.
*   No grace periods, no removals, no trust reset: the first updates
    only add material, and the draft's grace machinery arrives with
    the first removals.
*   No harness migration: the `GenesisCores` crutch and the labs that
    stand on it keep their shape; the join lab stands beside them on
    the real path.
*   No new run arguments — the join reuses `--topology.neighbor`
    exactly as `cion run local` takes it.

## Proposal

### Joining decides the role

`cion run core` registers `--topology.neighbor` beside the founder's
arguments — the same registration `cion run local` carries — and
`NodeConfig.Validate` drops the refusal that today rejects the pair.
`loadIdentity` derives the tier from the pair: the core flag without a
neighbor founds, the core flag with one joins as `ASTypeAuthoritative`
([node.go](/internal/services/node.go)). The domain argument keeps its
double meaning by role — the founding core's own WebPKI identity, the
network's core domain for a joiner — and the flag's help text grows to
say both. A restart derives the same tier from the same arguments; the
persisted identity and keys are untouched by it.

### The joiner holds a regular voting key

Beside the founder's all-or-nothing `LoadOrCreateCoreKeys`
([keys.go](/pkg/trust/keys.go)) stands the role-shaped loader: the
regular voting key alone, under the same file name the founder's
occupies — a node is one tier or the other for its lifetime, never
both. The self-signed certificate over it — `createVotingCert`'s
regular shape, the construction genesis already uses
([certs.go](/pkg/trust/certs.go)) — is created after the provider
completes the provisional ISD draw, for the certificate names the
completed ISD-AS, and persists beside the key.

### Enrollment admits the role

The CMS-signed renewal body grows the voting certificate beside the
CSR — a CION extension of the reference body, which carries the CSR
alone, and the same liberty ADR-0003 took when it automated first
enrollment against the draft's formality. The wrapper's possession
proof still covers the AS key it always covered; the voting key's
possession is proved later, by the co-signature on the TRC that
carries the certificate. The authorizer's facts grow the presented
certificate — the question becomes what to admit the joiner as, on the
same seam ADR-0010 established
([admission.go](/pkg/modules/enrollauth/admission.go)) — and the CIDR
and Telegram methods answer it as they answer any ask.

### The founder casts, the joiner co-signs

The founder assembles the successor from its newest pinned TRC and the
admitted joiner: serial incremented by one on the same base number;
the joiner's AS appended to the core and authoritative AS lists; its
regular voting certificate appended to the certificate set; the quorum,
`noTrustReset`, and the sensitive voting certificates untouched — a
sensitive update, as cppki's classification will read it. The votes
field carries the predecessor's index of the founder's sensitive
voting certificate (Section 3.5.5), and the validity is the window
every certificate the successor carries still covers — cppki refuses
a TRC whose certificates do not cover its validity, and the joiner's
fresh certificate never rules that window; the founder's carried ones
do.

The draft leaves the casting procedure to the ISD (Section 3.5.6);
CION's is one request-response pair on the control endpoints the
enrollment channel already connects. The founder sends the successor
carrying its sensitive vote; the joiner adds the signer info its
regular key makes — the proof of possession — verifies the whole
against the base TRC it pinned at enrollment, and returns the
completed TRC. The founder verifies the same way and pins. The
artifact carries exactly two
signatures, the vote and the possession proof, and the founder's
assembly is what keeps it at two. The cast is serialized on the
founder, so serials stay monotone under concurrent joins, and
idempotent: a joiner whose AS the newest TRC already names is issued
its chain and casts nothing.

### Verification follows the chain

`fetchTRC` resolves the fetched TRC's predecessor before it verifies:
serial one stands on nothing and verifies as the base, as today; a
later serial is verified with the predecessor once that predecessor is
pinned — fetched first when it is missing, so a node holding only the
base can chain its way to any successor
([network.go](/pkg/trust/network.go)). The posture stays fail-closed:
a TRC no pinned predecessor vouches for never enters the database, and
`InsertTRC`'s conflict check keeps two versions of one ID from ever
coexisting ([db.go](/pkg/modules/trustdb/impl/bbolt/db.go)).

### The newest TRC is the one nodes use

Three reads move from the base TRC's exact ID to the newest pinned
TRC, and one fetch learns to ask for it. The signer cites the newest
TRC held locally — `Signer`'s TRC ID reads the local newest, not the
base ([engine.go](/pkg/trust/engine.go)). Chain verification anchors in
the newest pinned TRC's root pool — `GetChains` and `RenewChain`
resolve and verify against it
([network.go](/pkg/trust/network.go)). The core lists — `CoreASes`,
and every reader it feeds — read the newest pinned TRC, which is where
onboarding becomes visible to the path layer. The pull asks the
numbers-less form the draft's active discovery defines (Section 4.1.2),
the form the handler maps and the store already answers. The discovery
itself rides what signed messages already carry: the verifier reports
the cited TRC ID through `NotifyTRC`, the dedup and its minute window
already in place ([verifier.go](/pkg/trust/verifier.go)), and the
provider pulls what the report names, from the founder's endpoint
every node already has a route to.

### Enrollment routes to issuers

Both core-route paths — the one-hop shortcut over a neighboring core
and the composed fallback over the freshest up segment
([controlplane.go](/internal/services/controlplane.go)) — select from
the cores whose root certificate the newest TRC carries: the ASes a
root certificate names as its subject, exactly the nodes that can
serve a chain renewal. Today that set is the founder alone, so the
shortcut that would have landed on the authoritative core falls
through — over the link to the founder when the founder is the
neighbor, over the composed route when it is not — and the joiner's
own enrollments and renewals reach the founder as any node's do.

### The authoritative runs as a node

The branch selections leave the joiner a normal node in every phase:
it builds the enrollment client, not the genesis-and-issuer path; it
runs the enroller, not the self-issuer
([node.go](/internal/services/node.go)); it prepares no WebPKI
identity of its own — the founder's domain stays the bootstrap
channel's only anchor; and the beaconer and lookup flags keep their
founding-tier selections, so the path-layer deferrals of the
non-goals hold by construction. `astype.go`'s milestone comment — the
tier "behaves like a normal node" while multi-core ISDs remain a
non-goal — updates beside the tier it finally describes, citing the
record.

## Test plan

*   **Unit, the assembly:** the successor assembled from a predecessor
    and an admitted joiner carries the incremented serial on the same
    base, both AS lists grown by the joiner, the certificate set grown
    by its regular voting certificate, the quorum untouched, and a
    validity bounded by the earliest expiry the set carries; cppki
    classifies it a sensitive update and verifies it against the
    predecessor.
*   **Unit, verification:** `fetchTRC` accepts a legitimate successor
    with its predecessor pinned and refuses the forgeries the rules
    exist for — a serial that does not increment, a vote cast by a
    regular certificate, a missing proof of possession, a tampered
    payload. A base TRC still verifies as a base.
*   **Unit, the newest reads:** the signer cites the newest pinned
    TRC; chains verify against its root pool; the core lists read it;
    a numbers-less pull returns the successor where the exact-ID
    lookup returns the base.
*   **Unit, the role:** the core flag beside a neighbor validates and
    derives `ASTypeAuthoritative`; the loader creates exactly the
    regular voting key; the certificate persists across restarts and
    names the completed ISD-AS.
*   **Unit, the seam and the route:** the authorizer's facts carry the
    presented certificate; the shortcut skips a named core without a
    root certificate and lands on the founder; the composed path
    selects the same set.
*   **Integration, the join lab:** a founder and a joining core, the
    joiner completing its ISD from the neighbor's reply, enrolling
    with its certificate presented, the founder casting, the joiner
    co-signing, and both pinning the successor; a third node
    discovering the successor from the founder's signed messages and
    enumerating two core ASes; a node neighboring the joiner enrolling
    through the founder's endpoint.
*   **Negative and interruption:** a forged successor pins nowhere; a
    re-presented joiner casts nothing; a join interrupted between vote
    and co-signature retries from the newest pinned TRC and leaves
    nothing partial pinned.

## Implementation history
