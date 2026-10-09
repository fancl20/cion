# Stage rolled keys and write state files whole

This proposal hardens the holder-initiated rolls of decision 5 of
[ADR-0015](/docs/adrs/0015-onboard-authoritative-cores-by-sensitive-trc-update.md)
against a crash or a failed write anywhere in a roll: wherever the roll
stops, the node boots on keys that cover the newest TRC it pins, and a roll
whose answer was lost completes without a second submission. It stages the
fresh keys on disk before the pin, where
[proposal 0038](/docs/proposals/0038-rotate-voting-and-root-certificates-by-sensitive-trc-update.md)
holds them in memory, and so closes the lost-answer window that
[proposal 0044](/docs/proposals/0044-gate-the-founders-vote-on-the-authorizer-and-roll-by-regular-update.md)
records. The staged file and every other file a node keeps in its state
directory are written whole through `pkg/statefile`, a shared library in
the sense of decision 2 of
[ADR-0009](/docs/adrs/0009-keep-a-minimal-node-core-and-move-everything-else-to-apps.md).

[TOC]

## Summary

A roll pins its successor first and then writes the fresh material over the
live key files ([rotation.go](/pkg/trust/rotation.go)): the founder's four
keys through `PersistCoreKeys`, and the authoritative's key and certificate
through `PersistVotingPair` ([keys.go](/pkg/trust/keys.go)). Each file is
one `os.WriteFile`, which truncates the file before it writes. Whatever
stops the sequence after the pin leaves live files that the newest TRC does
not name:

*   A founder that stops before its root key is written does not boot. The
    issuer certifies its CA under the newest TRC's root, and x509 refuses a
    root key that does not match it.
*   A founder whose write fails while it runs keeps the predecessor's
    sensitive key in its decision, since the watch hands over the fresh key
    only after the write, and its votes no longer verify. If the failed
    write was the sensitive key's, the next pass takes that key for lost,
    which only a redeploy answers; if the write truncated a file, no later
    pass parses it.
*   An authoritative that stops between its key and its certificate does
    not boot: `LoadOrCreateVotingCert` refuses a certificate that does not
    cover the key. One that stops before its key is written runs on a key
    the newest TRC does not name, and its next roll is the sensitive
    fallback, a question for the operator.
*   A reader that races the write reads a truncated file. The rotation lab
    failed this way, on "no PEM block".

The submission has a window of its own. When the founder pins a submission
after the holder's attempt gave up, the holder's next roll is the sensitive
fallback. The fallback in turn cannot complete under an authorizer that
answers later. The Telegram plugin pends the first ask about a key and
keeps the operator's answer for later asks about the same key
([telegram.go](/pkg/modules/enrollauth/impl/telegram/telegram.go)), but
`RollVotingKey` mints a fresh key for every attempt: each retry is a new
prompt, and no approval meets the key it approved.

## Motivation

A roll is the only way a node's voting and root material outlives its
365-day validity short of a redeploy, so a roll that strands the node
defeats the decision it implements. The pin is already a durable commit,
the trust database's. The fix is ordering: write the fresh material durably
before anything can commit it, and make the replacement of the live files a
step that is redone until it completes.

### Goals

*   Wherever a roll stops, the node boots. A roll that pinned leaves live
    keys that cover the certificates the newest pinned TRC names for the
    node; a roll that did not pin leaves the predecessor's keys untouched.
*   A replacement of the live files that fails in a running node completes
    at the next watch pass, with no second roll.
*   A roll whose answer was lost completes at the holder's next attempt,
    with no submission.
*   Every attempt of a roll uses the same fresh keys until one lands, so an
    authorizer's answer about a key applies to the retry.
*   A file the node keeps in its state directory is replaced whole: a
    reader sees the old content or the new one, and a crash leaves one of
    the two.

### Non-goals

*   No change to what a roll submits, how the founder decides, or what the
    wire carries.
*   No change to the mismatch trigger or to the terminal corner of a lost
    sensitive key.
*   The bbolt databases keep their own commits, and certmagic keeps its own
    storage.

## Proposal

### State files are written whole

`pkg/statefile` is a new shared library with three functions:

*   `Write(path, data)` writes the data to `<path>.tmp` with mode 0600,
    syncs it, renames it over the path, and syncs the directory. A missing
    parent directory is created with mode 0700 and synced into its own
    parent. A failed write removes the temporary file and leaves the path
    as it was. Writes to one path must not overlap; every file has a single
    writer: a loop, the boot, or the holder of a mutex.
*   `Remove(path)` unlinks the file and syncs the directory. A missing file
    is not an error.
*   `LoadOrCreate[T](path, decode, create)` decodes the file and names the
    path in a decode error. When the file is missing, `create` returns a
    fresh value and its bytes, and `Write` persists them before the value
    returns.

Every writer of a state file moves onto it:

*   In `pkg/trust`, `LoadOrCreateForwardingKey`, `LoadOrCreateASKey`,
    `LoadOrCreateCoreKeys`, `LoadOrCreateVotingKey`, and
    `LoadOrCreateVotingCert` use `LoadOrCreate`, and `PersistIA` uses
    `Write`.
*   The WireGuard application's key and the coordination application's
    machine and DERP keys use `LoadOrCreate`
    ([keys.go](/pkg/apps/wireguard/keys.go),
    [keys.go](/pkg/apps/coordination/keys.go)).
*   The measured provider's learned external host
    ([external.go](/pkg/modules/topology/impl/measured/external.go)) and
    the Telegram plugin's invitations use `Write`; the plugin's own
    temporary file and rename go.

The library serves the core and the applications alike, runs no loop, and
holds no policy. The architecture's list of shared libraries gains it
([architecture.md](/docs/design/architecture.md)).

### A roll stages its material before anything can commit it

A roll writes its fresh material to one staged file in the keys folder,
`staged.pem` (the new constant `trust.StagedFile`), with a single
`statefile.Write`, so a stop never leaves part of a set staged. The file
holds PEM blocks, and each block's `File` header names the live file it
replaces. The founder stages its four fresh keys before it pins. The
authoritative stages its fresh key and the self-signed certificate over it
before it submits, for the founder may pin the submission even when no
answer arrives.

A roll that finds a staged file reuses it instead of minting again: the
founder mints its certificates again over the staged keys, and the
authoritative submits its staged certificate unchanged. The staged file
therefore goes away only by promotion. A submission that the founder pins
after the holder gave up names the staged pair, and every retry carries the
key that an authorizer was asked about.

### Promotion replaces the live files once a pinned TRC names them

`trust.PromoteStaged(stateDir, ia, trc)` is new. When the TRC names
certificates for the ISD-AS and the staged keys cover every one of them, it
writes each block to the live file its header names with `statefile.Write`,
then removes the staged file, and reports that it promoted. Otherwise it
leaves the staged file in place: the roll may not have pinned yet, or, on
the authoritative, the founder may have pinned a TRC that the node's own
database has not learned. A promotion that stops partway is redone whole,
since each write gives a file the content it would hold anyway and the
staged file outlives the last write.

Promotion runs at four points:

1.  At boot, `setupTrustRole`
    ([controlplane.go](/internal/services/controlplane.go)) promotes
    against the newest pinned TRC before it loads the voting material, on
    both core tiers.
2.  Each watch pass promotes against the newest pinned TRC before it reads
    the live files ([rotation.go](/pkg/controlplane/rotation.go)). A
    promotion that failed in a running node completes there, with no
    second roll.
3.  The founder's roll: `RotateCoreKeys` ends at its pin. Inside the cast,
    the watch sets the decision's sensitive signer and rekeys the issuer,
    then promotes, so the node signs with the material the newest TRC
    names even while its disk lags behind.
4.  The authoritative's roll: once `RollVotingKey` has verified and pinned
    the founder's newest TRC, it promotes against it before staging. If it
    promotes, an earlier attempt landed, the roll is complete, and nothing
    is submitted. After its own pin, it promotes again.

`PersistCoreKeys` and `PersistVotingPair` go: after the first start,
promotion is the only writer of a core's live voting material. The mismatch
trigger keeps answering an operator's replacement of that material; the
crash between pin and persist that it also guarded against no longer
reaches it.

## Test plan

*   **Unit, state files:** a write creates the file with mode 0600 in a
    parent it creates with mode 0700, and a second write replaces it whole.
    A reader racing a stream of writes of two contents of different lengths
    reads one of the two, whole, every time; it reads until the writer
    finishes, with no sleeps. A directory standing at the temporary name
    fails the write and leaves the old content; a directory standing at the
    path fails the rename and leaves no temporary file. `LoadOrCreate`
    creates a missing file once and returns what it wrote, decodes a
    present one without calling `create`, and names the path in a decode
    error. `Remove` removes the file and accepts a missing one. The syncs
    are not observable from a test and rest on review.
*   **Unit, the founder's stop points:** each state a stop can leave is
    built from the founder's roll, then promoted and loaded the way the
    boot does it. With no staged file, nothing promotes and nothing is
    written. A roll whose pin fails leaves the staged file beside the
    predecessor's live keys; nothing promotes, the live keys anchor an
    issuer in the predecessor, and the next roll reuses the staged keys. A
    roll that pinned and was not promoted, one promoted in part, and one
    promoted with the staged file not yet removed all promote: the live
    keys cover the successor's certificates and anchor an issuer in it, and
    the staged file is gone.
*   **Unit, the authoritative's roll:** a lost answer, where the caster
    lets the founder pin and then fails, leaves the live pair and the
    staged file, and the next roll promotes without calling the caster. A
    refused submission leaves both, and the retry submits the same staged
    certificate. A stop between the key's write and the certificate's,
    reproduced by copying the staged key to the live file, is promoted by
    the sequence the boot runs, and `LoadOrCreateVotingCert` accepts the
    pair.
*   **Unit, the watch:** the founder's promotion failing after its pin, by
    a directory standing at one live file's temporary name, leaves the
    decision voting with the fresh sensitive key and the issuer issuing
    under the fresh root; with the directory gone, the next pass promotes
    and pins nothing further. The authoritative's lost answer completes at
    the next pass with no submission and no question to the authorizer. A
    sensitive fallback under an authorizer that pends the first ask about a
    key and allows later ones lands on the retry, both asks naming the same
    key.
*   **Integration:** a founder stopped between its pin and its promotion —
    booted, stopped, its roll pinned by `RotateCoreKeys` on its state
    directory, and booted again — boots with live keys that cover the
    successor and no staged file, and a node that joins it holds a chain
    that verifies against the successor alone. The rotation lab's polls
    wait for each promotion: the live keys cover the roll's successor, and
    no staged file remains.
