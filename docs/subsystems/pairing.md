> **Verified against:** the commit landing this doc change (built on
> `c060403`) · 2026-09-24 · by coder
> (adds the "Partner admission" section below for the new `admitPartner`
> option, the `pair_abort` event, and `PARTNER_NOT_ADMITTED_ERROR`/
> `PEER_REFUSED_ERROR` — every `src/pairing.js:NNN` anchor inside that new
> section was checked against `src/pairing.js` as changed by this same commit.
> This commit adds code throughout the file — not only where the new section
> was inserted — so every OTHER section's pre-existing `src/pairing.js:NNN`
> anchors, carried over unchanged from the `91a4ad6` pass below, are now
> offset by the new lines and were NOT re-verified by this pass; re-read the
> code before trusting them)
>
> **Prior stamp:** `91a4ad6` · 2026-09-24 · by coder
> (re-read the whole file against this commit — PR #17 moved ~170 lines;
> corrected ~25 stale `src/pairing.js:NNN` line anchors across every section
> and the one test line ref; the lock-by-KeyStore fact was already correct)
>
> **Prior stamp:** `ad085f1` · 2026-09-24 · by coder
> (only the "Storage this module owns" section's `src/pairing.js:NNN` line
> anchors were re-verified against the file at this commit, since that is the
> section this pass changed; the rest of the doc's line anchors were not
> re-checked and may be stale — do not treat them as current without
> re-reading the code they point at)

# Pairing — the X25519 + SAS handshake

This subsystem is `src/pairing.js`: the interactive handshake that gets two
devices sharing no prior secret to a 32-byte pairing root key, `K_pair`, over
an untrusted `Transport`. Read it alongside `docs/subsystems/message-crypto.md`
(what `K_pair` becomes the root of) and `docs/subsystems/key-hierarchy.md`
(how `K_pair` is used to deliver `K_shared`, in `dynamicKeys.js`).

## What this defends against

The transport (a Supabase Realtime broadcast channel in the app) can reorder,
drop, duplicate, or forge messages — none of that is trusted to break the
pairing (`src/pairing.js:30-37`). Authenticity of the final key comes
entirely from the committed X25519 exchange plus an out-of-band **Short
Authentication String (SAS)** comparison the two humans perform: matching SAS
implies no machine-in-the-middle. The five-step protocol
(`src/pairing.js:15-22`) — commit, response, reveal, confirm, SAS — exists
specifically so a MITM cannot grind its own keypair after seeing the other
side's public key to force a matching SAS (`src/pairing.js:24-28,
421-424`).

## Out-of-band commitment delivery (QR path) — board #233

The wire commit alone cannot authenticate anything: it travels over the same
untrusted `Transport` as everything else, so a MITM sitting between the two
devices simply substitutes its own `pair_commit` **and** its own matching
`pair_reveal` together — the commitment only ever stopped SAS-*grinding*
(picking a key after seeing the other side's), never impersonation. Two
hooks let a caller deliver that same commitment through a channel a MITM
cannot reach — a QR code scanned camera-to-screen between the two devices —
so the app can authenticate the pairing *before* the SAS step even runs.
Neither hook changes the wire protocol, message shapes, the transcript, or
the SAS; they are additions gated on the new options being present.

**API shape: a trailing options bag, not a 4th positional.** `onStateChange`
stays positional (existing 3-arg callers are unaffected); `onCommit` and
`expectedCommit` are role-dependent and NOT the same type, so a shared
positional slot would be a footgun (a joiner's string landing in an
initiator's callback slot, or vice versa) and a future addition would need a
5th positional, which does not scale. Both entry points take the bag as their
4th, optional argument:

```js
await pairing.initiatePairing(code, userId, onStateChange, { onCommit });
await pairing.joinPairing(code, userId, onStateChange, { expectedCommit });
```

(`src/pairing.js:223-252`, threaded into `performHandshake(code, userId, role,
onStateChange, options)` at `src/pairing.js:253-254`.) Consumers pin this
package to an exact commit, so no released consumer used these hooks yet when
they were introduced — the API was still free to move. That window closes the
moment a consumer bumps its pin to a commit containing them.

**Both options are validated up front, before anything else runs**
(`src/pairing.js:259-288`): `onCommit` (if present) must be a function,
`expectedCommit` (if present) must be a base64-encoded 32-byte digest (shape
checked, so a base64url or truncated value from a QR round-trip is the
caller's bug, not a user-facing attack warning), and an unrecognised option
key is rejected outright (a typo like `expectedCommmit` would otherwise read
as "no verification requested"). `performHandshake` is `async`, so these
surface as an immediate promise REJECTION — before any transport activity or
key generation — not as a synchronous throw; callers must `await` or
`.catch`. Before this validation existed, a
wrong-typed `onCommit` (e.g. a string) was silently ignored — the QR was
never rendered and the handshake proceeded, unauthenticated, with no signal
to the caller that anything was wrong — and a wrong-typed `expectedCommit`
(e.g. `null`, the natural initial value of a caller's `useState(null)`, or
`''`) would have been carried into the mismatch checks below and could
render an attack warning for what is actually a programmer bug. Both are now
a loud, immediate rejection instead.

- **`onCommit`** (`src/pairing.js:312-333`): called once with the base64
  commitment (`sha256(pk_I)`) the instant it's computed, on the initiator
  path only, before the `pair_commit` broadcast loop starts — so the caller
  can render it into a QR. It is called inside a `try/catch`, and if it
  returns a thenable, a no-op rejection handler is attached to that too
  (`src/pairing.js:326-329`): an **async** `onCommit` that later rejects would
  otherwise become an unhandled promise rejection, which under Node's default
  terminates the process — and QR rendering is exactly the kind of thing a
  caller writes as `async`. Precisely: a throwing or slow **synchronous**
  callback cannot break the handshake and cannot eat into its timeout budget
  (the try/catch swallows a throw; a slow synchronous call still blocks that
  turn of the event loop for as long as it runs, same as any other synchronous
  call here — it does *not* "never stall"). `onStateChange` itself gets no
  such guard today; this is a deliberately *stricter* treatment for the new
  hook, not a mirror of an existing one. The joiner never receives `onCommit`
  — it is gated on `role === 'initiator'`.
- **`expectedCommit`** (`src/pairing.js:496-503, 578-585`): the base64 commitment
  obtained out-of-band (e.g. scanned from the initiator's QR), in the SAME
  encoding `primitives.encodeBase64` produces (standard RFC 4648 base64 WITH
  padding — this package does **not** accept base64url (`-`/`_`) or
  unpadded input; `decode32` rejects both, since it goes through
  `primitives.decodeBase64` → `tweetnacl-util`, which is strict. **If a QR
  encoding pipeline uses base64url, the caller must convert to standard
  base64 before passing `expectedCommit`** — this crypto core will not do
  that conversion for you.

  When present:
  1. **Commit-stage gate, the PRIMARY defence** (`src/pairing.js:496-503`): on
     `pair_commit`, the wire's commit is decoded and byte-compared (via
     `timingSafeEqual`, reusing the already-decoded `commitBytes` — not a raw
     string compare, since an equivalent re-encoding of the same digest is
     routine for QR encoders and must not read as an attack) against
     `expectedCommit`, **before** `pair_response` is ever sent. This is the
     check that actually stops a consistent-substitution MITM: pinning the
     wire commit to the out-of-band value before any response goes out means
     such a MITM's `pair_commit` never gets a response and the handshake never
     reaches `pair_reveal` at all. **This gate must never be removed as a mere
     "fail-fast nicety"** — it is not redundant with the reveal-stage check
     below.
  2. **Reveal-stage re-hash, defence-in-depth** (`src/pairing.js:578-585`): on
     `pair_reveal`, the revealed key is independently re-hashed and checked
     against `expectedCommit` directly — never against the already-stored,
     wire-derived `partnerCommit`. This exists to preserve the same guarantee,
     and to surface the more specific `QR_COMMITMENT_MISMATCH_ERROR` rather
     than `TAMPERED_ERROR`, **if the commit-stage gate above is ever weakened
     or bypassed** — it is not the primary mechanism and must not be relied on
     alone.
  3. Either mismatch is a hard, fatal, non-recoverable abort with the new
     `QR_COMMITMENT_MISMATCH_ERROR` message (`src/pairing.js:107-109`) — no
     retry, no fallback path, no session ever derived, no `sharedKey` ever
     returned. The thrown `Error` also carries `err.code ===
     'QR_COMMITMENT_MISMATCH'` (`src/pairing.js:111-116`, via an optional 2nd
     arg accepted by the internal `fail()` helper) — this was the file's
     **first** exported pairing error, and set the precedent: `CONTESTED_ERROR`
     and `TAMPERED_ERROR` are now exported the same way, each with its own
     stable `err.code` (`CONTESTED_CODE = 'CONTESTED'`, `TAMPERED_CODE =
     'TAMPERED'`, `src/pairing.js:90-100`), attached at every `fail(...)` call
     site that throws them. Callers should branch on `err.code`, not on
     message text, for all three — message text itself is unchanged, so
     existing callers still matching on it are unaffected (board #288).

**When `expectedCommit` is absent, there is no behavioural change on the
shipped (link/typed-code) path** — both new checks are gated on
`expectedCommit !== undefined`. (Earlier revisions of this doc claimed
"byte-identical to today"; the `pair_reveal` handler was reordered to run the
QR check before the pre-existing wire-commit check, so the *code path taken*
changed even though the *observable behaviour* for `expectedCommit`-absent
callers did not — the distinction matters if you're diffing control flow.)

**The SAS is unchanged and still required.** These hooks authenticate the
*key exchange*; they say nothing about the SAS step that follows, which the
protocol still runs unconditionally. Skipping the SAS because a caller
verified `expectedCommit` would be a caller-side product decision — out of
scope for this crypto core, and not something this change endorses.

## Partner admission (`admitPartner`) — before anything is stored

**Why this exists.** `storePairing` is never called until the caller shows
the SAS and the user confirms it — but the consuming app enforces its own
partner-limit policy *after* the handshake resolves, in its own
`confirmPairing`. On a QR pairing the joiner auto-confirms, so an at-limit
INITIATOR meeting a total stranger on a code still runs the whole handshake
to completion: it derives a session, shows a SAS, and only refuses at its own
confirm step — by which point the *joiner* has already auto-confirmed and
stored a one-sided pairing that nothing but a Force purge removes. Moving the
same "may I pair with this user?" question into the handshake itself, before
either side ever reveals/responds, means a refusal aborts before either side
gets far enough to store anything.

**API shape and ordering.** `admitPartner?: (partnerUserId: string) =>
(boolean | Promise<boolean>)` is accepted wherever `onCommit`/
`expectedCommit` are — the same trailing options bag, validated at the same
point, before any transport activity or key generation: an unknown option
key (now including a misspelled `admitPartner`) is still rejected outright
(`src/pairing.js:319-323`), and a present-but-non-function `admitPartner`
throws immediately (`src/pairing.js:353-355`) the same way a malformed
`onCommit`/`expectedCommit` already did.
Each side calls it **exactly once**, with the locked partner's user id, as
soon as that id is known and the existing per-message checks for that step
have already passed — but strictly *before* this side's next message goes
out:

- **Joiner** (`pair_commit` handler): after `lockOrVerifyPartner` and the
  QR `expectedCommit` check both pass, `partnerCommit` is recorded first (so
  a later duplicate `pair_commit` carrying a *different* commit still hits
  `CONTESTED_ERROR`, not a stale admission check), *then* `admitPartner` is
  awaited — only on a `true` result does the joiner ever start its
  `pair_response` repeat loop.
- **Initiator** (`pair_response` handler): after `lockOrVerifyPartner` and
  the public-key shape check both pass, `partnerPublicKey` is recorded first
  (same CONTESTED-on-conflict reasoning), *then* `admitPartner` is awaited —
  only on `true` does the initiator derive the session and ever send
  `pair_reveal`. `onStateChange('exchanging')` on this path is deliberately
  deferred to *after* admission, not before — a refusal never claims progress
  it didn't make.

**Per-handshake, per-side state machine:** `admission: 'none' | 'pending' |
'admitted' | 'refused'`. `'none'` when no `admitPartner` was supplied at all
(today's behaviour, exactly unchanged — no gate, no new event, no new state)
or before the partner's identity is locked; `'pending'` while the call is
in flight; `'admitted'` only on a result `=== true`; `'refused'` on anything
else. **The admission check is strict fail-closed:** `false`, `undefined`,
a truthy non-boolean, a synchronous throw, and a rejection are all treated
identically — only exactly `true` admits.

**While admission is pending or after it is refused, this side must not act
on messages that assume the other side already admitted:**

- A duplicate `pair_commit`/`pair_response` carrying the *same* value as the
  one already locked is a silent no-op either way (nothing new to decide);
  one carrying a *different* value still triggers `CONTESTED_ERROR`
  regardless of admission state — the identity-lock check runs independently
  of, and before, the admission gate.
- The initiator's "duplicate response, resend `pair_reveal`" branch only
  fires when `admission === 'admitted'` — otherwise it would leak the reveal
  to a partner this side hasn't yet decided to pair with.
- The joiner's `pair_reveal` handler and both sides' `pair_confirm` handler
  are gated on `admission === 'admitted'` at their top and drop the message
  otherwise — belt-and-suspenders, since neither message should arrive
  before that point in the honest protocol, but a forged/duplicated one must
  never be processed early regardless.
- A resolution or rejection of the `admitPartner` promise that lands *after*
  the handshake has already settled for an unrelated reason (cancel,
  timeout, transport error, a contested-by-another-message abort) is a
  no-op: the settled check runs immediately after the `await`, and the
  rejection path is caught internally, so a late settle can neither revive
  the handshake nor become an unhandled promise rejection.

**Refusal, `pair_abort`, and the two new errors.** A refusal
(`refuseAdmission`, `src/pairing.js:487-500`, called from
`requestAdmission`, `src/pairing.js:514-535`) stops any in-flight repeat, then
flushes **one** best-effort `pair_abort { userId, reason: 'not_admitted' }`
to the peer — bounded exactly like the `#262` confirm flush (`Promise.race`
against a single `REPEAT_MS` timer, so a stuck `send` can never hold this
side open past one repeat interval) — and only then fails with
`PARTNER_NOT_ADMITTED_ERROR` / `PARTNER_NOT_ADMITTED_CODE` (`src/pairing.js:
143-163`, alongside `PEER_REFUSED_ERROR` / `PEER_REFUSED_CODE`) on the
refusing side. **The no-store guarantee never depends on the abort arriving**: if it's
lost, dropped, or ignored, the peer simply falls back to its own
`PAIRING_TIMEOUT_MS` timeout, and neither side has stored anything either
way — the abort is an optimisation for a faster, more specific rejection, not
a correctness requirement.

The side that *receives* a `pair_abort` and honours it fails with
`PEER_REFUSED_ERROR` / `PEER_REFUSED_CODE` instead. Honouring is scoped as
tightly as the protocol allows, since `pair_abort` is **unauthenticated** —
it travels over the same untrusted transport as everything else, before any
key material exists to sign or verify it with:

- **Initiator:** before any `pair_response` has been accepted, *any* valid,
  well-formed UUID that isn't its own id is honoured — no lock needed, the
  same way an unlocked initiator already fails closed on a foreign
  `pair_commit` today. Once a response has been accepted (a partner is
  locked), only that locked partner's id is honoured, and only up to the
  point the handshake settles.
- **Joiner:** only from the locked initiator's id (`partnerId` — `null`
  until `pair_commit` locks it, so nothing can match before that), and only
  before a `pair_reveal` has been accepted.
- Outside those windows the message is silently dropped. The handler
  (`src/pairing.js:830-840`) never calls `lockOrVerifyPartner` (an abort must
  not be able to lock or contest the handshake by itself) and never copies
  `payload.reason` into the thrown error (it is untrusted free text). It also
  works while *this* side's own admission is still pending or unresolved —
  receiving a valid abort doesn't wait on anything else in flight.

**`admitPartner` is a policy pre-check on a self-asserted id, not
authentication.** At the point either side calls it, the only thing that's
happened is `lockOrVerifyPartner` accepting a UUID that arrived over the
untrusted transport — nothing has been cryptographically bound to that id
yet (that only happens at the `pair_confirm` step's key-confirmation MACs,
see "Key confirmation is bound to role and both identities" below).
`admitPartner`'s job is app-level policy ("would I be willing to pair with
this user id, assuming it's genuine?"), not identity verification — and
because `PEER_REFUSED_ERROR` rides on that same unauthenticated signal,
**its message text must stay neutral**: receiving it is not proof the named
peer actually refused, only that something claiming to be on the other end
of this handshake said so before either side had a key to authenticate that
claim with. App-facing copy built on top of this error must not imply
certainty it doesn't have.

**The accepted one-bit oracle.** Whoever holds a pairing code or QR link
learns exactly one bit either way: whether the app was willing to pair with
*some* identity (their own, since a stranger has no other id to present at
this stage) — win, and the handshake proceeds to the SAS step; lose, and it
aborts with `PARTNER_NOT_ADMITTED_ERROR`/`PEER_REFUSED_ERROR` before a
session ever exists. This is the same shape of exposure the confirm-time
check already had (an app that later says "no room for another partner"
tells the same one bit, later); moving the check earlier does not create a
new information leak, it only closes the window where a refused stranger
could still end up holding stored key material.

**Old/new peer interop.** Neither `admitPartner` nor `pair_abort` change the
wire protocol's other four message types, so an old peer (one built before
this feature existed) still speaks steps 1–4 exactly as before — it just has
no listener for `pair_abort` at all, and the transport drops an unknown
event with no registered handler (`adapters/memoryTransport.js`; the app's
real Realtime broadcast channel behaves the same way for an event nobody
subscribed to). Concretely: an old joiner paired against a refusing new
initiator never receives `pair_reveal` and times out; an old initiator paired
against a refusing new joiner never receives `pair_response` and times out.
Neither side stores in either case — **protection requires the REFUSING side
to be running this code**; an old refusing side has no admission gate at all
and simply completes the handshake as it always did. There is no way to make
an old peer aware of a refusal it doesn't know how to listen for.

## Contested pairing is a fatal abort, by design — and not yet recoverable

**Three triggers reject the handshake promise and the handshake never
revives, for the lifetime of that `performHandshake` call:**

1. A second, different partner id answers after the first has locked in
   (`lockOrVerifyPartner`, `src/pairing.js:408-419`, called from the
   `pair_commit`/`pair_response`/`pair_reveal`/`pair_confirm` handlers at
   lines 468, 520, 551, 610).
2. A duplicate `pair_commit` whose committed value differs from the one
   already locked (`src/pairing.js:507-509`).
3. A duplicate `pair_response` whose public key differs from the one already
   locked (`src/pairing.js:521-528`, the branch that is NOT the same-key
   "resend" case).

All three call `fail(CONTESTED_ERROR, CONTESTED_CODE)` (`src/pairing.js:91-92,
98`, `367` for `fail()` itself), so the rejected error carries both the
message and `err.code === 'CONTESTED'` (board #288). Calling `fail()` also
sets the closure-scoped `settled` flag, tears the handshake down
(`cleanup()` — clears timers and closes the transport), and rejects the
promise. Every event handler in `performHandshake` checks `settled` at its
top or via `lockOrVerifyPartner`'s own guard, so a message arriving after
`fail()` — even a well-formed, correctly-signed one from the *original*
locked partner — is silently dropped, not processed
(`src/pairing.js:461-636`, the `if (settled ...) return;` guards on every
handler). **There is no path back to `pending`/`exchanging` once `settled` is
true.** `test/pairing.test.js:421-451` pins exactly this: it crafts a
post-abort message from the originally-locked partner and asserts no further
`onStateChange` call occurs.

This is deliberate fail-closed behaviour against a guessed-code collision (two
devices racing to answer the same short pairing code), not a bug. Making a
contested handshake recoverable (e.g. re-arming the lock instead of aborting,
or letting the caller retry within the same `performHandshake` call) was
proposed as a way to defang a guessed-code denial-of-service, where an
attacker who can answer pairing codes faster than a legitimate second device
forces every real attempt to fail. **Decided 2026-07-30: deliberately
deferred, not rejected.** The consuming app is closing the same
denial-of-service at a lower layer — a server-side claim on the pairing
topic, so a guesser cannot join the channel at all and never reaches this
code path. Recoverability therefore drops from primary defence to
defence-in-depth, and is scheduled after that claim predicate is enforced.
**The change has not been made.** Any future edit here must not
treat "contested is fatal" as accidental — it is the current answer to a
real trade-off, and changing it changes the DoS story in both directions
(recoverable pairing helps a legitimate retry, but also gives a
guessed-code attacker more tries against the same code before it expires).

## Invariants

**The pairing code is a rendezvous identifier, not a trust anchor**
(`src/pairing.js:133-139`). Trust comes entirely from the SAS comparison after
the committed exchange. The code space (two words + four digits ≈ 23M
combinations, `PAIRING_WORDS` at `src/pairing.js:121-128`) exists to make
online guessing of an *active* rendezvous statistically dead within the
120-second `PAIRING_TIMEOUT_MS` window (`src/pairing.js:79`), referencing
DeviousByDC#433 where the older WORD-NNNN space (480k) was judged too small.

**The ephemeral keypair never touches the `KeyStore`.** It lives only in the
`performHandshake` closure (`src/pairing.js:301-307`), so two concurrent
handshake attempts on the same controller can never cross-derive by sharing
a stored secret slot.

**Only one handshake is live per controller.** `cancelActiveHandshake`
(`src/pairing.js:197-201`) aborts any previous in-flight attempt before a new
one starts (`src/pairing.js:293`), so an abandoned handshake cannot hold its
transport subscribed for the full timeout, nor reject minutes later into a
newer attempt's UI state.

**The revealed key must match its earlier commitment, checked with
constant-time comparison.** The joiner verifies
`sha256(revealed_pk) == commit` via `primitives.timingSafeEqual`
(`src/pairing.js:586-593`) before deriving a session from it — an initiator
that reveals a key different from what it committed to is treated as
tampering (`TAMPERED_ERROR`, `err.code === 'TAMPERED'`), not as a protocol
variance.

**Key confirmation is bound to role and both identities.** `confirmMac`
(`src/pairing.js:439-444`) HMACs `role|initiatorId|joinerId` under the
derived shared key, so a swapped or replayed confirm from the wrong role or
wrong pair fails `verifyConfirm` (`src/pairing.js:446-454`) and the handshake
fails closed before either side trusts the shared key.

**The initiator's final confirm is awaited before teardown.** `#262`
(`src/pairing.js:618-631`): sending the last `pair_confirm` is awaited before
`succeed()` runs `cleanup()` → `transport.close()`, because an unawaited send
raced against teardown could drop that one message — leaving the joiner to
time out while the initiator has already shown its SAS and stored its side
of the pairing (an asymmetric, half-completed pairing).

## Storage this module owns

Pairing state persists through the injected `KeyStore`
(`src/pairing.js:39-44`): `relay_pairings` (JSON array of
`{ id, partnerId, channelName, dynamicId?, nickname? }`), `pairing_key_<id>`
(base64 `K_pair` per pairing), `relay_active_partner`, and three legacy
single-partner slots migrated once on first read
(`migrateLegacyPairing`, `src/pairing.js:684-708`). **Trust is committed at
`storePairing`, not at handshake success** — `performHandshake` resolving
only means keys are exchanged and confirmed; the caller must still show the
SAS for explicit human comparison and only then call `storePairing`
(`src/pairing.js:12-13, 204-207`).

**Every `relay_pairings` read-modify-write runs under one lock, keyed by the
`KeyStore` object, not by controller.** Five mutators —
`storePairing`, `setPairingDynamicId`, `updatePairingNickname`,
`removePairing`, and `clearPairing` (`src/pairing.js:805-910`) — each read
the JSON array → mutate it in memory → write it back; without coordination,
two of those calls running concurrently against the same store (e.g. a
background dynamic-id resolve racing a user-triggered nickname rename) can
interleave their read and write so one call's change is silently overwritten
by the other's stale copy of the array. `migrateLegacyPairing` is a sixth
writer of `relay_pairings`, but it only ever runs *under* the lock — either
directly, wrapped in `withPairingsLock` from the public `getStoredPairings`
when a legacy key is still present (`src/pairing.js:738-743`), or as part of
`readPairingsUnlocked` when called from inside an already-locked mutator's
critical section (`src/pairing.js:710-729`) — never on its own outside one.

Consumers commonly build a **fresh controller per call** over one shared,
long-lived `KeyStore` (the app's own pairing wrapper does exactly this), so a
lock created inside `createPairing` would give every call its own
independent lock over the same underlying store and serialize nothing. The
lock is instead a module-level `WeakMap<KeyStore, Lock>`
(`pairingsLockFor`, `src/pairing.js:58-74`, built with the small
promise-chain mutex in `./asyncLock.js`, the same shape `ratchet.js`'s own
`withLock` already uses): every `createPairing({ keyStore })` call looks up
(or creates) the one lock for that `keyStore` object
(`src/pairing.js:678`), so any number of controllers built over the same
store share the same lock and queue behind each other instead of
interleaving. Two separate stores never share a lock, and don't need to.

**One constant key, not one per pairing id** — all six writers share the
single `relay_pairings` blob regardless of which pairing they touch, so
keying the lock by pairing id would not have closed the race (two calls
touching *different* ids still clobber the one shared array).
`readPairingsUnlocked` (`src/pairing.js:710-729`) is the internal, unlocked
read+migrate step — it must only ever be called from inside a function that
already holds the lock (taking it again there would deadlock against
itself); the public `getStoredPairings` (`src/pairing.js:731-743`) is safe to
call from anywhere, since it takes the lock itself for the migration and
reads unlocked afterward. `relay_active_partner` is not covered by this lock
(no interleave against it was found to break it) — each mutator that touches
it (`storePairing`, `removePairing`) does so from inside its own
already-locked section, so calls into those specific paths are still
serialized as a side effect, but a caller invoking `setActivePartnerId`
directly, concurrently with one of the locked mutators, is not synchronized
against it. **In-process only**: this is a single JS-runtime lock, not a
cross-process one — two separate app processes (or two tabs/workers) writing
the same underlying storage are not serialized by it.

## Traps

**Re-pairing an existing partner overwrites `pairing_key_<id>` in place**
(`src/pairing.js:812-821`) — the pairing id is preserved, only the key and
channel name rotate. This module does **not** clear ratchet state or an
offline message queue for the old root when that happens; see "deliberately
dropped app coupling" below.

**A `KeyStore` call that never settles inside a locked section blocks every
later mutator on that store.** The lock has no timeout — this is deliberate
(see "Storage this module owns" above): a hung `getItem`/`setItem` inside one
mutator's critical section leaves `withPairingsLock` waiting on a promise
that never resolves, so every subsequent call sharing that same lock (any
controller built over that `KeyStore`) queues behind it forever, not just the
one that hung.

**`removePairing`/`clearPairing` touch only pairing metadata and the pairing
key slot**, never the ratchet's own storage keys (`relay_ratchet_*`, owned by
`ratchet.js`). A consumer that runs the ratchet must clear that state itself
on unpair/re-pair rotation — this module cannot do it because it has no
reference to a ratchet instance.

**The `relay_pairings` lock does not extend to `relay_active_partner`.**
`setActivePartnerId`/`getActivePartnerId` are plain unlocked reads/writes; a
caller that calls `setActivePartnerId` directly while a locked mutator
(`storePairing`/`removePairing`) is also updating the active partner from
inside its own critical section can still race that specific key. No
concurrent-in-practice caller of `setActivePartnerId` on its own was found,
so this was deliberately left out of scope rather than folded into the same
lock — see "Storage this module owns" above.

## Deliberately dropped app coupling (not a regression — a stated boundary)

Several NOTE comments mark app-side side effects that this crypto core
intentionally does not reproduce, because they are relay/transport concerns,
not the handshake itself:

- On re-pair rotation, the app purges the offline message queue and ratchet
  chain state under both the old and new channel name so queued ciphertext
  under an abandoned root cannot be silently dropped (`src/pairing.js:793-798,
  813-815`). **A consumer here must do this itself.**
- The app best-effort registers/unregisters the pairing server-side for
  premium propagation (`src/pairing.js:793-798, 864-866`) — dropped, no
  server awareness in this package.
- `clearPairing` in the app also clears the stored relay keypair, the
  per-channel last-seen cursor, and ratchet state (`src/pairing.js:889-894`)
  — none of that lives here.

## Deliberately not done

- No recoverable-contested-pairing path — deliberately deferred 2026-07-30,
  not rejected (see above; scheduled behind the app's server-side
  pairing-topic claim).
- No server-side rate limiting of pairing-code guesses — out of scope for a
  crypto-core package with no network awareness.
- No re-verification/reset UI for a pairing gone bad; that is app-layer.
- No `err.code` on the cancel (`'Pairing cancelled'`), timeout (`'Pairing timed
  out'`), transport-error, or the argument-validation throws (bad `KeyStore`,
  missing `Transport`, malformed `onCommit`/`expectedCommit`, unknown option
  key) — board #288 only retrofitted `CONTESTED_ERROR`/`TAMPERED_ERROR`
  alongside the existing `QR_COMMITMENT_MISMATCH_ERROR`; this is a deliberate
  scope line, not an oversight, and consumers still prose-match those.
- No app-side wiring for `admitPartner` in this repo — this package only adds
  the hook and the protocol-level `pair_abort`. The consuming app's own
  partner-limit policy (what makes a partner "admissible") lives entirely on
  the other side of that callback and is out of scope here; the app also
  keeps its existing confirm-time check as a backstop, since a limit can
  change mid-handshake.
- No retry/renegotiation after a refusal — `PARTNER_NOT_ADMITTED_ERROR` and
  `PEER_REFUSED_ERROR` are both terminal, fatal aborts, same as
  `CONTESTED_ERROR`/`TAMPERED_ERROR`: a refused handshake does not revive,
  the caller must start a fresh one with a new code.
