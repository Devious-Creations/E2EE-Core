> **Verified against:** branch `feat/qr-commitment-hooks` · 2026-08-02 · by coder (board #233 step 6 phase A)

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
288-291`).

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
the SAS; they are pure additions gated on the new parameters being present.

- **`onCommit`** (initiator, optional 4th arg to `initiatePairing`,
  `src/pairing.js:179-180`): called once, synchronously, with the base64
  commitment (`sha256(pk_I)`) the instant it's computed (`src/pairing.js:
  231-236`) — before the `pair_commit` broadcast loop starts — so the caller
  can render it into a QR. A throwing or slow callback is caught and can never
  break or stall the handshake (`try/catch` around the call,
  `src/pairing.js:232-236`); note `onStateChange` itself gets no such guard
  today, so this is a deliberately *stricter* treatment for the new hook, not
  a mirror of an existing one.
- **`expectedCommit`** (joiner, optional 4th arg to `joinPairing`,
  `src/pairing.js:198-199`): the base64 commitment obtained out-of-band (e.g.
  scanned from the initiator's QR). When present:
  1. On `pair_commit`, the wire value must equal `expectedCommit` **before**
     `pair_response` is sent (`src/pairing.js:378-388`) — fail-fast, so an
     impostor holding the transport never even gets a response.
  2. On `pair_reveal`, the revealed key is re-hashed and checked against
     `expectedCommit` **directly** — never against the already-stored,
     wire-derived `partnerCommit` (`src/pairing.js:447-462`, checked *before*
     the pre-existing wire-commit check at `src/pairing.js:463-467`). This is
     the point that actually matters: a MITM that substitutes both halves
     consistently with *each other* still passes the ordinary wire-commit
     check, so `expectedCommit` must be verified against the **revealed key
     itself**, not merely against whatever commit value arrived over the wire.
  3. Either mismatch is a hard, fatal, non-recoverable abort with the new
     `QR_COMMITMENT_MISMATCH_ERROR` (`src/pairing.js:71-77`) — no retry, no
     fallback path, no session ever derived, no `sharedKey` ever returned.
     It is deliberately distinguishable from `CONTESTED_ERROR`/
     `TAMPERED_ERROR` (neither of which is actually exported — callers
     today match on message text) so the app can render a louder,
     different UI for "the thing you scanned isn't this device" than for an
     ordinary contested-code or wire-tamper abort.

**When `expectedCommit` is absent, behavior is byte-identical to today** — the
link/typed-code path is untouched; both new checks are gated on
`expectedCommit !== undefined`.

**The SAS is unchanged and still required.** These hooks authenticate the
*key exchange*; they say nothing about the SAS step that follows, which the
protocol still runs unconditionally. Skipping the SAS because a caller
verified `expectedCommit` would be a caller-side product decision — out of
scope for this crypto core, and not something this change endorses.

## Contested pairing is a fatal abort, by design — and not yet recoverable

**Three triggers reject the handshake promise and the handshake never
revives, for the lifetime of that `performHandshake` call:**

1. A second, different partner id answers after the first has locked in
   (`lockOrVerifyPartner`, `src/pairing.js:275-286`, called from the
   `pair_commit`/`pair_response`/`pair_reveal`/`pair_confirm` handlers at
   lines 332, 335/356/359, 390, 427).
2. A duplicate `pair_commit` whose committed value differs from the one
   already locked (`src/pairing.js:346-348`).
3. A duplicate `pair_response` whose public key differs from the one already
   locked (`src/pairing.js:360-364`, the branch that is NOT the same-key
   "resend" case).

All three call `fail(CONTESTED_ERROR)` (`src/pairing.js:65-66, 236-241`),
which sets the closure-scoped `settled` flag, tears the handshake down
(`cleanup()` — clears timers and closes the transport), and rejects the
promise. Every event handler in `performHandshake` checks `settled` at its
top or via `lockOrVerifyPartner`'s own guard, so a message arriving after
`fail()` — even a well-formed, correctly-signed one from the *original*
locked partner — is silently dropped, not processed
(`src/pairing.js:328-453`, the `if (settled ...) return;` guards on every
handler). **There is no path back to `pending`/`exchanging` once `settled` is
true.** `test/pairing.test.js:218-303` pins exactly this: it crafts a
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
(`src/pairing.js:86-91`). Trust comes entirely from the SAS comparison after
the committed exchange. The code space (two words + four digits ≈ 23M
combinations, `PAIRING_WORDS` at `src/pairing.js:73-80`) exists to make
online guessing of an *active* rendezvous statistically dead within the
120-second `PAIRING_TIMEOUT_MS` window (`src/pairing.js:59-60`), referencing
DeviousByDC#433 where the older WORD-NNNN space (480k) was judged too small.

**The ephemeral keypair never touches the `KeyStore`.** It lives only in the
`performHandshake` closure (`src/pairing.js:193-199`), so two concurrent
handshake attempts on the same controller can never cross-derive by sharing
a stored secret slot.

**Only one handshake is live per controller.** `cancelActiveHandshake`
(`src/pairing.js:149-153`) aborts any previous in-flight attempt before a new
one starts (`src/pairing.js:185`), so an abandoned handshake cannot hold its
transport subscribed for the full timeout, nor reject minutes later into a
newer attempt's UI state.

**The revealed key must match its earlier commitment, checked with
constant-time comparison.** The joiner verifies
`sha256(revealed_pk) == commit` via `primitives.timingSafeEqual`
(`src/pairing.js:404-410`) before deriving a session from it — an initiator
that reveals a key different from what it committed to is treated as
tampering (`TAMPERED_ERROR`), not as a protocol variance.

**Key confirmation is bound to role and both identities.** `confirmMac`
(`src/pairing.js:308-311`) HMACs `role|initiatorId|joinerId` under the
derived shared key, so a swapped or replayed confirm from the wrong role or
wrong pair fails `verifyConfirm` (`src/pairing.js:313-321`) and the handshake
fails closed before either side trusts the shared key.

**The initiator's final confirm is awaited before teardown.** `#262`
(`src/pairing.js:442-448`): sending the last `pair_confirm` is awaited before
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
(`migrateLegacyPairing`, `src/pairing.js:487-511`). **Trust is committed at
`storePairing`, not at handshake success** — `performHandshake` resolving
only means keys are exchanged and confirmed; the caller must still show the
SAS for explicit human comparison and only then call `storePairing`
(`src/pairing.js:12-13, 155-159`).

## Traps

**Re-pairing an existing partner overwrites `pairing_key_<id>` in place**
(`src/pairing.js:588-603`) — the pairing id is preserved, only the key and
channel name rotate. This module does **not** clear ratchet state or an
offline message queue for the old root when that happens; see "deliberately
dropped app coupling" below.

**`removePairing`/`clearPairing` touch only pairing metadata and the pairing
key slot**, never the ratchet's own storage keys (`relay_ratchet_*`, owned by
`ratchet.js`). A consumer that runs the ratchet must clear that state itself
on unpair/re-pair rotation — this module cannot do it because it has no
reference to a ratchet instance.

## Deliberately dropped app coupling (not a regression — a stated boundary)

Several NOTE comments mark app-side side effects that this crypto core
intentionally does not reproduce, because they are relay/transport concerns,
not the handshake itself:

- On re-pair rotation, the app purges the offline message queue and ratchet
  chain state under both the old and new channel name so queued ciphertext
  under an abandoned root cannot be silently dropped (`src/pairing.js:576-582,
  595-597`). **A consumer here must do this itself.**
- The app best-effort registers/unregisters the pairing server-side for
  premium propagation (`src/pairing.js:578-579, 641-643`) — dropped, no
  server awareness in this package.
- `clearPairing` in the app also clears the stored relay keypair, the
  per-channel last-seen cursor, and ratchet state (`src/pairing.js:664-669`)
  — none of that lives here.

## Deliberately not done

- No recoverable-contested-pairing path — deliberately deferred 2026-07-30,
  not rejected (see above; scheduled behind the app's server-side
  pairing-topic claim).
- No server-side rate limiting of pairing-code guesses — out of scope for a
  crypto-core package with no network awareness.
- No re-verification/reset UI for a pairing gone bad; that is app-layer.
