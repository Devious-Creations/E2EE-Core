> **Verified against:** `e2235f5` · 2026-07-30 · by coder (#142 backfill)

# Message crypto — the relay ratchet and sealing primitives

This subsystem is `src/ratchet.js` (the symmetric-key message ratchet over
`K_pair`) and `src/sealing.js` (the `secretbox`-based sealing routines the
ratchet, `dynamicKeys.js`, and the app's backup/proof-image encryption all
build on). Read it alongside `docs/subsystems/pairing.md` (where `K_pair`
comes from) and `docs/subsystems/key-hierarchy.md` (`K_shared`, the other
key sealing carries).

## What `sealing.js` is

Four independent operations, all pure (key passed in as base64, no storage or
network dependency):

- `encryptDataWithKey` / `decryptDataWithKey` — a JSON object under a 32-byte
  key, wire form `{ ciphertext, nonce }` (both base64).
- `sealBytes` / `openBytes` — a raw blob under a 32-byte key, wire form a
  single self-contained `nonce || ciphertext` byte array (used for proof
  images).
- `sealBox` / `openSealBox` — sealing to a recipient's *published* X25519
  public key with no prior shared secret: ephemeral keypair → X25519 →
  `secretbox`, the ephemeral public key travelling alongside the ciphertext.

All four are `secretbox` (XSalsa20-Poly1305): random 24-byte nonce per
message, and `open` throws on any tampering or wrong key (`primitives.js:98-103`).

## Invariants

**`secretbox` has no AAD slot, so context binding happens inside the
plaintext.** Anywhere a ciphertext must be bound to a context (which dynamic
it belongs to, in `dynamicKeys.js`), the context rides inside the
authenticated JSON payload and the unwrap path checks it explicitly
(`src/dynamicKeys.js:34-41`, `unwrapSharedKey` throws if `obj.d !== dynamicId`).
`sealing.js` itself does not enforce this — it only provides the primitive
that lets a caller do it correctly. A caller who seals a JSON object without
including a context field gets no binding at all; that is a property of what
they put in the object, not of `sealing.js`.

**`sealBox` carries no sender authentication** (`src/sealing.js:98-100`,
restated in `README.md`). `openSealBox` succeeding proves only that the
ciphertext was produced by *someone* who knew the recipient's public key —
which is public. Any identity claim about the sender must be bound inside the
sealed payload by the caller; a receiver must treat `openSealBox` failure as
ordinary invalid input, not as evidence of an attack, because a stranger
sending garbage looks identical to a tampered message.

## No forward secrecy for the archive — the ratchet's central limitation

**This is the single most consequential claim in the repo, and it must never
be softened.** `src/ratchet.js:21-37` states it directly: discarding a chain
key (`ck_n`) after each step only protects against an attacker who recovers a
chain key *in isolation*. That is not the threat that matters, because:

- The root, `K_pair`, is retained verbatim at rest — `storePairing` writes it
  to `pairing_key_<id>` (`src/pairing.js:588-610`) and it is never deleted
  except by an explicit unpair/purge.
- `loadState`/`initState` deterministically re-derive **both** chains from
  counter 0 given only that root (`src/ratchet.js:116-127, 221-234`) — there
  is no independent per-message secret that, once discarded, is actually gone.

So anything that yields the stored `K_pair` (or a live chain-state blob)
yields the entire message history for that pairing, not just future traffic.
The only bound on exposure is operational, not cryptographic: the relay's
ciphertext retention window (the app purges `relay_messages` after 7 days —
`src/ratchet.js:33`), which this package neither enforces nor knows about.

**No README or marketing sentence for this project may say "forward secrecy"
without this qualifier.** The repo's own README once claimed "used keys are
deleted (forward secrecy along the chain)" and had to be corrected in PR #3
after the KEK/DEK terminology audit — the corrected language survives at
`README.md:151-152` ("used keys are deleted... key hygiene, not forward
secrecy — see below") and the honest limitation is spelled out at
`README.md:154-162`. Any future edit to that section must preserve, not
relax, that framing. **Nor does the ratchet provide post-compromise
security** (`README.md:159-161`): a compromised chain state stays compromised
until a genuine re-pair rotates the root.

**`README.md:83`'s "this library never transmits the password or the
unwrapped DEK" is a claim about this package in isolation, and it is true of
it — but it is not true of the shipping app.** The very next sentence
(`README.md:84-86`) already scopes it correctly: an app embedding this core
"may still send that same password to its auth provider during ordinary
account sign-in — ours does." That boundary note must never be dropped from
the README; without it, the sentence reads as a guarantee about user
password handling that the shipping app does not make.

## Invariants — the ratchet mechanics

**Receiver state persists only after a successful decrypt**
(`src/ratchet.js:280-281, 339-343`). A forged or garbage counter walks the
chain forward in memory, fails to authenticate, and is discarded without
writing anything — so an attacker who cannot produce a valid `secretbox` tag
cannot advance or corrupt the receive chain, no matter how many bogus
messages they send.

**Sender state persists *before* the send.** `ratchetEncrypt` writes the
advanced chain state before returning the ciphertext
(`src/ratchet.js:257-276`), so a message key is never reused even if the
actual transport send afterward fails.

**A write-through in-memory cache (`_lastGood`) makes a transient `KeyStore`
read failure distinguishable from "no state stored."** `readState` throws on
a `keyStore.getItem` failure with an empty cache rather than falling through
to re-initialization (`src/ratchet.js:165-194`), because re-initializing on
a transient error would silently reset the chain to counter 0 and brick the
channel until re-pair. This mirrors the DEK-gate pattern in
`identity-pinning.md` (Smaddle-App): a storage failure must never look like
"nothing here."

**A tombstoned channel refuses to silently re-derive.** `clearRatchetState`
replaces surviving chain state with a fingerprinted tombstone rather than
bare-deleting it (`src/ratchet.js:353-375`); `loadState` then refuses to
re-derive fresh chains for the *same* root key (`src/ratchet.js:210-234`).
Without this, a stale in-memory copy of `K_pair` held elsewhere in the
consuming application could resurrect a chain that a purge/unpair was meant
to destroy, and decrypt a partner's still-archived history — breaking the
one cryptographic-erasure guarantee this module can actually make. A genuine
re-pair produces a different root fingerprint and initializes cleanly.

## The skipped-key cache is a permanent loss boundary

`MAX_SKIPPED_KEYS` (`src/ratchet.js:61-80`) bounds how many out-of-order
message keys the receive side will cache. **Anything evicted from that cache
is a message that will never decrypt on that device again** — there is no
second chance, because the corresponding chain key has already been
discarded (that discard is the ratchet doing its job; it just means the
cached `mk` was the last copy).

The comment block at `src/ratchet.js:74-79` records the value's own history
as a cautionary trap: CR-78 shrank the cap from 1000 to 64 to keep serialized
chain state under Android `SecureStore`'s ~2 KB value guidance, but 64
silently drops any reconnect backlog deeper than 64 messages — exactly the
failure mode described at `src/ratchet.js:62-72` (a live broadcast winning
the per-channel lock ahead of a draining missed-message backlog). It was
restored to 1000 to comfortably span a full server-side replay window; normal
traffic holds ~0 skipped keys, so the cap is a pathological-reordering
safety margin, not routine storage cost. **Do not shrink this value again
without re-reading that history** — the failure is silent (a dropped message,
not an error) and easy to reintroduce for a storage-size reason that looked
reasonable the first time.

## Traps

**`ratchetEncrypt`/`ratchetDecrypt` are serialized per channel via
`withLock`** (`src/ratchet.js:236-247`), not per instance globally — two
`createRatchet(keyStore)` instances (e.g. both ends of a channel in one test
process) have independent lock maps and independent `_lastGood` caches. Do
not assume a lock held in one instance blocks the other.

**`partnerIdFromChannel` derives the chain-key label from the channel name,
not from a caller-supplied id** (`src/ratchet.js:105-114`), and throws if
`selfId` is not one of the channel's two participants. A caller that passes
a channel name for a different pair than `selfId`/`session` implies gets a
hard failure here, not a silently wrong chain.

**Forward jumps are capped by `MAX_SKIP` (2000)** (`src/ratchet.js:61`,
`315-317`) independently of `MAX_SKIPPED_KEYS` — this bounds CPU spent
walking the chain forward per message, not storage. A counter more than 2000
ahead of `recv.next` is rejected outright rather than accepted and then
partially cached.

## Deliberately not done

- No per-message Diffie-Hellman step (a full Double Ratchet) — this is the
  symmetric-key half only; see `src/ratchet.js:1-8`.
- No deletion of `K_pair` once chains are seeded — deleting it would break
  re-initialization after an app reinstall/restore, since nothing would be
  left to derive fresh chains from (`src/ratchet.js:28-30`).
- No enforcement of the relay's 7-day retention window from inside this
  package — it is an operational bound the app owns, not a cryptographic one.
