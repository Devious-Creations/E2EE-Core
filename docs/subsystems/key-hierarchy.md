> **Verified against:** `f8da815` · 2026-08-07 · by sonnet-main (PR #12 merge stamp)

# Key hierarchy — the vault (DEK/KEK) and per-relationship provisioning

This subsystem is `src/keyVault.js` (DEK generation, password/recovery-code
KEK derivation, DEK wrap/unwrap, and per-relationship `K_shared` storage) and
`src/dynamicKeys.js` (provisioning `K_shared` between two paired members using
`keyVault` for storage and `sealing.js` for the AAD-bound wrap/unwrap). Read
it alongside `docs/subsystems/pairing.md` (`K_pair`, the one-time delivery key
for a grant) and `docs/subsystems/message-crypto.md` (the sealing primitives
both of these build on).

## The hierarchy

```
password ──scrypt(v3: N=2^16,r=8,p=1)──▶ KEK ──wraps──▶ DEK (random 32B)
recovery code ──pbkdf2(10k)──▶ recovery-KEK ──wraps──▶ DEK   (alternate unwrap path)
DEK ──wraps──▶ K_shared_i (random 32B, one per relationship/"dynamic")
```

The DEK encrypts the user's cloud backup (via `sealing.js`, not in this
module). `K_shared` encrypts one shared relationship ("dynamic") data plane;
each member stores it wrapped under their *own* DEK, so a dynamic shred
(deleting both members' grants and local slots) makes `K_shared`
unrecoverable while neither member's DEK is touched
(`src/dynamicKeys.js:14-16`).

## What `keyVault.js` does — and what a caller must not assume

- **`generateDEK`/`generateSharedKey`** are both 32 random bytes from
  `primitives.randomBytes` (`src/keyVault.js:52-60`) — there is no derivation
  from anything else; losing the wrapped copy loses the key, full stop.
- **`deriveKEK`** dispatches on a `kdf` descriptor's `algo` field
  (`src/keyVault.js:74-82`) and defaults to `CURRENT_KDF` (v3 scrypt). A
  caller unwrapping an existing vault **must** pass that vault's stored `kdf`
  descriptor, not the default — v1/v2 vaults are still accepted for unwrap
  (`src/keyVault.js:20-24, 37-39`) but only if the caller supplies the
  matching parameters; `deriveKEK` does not infer which version a wrapped DEK
  used.
- **`wrapDEK`/`unwrapDEK`/`wrapKeyUnder`/`unwrapKeyUnder`** are all the same
  `secretbox` operation (`wrapKeyUnder` is a thin alias over `wrapDEK`,
  `src/keyVault.js:220-238`) — a KEK, a recovery-KEK, `K_pair`, and a DEK are
  all just interchangeable 32-byte wrapping keys to this module. **Neither
  function binds the wrapped payload to any context** (no dynamic id, no
  purpose tag) — that binding, where it matters, is `dynamicKeys.js`'s job via
  `sealing.js`'s AAD-in-plaintext pattern, not this module's.
- **`unwrapWithRecoveryCode` requires `assertValidRecoveryKeys` to pass
  first** (`src/keyVault.js:200-201`) — the `recovery_keys` list is
  characterized as **untrusted server input for every consumer** of this
  library (`src/keyVault.js:161-163`): an unbounded or malformed list would
  otherwise turn a `for` loop doing one PBKDF2 (10k) per entry into a hang or
  a bare `TypeError`. The bounds (`MAX_RECOVERY_ENTRIES = 20`, field-length
  bounds `src/keyVault.js:169-172`) and field names deliberately mirror the
  app-side check (`Smaddle-App`'s `recoveryFlow.assertValidRecoveryKeys`) so
  every consumer of this list rejects the same malformed shapes. **A caller
  that fetches `recovery_keys` from storage/network and skips this check is
  not protected by anything inside `unwrapWithRecoveryCode` alone against a
  hang on a hostile or corrupted list** — the guard is in the exported
  function, but only because `unwrapWithRecoveryCode` calls it first; a
  caller reimplementing the lookup loop directly would lose the guard.
- **`createKeyVault(keyStore)` is the only storage-touching half.** Its
  returned `storeDEK`/`loadDEK`/`clearDEK` and
  `storeDynamicSharedKey`/`loadDynamicSharedKey`/`cryptoShredDynamic` do no
  validation of what they're storing — they are opaque `getItem`/`setItem`/
  `removeItem` pass-throughs (`src/keyVault.js:260-303`). **A missing DEK is
  the caller's problem**: `wrapKeyToMaster`/`unwrapKeyFromMaster` throw `'No
  master DEK loaded'` if `loadDEK()` returns falsy (`src/keyVault.js:275-284`)
  rather than silently returning `null` — callers must handle that throw, not
  assume these functions degrade gracefully.
- **`clearAllDynamicKeys` has no enumeration to fall back on** — it can only
  shred the dynamic ids a caller passes in (`src/keyVault.js:299-301`),
  because device keychains have no "list all keys" operation. A caller that
  loses track of which dynamic ids exist cannot use this function to find and
  wipe them; it must keep its own list.
- **`sanitizeStoreKey`** (`src/keyVault.js:241-246`) strips a stored key down
  to `[A-Za-z0-9._-]` because device keychains (`expo-secure-store`) reject
  other characters. It is a lossy, many-to-one mapping — two different
  `dynamicId`s that sanitize to the same string collide on the same slot.
  Nothing in `keyVault.js` detects or prevents that collision at the storage
  layer; the AAD-in-plaintext binding in `dynamicKeys.js` (below) is what
  makes a collision reveal itself as a failed unwrap instead of a silent
  cross-read.

## AAD binding in `dynamicKeys.js`

`secretbox` has no associated-data slot (see `message-crypto.md`), so
`wrapSharedKey`/`unwrapSharedKey` (`src/dynamicKeys.js:28-41`) embed the
`dynamicId` inside the authenticated JSON payload (`{ d: dynamicId, k:
kSharedB64 }`) and `unwrapSharedKey` **rejects** a blob whose bound `d`
disagrees with the caller's expected `dynamicId`
(`src/dynamicKeys.js:37-39`). Without this, a malicious server could swap a
grant between two of a user's dynamics — both are wrapped under the same
master DEK, so a naive swap would otherwise unwrap cleanly and hand the wrong
`K_shared` to the wrong relationship, silently.

## Invariants

**Ordering: in both provisioning entry points, the DEK gate runs FIRST — no
key material is loaded, generated, or unwrapped before it.** Both
`provisionDynamic` (creator, `src/dynamicKeys.js:62-80`) and
`acceptDynamicGrant` (accepter, `src/dynamicKeys.js:92-107`) call
`keyVault.loadDEK()` and throw `'No master DEK loaded'` as the very first
thing, before `loadDynamicSharedKey`, `generateSharedKey`, `unwrapSharedKey`,
or `storeDynamicSharedKey` ever run. This was tightened in board #416: the
gate used to sit *after* the reuse-vs-generate decision (`provisionDynamic`)
or after the delivery unwrap (`acceptDynamicGrant`). That older order was
never a correctness bug — the throw already preceded `storeDynamicSharedKey`
and the `return`, so a doomed call never persisted, returned, or delivered
anything. It was hardening: a doomed call would still read the local slot
and generate (or unwrap) 32 bytes of key material that could never be used.
The gate now guarantees no key material is produced at all when the DEK is
absent. (`loadDynamicKeys`, covered below, is a deliberate exception: it
reads the cached local `K_shared` slot *before* any DEK check, because a
cache hit must succeed with no DEK loaded at all.)

**Re-running provisioning reuses the existing local key.** `provisionDynamic`
checks `keyVault.loadDynamicSharedKey(dynamicId)` (after the DEK gate) and
only generates a fresh `K_shared` if none exists (`src/dynamicKeys.js:72-73`)
— a re-pair or retry does not silently mint a second, divergent shared key
for the same dynamic. **This guarantee rests on `loadDynamicSharedKey`
reporting truthfully.** The DEK gate says nothing about that read: if the
keystore returns a spurious `null` for a slot that actually still holds a
key (while `loadDEK()` itself succeeds), `provisionDynamic` will generate and
publish a **second, divergent** `K_shared` for the same dynamic — the gate
added in board #416 only covers the DEK read, not this one.

**`loadDynamicKeys` rehydrates from the own grant, and never re-persists on
failure.** If the local slot is empty, it falls back to unwrapping the
supplied `ownGrant` under the DEK (the "recovery on a fresh device" case,
`src/dynamicKeys.js:117-143`). An unwrap failure (wrong key, tampered, or
bound to a different dynamic) is reported through the optional
`onUnwrapFault` callback and the function returns `null` — it does **not**
throw, and it does **not** cache anything on failure. Telemetry for that
failure is deliberately left to the consumer
(`src/dynamicKeys.js:46-50`) — this module never phones out on its own.

## Traps

**`wrapKeyUnder`/`unwrapKeyUnder` do not know or care what key they're
wrapping under.** Passing a `K_pair` where a DEK was intended (or vice versa)
produces a syntactically valid wrap that fails only when something later
tries to unwrap it with the *actual* correct key. There is no type tag
distinguishing a DEK-wrapped payload from a `K_pair`-wrapped one at this
layer — only the AAD `d` field (where dynamicKeys.js adds it) catches a
context mismatch, and only for dynamic-id, not for wrapping-key identity.

**Recovery codes intentionally use the cheap KDF** (`KDF_PBKDF2_LEGACY`,
10k iterations, `src/keyVault.js:20-21, 152-153`) — this is correct, not an
oversight: at ~60 bits of entropy (12 chars × 5 bits/char, confusable-free
32-symbol alphabet, `src/keyVault.js:44-46`) they don't need memory-hard
stretching, which exists to compensate for low-entropy secrets like
passwords. Do not "fix" this by moving recovery codes onto scrypt.

## Deliberately not done

- No enumeration/listing of stored dynamic-key slots (keychains don't
  support it) — callers must track their own dynamic-id sets.
- No re-wrap-on-read for `K_shared` (unlike the DEK, which is re-wrapped to
  the current KDF version on the next successful password unwrap per the
  README) — `K_shared` has no KDF-version concept, since it is never
  password-derived.
- No collision detection for `sanitizeStoreKey` at the storage layer — the
  AAD check is what catches it, and only for dynamic-id mismatches.
