> **Verified against:** branch `fix/scrypt-async-tick` (uncommitted at time of writing) · 2026-08-02 · by fable

# Primitives — the audited-library wrapper

This subsystem is `src/primitives.js`: the thin, platform-agnostic layer
every other module in this repo is built from
(`message-crypto.md`, `pairing.md`, `key-hierarchy.md`). It wraps `tweetnacl`
(secretbox, X25519 `box`), `tweetnacl-util` (base64/UTF-8 codecs), and
`@noble/hashes` (scrypt, PBKDF2, SHA-256, HMAC-SHA256) — **no home-rolled
cipher or hash is implemented here or anywhere in this repo.**

## Why it exists as its own layer

Everything else in this repo imports `./primitives.js` and nothing else for
crypto — no module reaches into `tweetnacl`/`@noble/hashes` directly. That
means a second opinion on "are the primitives used correctly" only has to
review this one file, and swapping a library later (or adding a platform
seam) touches one file rather than six.

## Decisions worth recording

**Libraries are lazy-imported** (`src/primitives.js:19-54`) so a consumer
that only needs hashing never pays to load `secretbox`, and so the app keeps
the tree-shaking it already relies on when depending on this package as a
library rather than a copy.

**The CSPRNG bootstrap is the one behavioural difference from the shipped
app code.** `getNacl()` probes `tweetnacl`'s built-in RNG check and, only if
that throws, wires in `globalThis.crypto.getRandomValues`
(`src/primitives.js:27-43`) instead of the app's React Native/Expo-specific
fallback. If neither is available it throws rather than silently falling
back to something weaker (`src/primitives.js:40-42`) — there is no
"insecure but works" path in this module.

**`scrypt` uses `@noble/hashes`' async variant deliberately, not the sync
one** (`src/primitives.js:236-263`): the sync version blocks the JS thread
for 9–35 seconds at the current parameters (v3: N=2¹⁶, r=8, p=1) on React
Native, freezing the app UI. The async version yields to the event loop in
chunks and accepts an `onProgress` callback for exactly that reason. Same
algorithm, same output — this is a scheduling choice, not a security
trade-off. The comment block also records that the scratch buffer is a
single contiguous `128*r*N`-byte allocation (64 MiB at v3) regardless of `p`
— relevant to why v3 (`p=1`) is only ~13% faster than v2 (`p=3`) despite
doing 2/3 the block-mixes: cache/TLB pressure at the larger working set eats
part of the saving (`src/primitives.js:244-252`). **Do not use the
block-mix-count ratio to predict wall-clock speedup** — it doesn't hold, and
the file says so explicitly.

**`scrypt` pins `asyncTick: 200` instead of noble's default 10** (same
comment block): the yield between work chunks is a scheduler round-trip, and
a consumer whose yield is a real macrotask (the app patches noble's
`nextTick` to `setTimeout(0)` so the UI actually runs between chunks) pays
1–15 ms per yield. At tick=10 the derivation yields ~100×/s and the waits
dominate the wall clock — measured 2026-08-02 at v3 params: 16.7 s total of
which 0.7 s was scrypt; tick=200 took 0.55 s, byte-identical output (the
sync-vs-async KAT in `test/primitives.test.js` pins that). The trade is
progress/paint granularity only: ~5 yields per second, coarser but
sufficient. Consumers that leave `nextTick` as a microtask see no meaningful
change either way. **Do not "restore" the default tick to make progress
smoother** — that reintroduces the minutes-long derivations on device.

**`randomInt` uses rejection sampling, not modulo, over random bytes**
(`src/primitives.js:203-219`): plain `value % maxExclusive` over uniform
random bytes measurably biases the low end of the range whenever
`maxExclusive` doesn't evenly divide the byte range. This matters here
specifically because `pairing.js`'s `generatePairingCode` depends on
`randomInt` to keep the pairing-code space actually uniform — a biased
generator would make some codes likelier to be guessed than the nominal
~23M-combination space implies.

**`timingSafeEqual` is a length-check-then-constant-time-OR comparison**
(`src/primitives.js:196-201`), used everywhere two MACs or commitment hashes
are compared (`pairing.js`'s commit/reveal and confirm-MAC checks). The
length check at the top is *not* constant-time, but the two values compared
here are always fixed-length digests/MACs (32 bytes) by construction, so
that early exit leaks nothing an attacker doesn't already know.

## Traps

**`encodeUTF8`/`decodeUTF8` names are inverted relative to
`tweetnacl-util`'s own naming**, and the code says so inline
(`src/primitives.js:153-166`): this module's `encodeUTF8` calls
`tweetnacl-util`'s `decodeUTF8` (string → bytes), and this module's
`decodeUTF8` calls `tweetnacl-util`'s `encodeUTF8` (bytes → string). This
wrapper's names describe *what this function does* (encode a string to
bytes, decode bytes to a string), not what the underlying library calls
itself. Do not "fix" this by swapping the calls to match the library's
naming — every caller in this repo already depends on this module's naming
convention.

**`hmacSha256`/`sha256Bytes` re-import `@noble/hashes` submodules on every
call** (`src/primitives.js:173-188`) rather than caching a module reference
the way `getNacl`/`getUtil` do. This is a minor, deliberate asymmetry (the
hash functions are cheap to re-import relative to `secretbox`'s one-time RNG
probe) rather than an oversight to "fix" by adding another module-level
cache — no bug report or profiling has flagged it as a cost worth paying
complexity for.

## Deliberately not done

- No home-rolled cipher, hash, or KDF — every cryptographic primitive comes
  from `tweetnacl` or `@noble/hashes`.
- No platform-specific keychain/secure-storage code lives here — that is the
  injected `KeyStore` seam (`src/interfaces.js`), consumed by
  `ratchet.js`/`pairing.js`/`keyVault.js`, never by this module.
- No caching or memoization of derived keys (KEKs, chain keys) — every
  derivation in this module is a pure, stateless function call.
