# CLAUDE.md

> **Verified against:** 7ee185c · 2026-07-31 · by fable

This file provides guidance to Claude Code when working with code in this repository.

---

## What this is

`e2ee-core` — the end-to-end-encryption core of a production mobile app (the
"Devious By DC" React Native app, repo `Smaddle-App`). It is **not a demo or a
copy**: `Smaddle-App`'s `package.json` depends on it directly as
`"e2ee-core": "github:Devious-Creations/E2EE-Core"` (a commit-pinned GitHub
dependency, not an npm-registry publish), so whatever is on `main` here is
what ships. No other repo under `C:\Claude work` currently depends on it, but
treat it as a shared library — a breaking change here breaks the app.

The package is **pure JS, no TypeScript, no build step** (`"type": "module"`,
plain `.js` under `src/`/`adapters/`). It has zero platform dependencies — the
device keychain and network transport are injected interfaces (`KeyStore`,
`Transport` in `src/interfaces.js`), which is why the whole crypto stack also
runs standalone here with in-memory adapters (`adapters/`).

This is the actual key hierarchy, pairing handshake, message ratchet, and
sealing routines behind the app's "servers only ever see ciphertext" claim.
The repo is **public** — it's pre-audit and published to invite review
(see `README.md`, `SECURITY.md`).

---

## Build / test commands

From `package.json` — there is no build step, only test/run:

```bash
npm install
npm test        # node --test  (no jest/babel toolchain to trust)
npm run demo    # examples/demo.js — end-to-end walk-through of every protocol
```

Requires Node ≥ 20 (`engines.node`). CI (`.github/workflows/test.yml`) runs
`npm ci && npm test` on Node 20 and 22, on push to `main` and on every PR.

Source layout: `src/primitives.js`, `keyVault.js`, `sealing.js`,
`dynamicKeys.js`, `pairing.js`, `ratchet.js`, exported from `src/index.js`.
Tests live in `test/*.test.js`, one file per module.

---

## Docs — read before touching crypto code

`docs/subsystems/` follows the same documentation rule as every repo under
`C:\Claude work`: **every code change updates its subsystem doc in the same
commit.** Each doc carries a `> **Verified against:** <sha> · <date> · by
<who>` header, moved forward only when the code was actually re-read against
it. Freshness is tracked on **The Board**, project `docs` — check there
before trusting a doc's stamp is current; this repo being public means a
stale security claim is a bug, not a nit.

| Doc | Covers |
| --- | --- |
| `docs/subsystems/INDEX.md` | Index of all four docs below, with a one-line "hook" per doc |
| `docs/subsystems/primitives.md` | `src/primitives.js` — the thin wrapper over `tweetnacl`/`@noble/hashes` everything else is built from |
| `docs/subsystems/key-hierarchy.md` | `src/keyVault.js`, `src/dynamicKeys.js` — DEK/KEK vault, per-relationship `K_shared` provisioning, AAD-in-plaintext binding |
| `docs/subsystems/pairing.md` | `src/pairing.js` — the X25519 + SAS handshake; a contested pairing is a fatal, non-recoverable abort by design |
| `docs/subsystems/message-crypto.md` | `src/ratchet.js`, `src/sealing.js` — the relay ratchet (no forward secrecy for the archive) and the sealing primitives |

`README.md` has the full key-hierarchy diagram, threat model, and the
project owner's explicit "what we'd love reviewed" list — read it before any
non-trivial change.

---

## Key rules and traps

- **`main` is protected — never direct-push.** Branch → `gh` PR → wait for CI
  checks (Node 20 + 22 matrix) → merge. Then run `npm update e2ee-core` in
  `Smaddle-App` (and any other consumer) to pick up the new commit.
- **This is security-critical crypto code.** No drive-by refactors. Any
  change to `src/` needs adversarial review, not just "does it pass tests" —
  see the README's threat model and open review questions.
- **Never weaken a documented invariant** without discussing it explicitly:
  the AAD-in-plaintext binding in `dynamicKeys.js` (rejects a grant whose
  bound dynamic id doesn't match — stops a malicious server swapping grants
  between two of a user's relationships), the five-step commit/response/
  reveal/confirm/SAS ordering in `pairing.js` (prevents a MITM from grinding
  a keypair to force a matching SAS), and the ratchet's replay rejection /
  bounded skipped-key cache (`MAX_SKIP` / `MAX_SKIPPED_KEYS`) in `ratchet.js`.
- **Only `primitives.js` touches `tweetnacl`/`@noble/hashes` directly.**
  Every other module imports crypto only through it — never add a direct
  library import elsewhere; that's what makes a primitives review sufficient
  to cover correct usage everywhere.
- **KDF versioning is backward-compatible by design:** vaults may be v1
  (PBKDF2-10k), v2 (scrypt N=2¹⁵/r=8/p=3), or v3 (scrypt N=2¹⁶/r=8/p=1,
  current default) — the stored `kdf` descriptor says which, all three still
  open, and a vault is re-wrapped at v3 only on the next successful password
  unwrap. Don't assume every stored vault is on the current KDF.
- **The relay ratchet has no forward secrecy for the archive and no
  post-compromise security** — this is a documented, accepted trade-off
  (chain-key ratchet from a static root, not full Double Ratchet), not a bug
  to "fix" unilaterally.
- **`sealBox`/`openSealBox` carry no sender authentication** — any identity
  claim must be bound inside the sealed payload by the caller, never assumed
  from the fact that a box opened successfully.
- Security vulnerabilities go through **GitHub private vulnerability
  reporting** (`SECURITY.md`), never a public issue.
