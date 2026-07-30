# E2EE-Core subsystem docs

This repo follows the same documentation rule as `Smaddle-App`: docs ship in
the same commit as the code they describe, and each doc's `Verified against`
stamp is only moved forward when the code was actually re-read against it.
This repo is **public**, so every security claim below is world-readable —
treat inaccuracy here as a bug, not a wording nit.

| Doc | Covers | Hook |
| --- | --- | --- |
| [`message-crypto.md`](./message-crypto.md) | `src/ratchet.js`, `src/sealing.js` | The relay ratchet has **no forward secrecy for the archive** — the root is retained and both chains re-derive deterministically; the skipped-key cache is a permanent loss boundary. |
| [`pairing.md`](./pairing.md) | `src/pairing.js` | The X25519 + SAS handshake; a **contested pairing is a fatal, non-recoverable abort** by current (undecided-as-final) design. |
| [`key-hierarchy.md`](./key-hierarchy.md) | `src/keyVault.js`, `src/dynamicKeys.js` | The DEK/KEK vault and per-relationship `K_shared` provisioning, with AAD-in-plaintext binding against grant-swap attacks. |
| [`primitives.md`](./primitives.md) | `src/primitives.js` | The thin wrapper over `tweetnacl`/`@noble/hashes` every other module is built from — no home-rolled crypto anywhere in this repo. |
