# e2ee-core — an end-to-end-encryption core

> **Status: pre-audit. We are publishing this to invite review.** Please break it.
> See [Reporting a finding](#reporting-a-finding). This is the *actual* crypto
> that ships in a production mobile app, extracted verbatim — only the platform
> seams (device keychain, network transport) were swapped for injectable
> interfaces so the whole thing runs with zero platform dependencies.

This is the encryption core of an end-to-end-encrypted mobile app: the servers store user data, relationship
("dynamic") data, proof images, and relayed messages **only as ciphertext**. The
keys never leave the users' devices. This package is the code that makes that
true — the key hierarchy, the pairing handshake, the message ratchet, and the
sealing routines — with nothing else.

We use **only audited, standard primitives** — no home-rolled ciphers or hashes:

| Library | Used for |
| --- | --- |
| [`tweetnacl`](https://github.com/dchest/tweetnacl-js) | XSalsa20-Poly1305 (`secretbox`), X25519 key agreement (`box.before`) |
| [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) | scrypt, PBKDF2-SHA256, SHA-256, HMAC-SHA256 |
| `tweetnacl-util` | base64 / UTF-8 codecs |

---

## Run it

```bash
npm install
npm test        # node --test — no jest/babel toolchain to trust
npm run demo    # end-to-end walk-through of every protocol
```

Requires Node ≥ 20. The test suite runs every protocol against the in-memory
adapters, so there is nothing to configure.

---

## What's in scope (and what isn't)

This package is **only the cryptography**. Two things the app does are
deliberately *not* here, because they are transport/storage, not crypto:

- **Where secrets live at rest** — the app uses the device keychain
  (`expo-secure-store`). Here that is the [`KeyStore`](./src/interfaces.js)
  interface. An in-memory implementation is in [`adapters/`](./adapters).
- **How messages move** — the app uses Supabase (Realtime for the pairing
  handshake, Storage for proof blobs, Postgres for the encrypted planes). Here
  the pairing handshake takes a [`Transport`](./src/interfaces.js); everything
  else simply *returns the ciphertext* for the caller to store/send.

That separation is the whole point: **the security-relevant logic has no idea
what a server is.** Swap in the memory adapters and every protocol runs offline
in one process (that is exactly what the tests do).

---

## Key hierarchy

```
  password ──scrypt(N=2^15,r=8,p=3)──▶ KEK ──secretbox──▶ [ wrapped DEK ]   (stored server-side)
                                                              │
  recovery code ──pbkdf2(10k)──▶ recovery-KEK ──secretbox──▶ ┘  (alternate unwrap path)
                                                              │
                                                        DEK (random 32B)
                                                              │
                        ┌─────────────────────────────────────┼───────────────────────────┐
                        ▼                                      ▼                           ▼
              encrypts the user's                    wraps K_shared_i               (per device, cached
              cloud backup blob                   (one per relationship)             in the KeyStore)
                                                          │
   pairing handshake (X25519 + SAS) ──▶ K_pair ──delivers K_shared_i once──▶ partner
                        │
                        └──▶ root of the relay message ratchet (chain keys via HMAC)
```

- **DEK** (Data Encryption Key, random 32 bytes) encrypts the user's own cloud
  backup. It is wrapped by a **KEK** derived from the password via **scrypt**
  (N=2¹⁵, r=8, p=3 — memory-hard, ~32 MiB). Only the *wrapped* DEK is stored
  server-side; the password and unwrapped DEK never leave the device.
- **Recovery codes** (8 codes, 12 chars from a 32-symbol confusable-free
  alphabet ≈ 60 bits each) wrap the DEK via a cheaper KDF (**PBKDF2**-SHA256,
  10k) — high entropy needs no stretching.
- **K_pair** comes from the interactive **pairing handshake**: an ephemeral
  X25519 exchange authenticated out-of-band by a **Short Authentication String**.
  It is both the one-time delivery key for K_shared and the **root of the relay
  ratchet**.
- **K_shared** (random 32 bytes, one per relationship / "dynamic") encrypts a
  shared data plane. Each member stores it wrapped under their *own* DEK (an
  "own grant"), and it is delivered creator→accepter once, sealed under K_pair.

---

## The protocols

| Module | What it does |
| --- | --- |
| [`primitives.js`](./src/primitives.js) | The thin, platform-agnostic wrapper over the audited libraries. Everything else is built from this. |
| [`keyVault.js`](./src/keyVault.js) | DEK generation, scrypt/PBKDF2 KEK derivation, DEK wrap/unwrap, recovery codes, and per-relationship key storage (via `KeyStore`). |
| [`sealing.js`](./src/sealing.js) | Authenticated encryption of a JSON object or a raw blob under a 32-byte key (the backup and proof-image sealing). Pure. |
| [`dynamicKeys.js`](./src/dynamicKeys.js) | Provisioning K_shared between two paired members, **with AAD binding** (see below). |
| [`pairing.js`](./src/pairing.js) | The interactive X25519 handshake + SAS that produces K_pair, over an untrusted `Transport`. |
| [`ratchet.js`](./src/ratchet.js) | The symmetric-key message ratchet over K_pair: HMAC chain keys, per-message keys, skipped-key handling, replay rejection. |

### Sealing & AAD binding

All sealing is **XSalsa20-Poly1305** (`secretbox`): a fresh random 24-byte nonce
per message, authenticated ciphertext (`open` throws on *any* tampering or wrong
key). `secretbox` has **no associated-data slot**, so where we need to bind a
ciphertext to a context we put the context **inside the authenticated
plaintext** and check it on open. `dynamicKeys` does this for K_shared grants:
a grant is `secretbox({ d: dynamicId, k: K_shared })`, and unwrap **rejects** a
blob whose bound `d` differs — otherwise a malicious server could swap a grant
between two of a user's dynamics (both are under the same DEK, so a naive swap
would unwrap cleanly). This "AAD in the plaintext" construction is one of the
things we'd most like a second opinion on.

### Pairing (X25519 + SAS)

Two devices exchange ephemeral X25519 public keys over an **untrusted**
transport and derive a shared root K_pair. Because the transport is untrusted,
authentication comes from a **Short Authentication String** that the two humans
compare out-of-band — matching SAS ⇒ no machine-in-the-middle. See
[`pairing.js`](./src/pairing.js) for the exact commitment ordering and SAS
derivation.

### Relay ratchet

Messages between paired devices are encrypted with a **symmetric-key ratchet**
rooted at K_pair: chain keys advance via HMAC, each message gets a fresh message
key, used keys are deleted (forward secrecy along the chain), out-of-order
messages are handled with a bounded skipped-key cache, and replays are rejected.
**Note the honest limitation:** this is a *chain-key* ratchet from a static root,
not a full Double Ratchet with per-message Diffie-Hellman — so it does **not**
provide post-compromise security (a compromised chain state stays compromised
until re-pairing). We think that's an acceptable trade for this app's model, but
it is exactly the kind of decision an audit should challenge.

---

## Threat model

**What the server (and any network observer) cannot do:**
- Read the user's backup, the shared relationship data, proof images, or relayed
  message contents. It holds only ciphertext + nonces.
- Learn the password, the DEK, K_pair, or any K_shared.
- Silently swap an encrypted grant from one of a user's relationships into
  another (AAD binding rejects it).
- Machine-in-the-middle a pairing without producing a **mismatched SAS** that the
  users would see.

**What we trust:**
- The **device keychain** (`KeyStore` implementation) for at-rest key secrecy.
  If the device is fully compromised, its keys are exposed — this package is not
  a defence against a rooted device.
- The **out-of-band SAS comparison** by the two humans to authenticate pairing.
- The **audited primitives** (`tweetnacl`, `@noble/hashes`) to be correct.
- A working platform **CSPRNG** (`globalThis.crypto.getRandomValues`).

**What is explicitly NOT protected (known limitations — please scrutinise):**
- **Metadata.** Who is paired with whom, message timing, and message/blob sizes
  are visible to the server/transport. This is not a metadata-private system.
- **Post-compromise security** on the relay ratchet (see above).
- **Backup forward secrecy.** The DEK is long-lived; compromising it exposes the
  backup. This is inherent to a password-recoverable backup.
- **The transport's availability/ordering.** The ratchet tolerates reordering and
  gaps but does not itself guarantee delivery.

---

## What we'd especially love reviewed

1. **The AAD-in-plaintext binding** in `dynamicKeys.js` — is embedding the
   context id in the authenticated plaintext a sound substitute for real AAD
   here? Any way to defeat the `d !== dynamicId` check?
2. **The pairing handshake** in `pairing.js` — commitment ordering, SAS
   derivation and length, and any reflection / unknown-key-share / downgrade
   angle over an attacker-controlled transport.
3. **The ratchet** in `ratchet.js` — chain-key derivation, nonce/counter
   handling, the skipped-key cache bound (`MAX_SKIPPED_KEYS`), and whether the
   replay rejection is watertight.
4. **KDF parameters** — is scrypt N=2¹⁵/r=8/p=3 an appropriate 2025 choice for a
   phone? Are the recovery-code entropy (~60 bits) and PBKDF2-10k defensible?
5. **Nonce hygiene** — every `secretbox` nonce is a fresh 24 random bytes; is
   there any path where a nonce could be reused under a fixed key?
6. **The extraction itself** — did we change any security-relevant behaviour
   while lifting this out of the app? Diff against the app's source is welcome.

---

## Reporting a finding

Please **do not** open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting instead: **Security → Report a vulnerability** on
this repository. We'll coordinate disclosure there. Non-sensitive feedback (docs,
style, test ideas) is very welcome as normal issues / PRs.

## License

[Apache-2.0](./LICENSE).
