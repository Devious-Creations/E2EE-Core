// keyVault.js — the master key hierarchy and per-relationship key wrapping.
//
// Faithful extraction of the app's `keyManager.js`. Only the platform seam
// changed: the app persisted secrets via expo-secure-store; here the storage-
// bound helpers live on a factory `createKeyVault(keyStore)` that takes an
// injected KeyStore. All the pure crypto (KDF, wrap/unwrap, recovery codes) is
// exported at module scope so it can be reviewed and tested with no platform
// dependency at all.
//
// Key hierarchy:
//   password ──scrypt(N=2^15,r=8,p=3)──▶ KEK ──wraps──▶ DEK (random 32B)
//   DEK ──wraps──▶ K_shared_i (random 32B, one per relationship/"dynamic")
//   recovery code ──pbkdf2(10k)──▶ recovery-KEK ──wraps──▶ DEK (alt unwrap path)
// The DEK encrypts the user's cloud backup; each K_shared encrypts one shared
// relationship plane. K_pair (the relay ratchet root) is produced by ./pairing.

import * as primitives from './primitives.js';

// ── KDF parameters (versioned — stored alongside the wrapped DEK) ──
// v1 (legacy): PBKDF2-SHA256 @ 10k — kept only to unwrap pre-existing vaults
//   (re-wrapped with the current KDF on sign-in) and for recovery codes.
// v2 (current): scrypt N=2^15 r=8 p=3 (an OWASP-listed set) — memory-hard
//   (~32 MiB), so GPU farms can't parallelize it cheaply. Pure JS via @noble.
// Recovery codes intentionally stay on the cheap KDF: at ~60 bits of entropy
// (12 chars x 5 bits/char) they don't need stretching — stretching compensates
// for LOW-entropy secrets like passwords.
export const KDF_PBKDF2_LEGACY = Object.freeze({ v: 1, algo: 'pbkdf2-sha256', iterations: 10_000 });
export const KDF_SCRYPT = Object.freeze({ v: 2, algo: 'scrypt', N: 32768, r: 8, p: 3 });
export const CURRENT_KDF = KDF_SCRYPT;

const DEK_LENGTH = 32;
const SALT_LENGTH = 32;
const RECOVERY_CODE_LENGTH = 12; // 3 groups of 4 chars
const RECOVERY_CODE_COUNT = 8;
const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // no 0/1/I/O to avoid confusion
const STORE_KEY_DEK = 'cloud_dek';
const STORE_KEY_DYN_SHARED_PREFIX = 'dyn_shared_';

// ── DEK generation ──

/** Generate a random 32-byte Data Encryption Key. @returns {Promise<Uint8Array>} */
export async function generateDEK() {
  return primitives.randomBytes(DEK_LENGTH);
}

/** Generate a fresh per-dynamic shared key (K_shared) — 32 random bytes. @returns {Promise<Uint8Array>} */
export async function generateSharedKey() {
  return primitives.randomBytes(DEK_LENGTH);
}

// ── KEK derivation ──

/**
 * Derive a Key Encryption Key from a password and salt. Defaults to the current
 * KDF (scrypt); pass a vault's stored `kdf` to unwrap under an older version.
 * @param {string} password
 * @param {Uint8Array} salt - 32-byte salt
 * @param {{ v:number, algo:string, N?:number, r?:number, p?:number, iterations?:number }} [kdf=CURRENT_KDF]
 * @param {(fraction: number) => void} [onProgress] - optional, forwarded to the
 *   scrypt branch so callers can show progress during KEK derivation.
 * @returns {Promise<Uint8Array>} 32-byte KEK
 */
export async function deriveKEK(password, salt, kdf = CURRENT_KDF, onProgress) {
  if (kdf.algo === 'scrypt') {
    return primitives.scrypt(password, salt, { N: kdf.N, r: kdf.r, p: kdf.p, dkLen: DEK_LENGTH }, onProgress);
  }
  if (kdf.algo === 'pbkdf2-sha256') {
    return primitives.pbkdf2(password, salt, kdf.iterations, DEK_LENGTH);
  }
  throw new Error(`Unknown KDF algorithm: ${kdf.algo}`);
}

// ── DEK wrapping / unwrapping (XSalsa20-Poly1305) ──

/**
 * Wrap (encrypt) the DEK with a KEK.
 * @returns {Promise<{ wrappedDek: string, nonce: string }>} base64 strings
 */
export async function wrapDEK(dek, kek) {
  const { nonce, ciphertext } = await primitives.encryptSecretbox(dek, kek);
  return {
    wrappedDek: await primitives.encodeBase64(ciphertext),
    nonce: await primitives.encodeBase64(nonce),
  };
}

/**
 * Unwrap (decrypt) the DEK with a KEK.
 * @returns {Promise<Uint8Array>} 32-byte DEK
 * @throws {Error} if unwrap fails (wrong password/code or tampering)
 */
export async function unwrapDEK(wrappedDekB64, nonceB64, kek) {
  const wrappedBytes = await primitives.decodeBase64(wrappedDekB64);
  const nonceBytes = await primitives.decodeBase64(nonceB64);
  return primitives.decryptSecretbox(wrappedBytes, nonceBytes, kek);
}

// ── Recovery codes ──

/** Generate recovery codes in XXXX-XXXX-XXXX format (reduced alphabet). @returns {Promise<string[]>} */
export async function generateRecoveryCodes(count = RECOVERY_CODE_COUNT) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const bytes = await primitives.randomBytes(RECOVERY_CODE_LENGTH);
    let raw = '';
    for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
      raw += ALPHABET[bytes[j] % ALPHABET.length];
    }
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`);
  }
  return codes;
}

/**
 * SHA-256 hash a recovery code for lookup, salted with the per-entry KDF salt
 * (which is public anyway) to prevent cross-user precomputation.
 * Input: saltBytes || utf8(normalizedCode).
 * Format change from v0.1: previously unsalted.
 * @param {string} code - raw recovery code (dashes or not)
 * @param {Uint8Array} saltBytes - 32-byte per-entry salt
 */
async function hashCode(code, saltBytes) {
  const normalized = code.replace(/-/g, '').toUpperCase();
  const encoded = new TextEncoder().encode(normalized);
  const input = new Uint8Array(saltBytes.length + encoded.length);
  input.set(saltBytes, 0);
  input.set(encoded, saltBytes.length);
  const hash = await primitives.sha256Bytes(input);
  return primitives.encodeBase64(hash);
}

/**
 * Build recovery entries: for each code, derive a recovery KEK and wrap the DEK.
 * @returns {Promise<Array<{ hash:string, wrappedDek:string, nonce:string, salt:string }>>}
 */
export async function buildRecoveryEntries(dek, codes) {
  const entries = [];
  for (const code of codes) {
    const salt = await primitives.randomBytes(SALT_LENGTH);
    const normalized = code.replace(/-/g, '').toUpperCase();
    // Recovery codes use the cheap KDF on purpose — ~60 bits of entropy needs no stretching.
    const recoveryKEK = await deriveKEK(normalized, salt, KDF_PBKDF2_LEGACY);
    const { wrappedDek, nonce } = await wrapDEK(dek, recoveryKEK);
    // hash uses the raw salt bytes (before base64 encoding) — must match unwrapWithRecoveryCode.
    entries.push({ hash: await hashCode(code, salt), wrappedDek, nonce, salt: await primitives.encodeBase64(salt) });
  }
  return entries;
}

// ── recovery_keys shape-check (the list is untrusted server input for every
// consumer of this library) ──
// The loop below walks the list one PBKDF2 (10k) per entry until it finds a
// hash match — a non-array turns the loop into a bare TypeError, and an
// unbounded list turns recovery into a hang rather than an error. Bounds and
// field names mirror the app-side check (Smaddle-App's
// recoveryFlow.assertValidRecoveryKeys) so every consumer rejects the same
// malformed shapes the app already does.
const MAX_RECOVERY_ENTRIES = 20;
const RECOVERY_ENTRY_FIELDS = ['hash', 'wrappedDek', 'nonce', 'salt'];
const MIN_ENTRY_FIELD_LENGTH = 16;
const MAX_ENTRY_FIELD_LENGTH = 256;

/**
 * Shape-check a `recovery_keys` list before any entry is used to unwrap.
 * @param {unknown} entries - the list as received from storage/network
 * @throws {Error} when the list can't be trusted
 */
export function assertValidRecoveryKeys(entries) {
  if (!Array.isArray(entries)) throw new Error('recovery_keys: expected an array');
  if (entries.length < 1) throw new Error('recovery_keys: must not be empty');
  if (entries.length > MAX_RECOVERY_ENTRIES) throw new Error('recovery_keys: too many entries');
  for (const entry of entries) {
    if (entry == null || typeof entry !== 'object') throw new Error('recovery_keys: malformed entry');
    for (const field of RECOVERY_ENTRY_FIELDS) {
      const value = entry[field];
      if (typeof value !== 'string') throw new Error(`recovery_keys: entry.${field} must be a string`);
      if (value.length < MIN_ENTRY_FIELD_LENGTH || value.length > MAX_ENTRY_FIELD_LENGTH) {
        throw new Error(`recovery_keys: entry.${field} has an invalid length`);
      }
    }
  }
}

/**
 * Find and use a recovery code to unwrap the DEK.
 * @returns {Promise<{ dek: Uint8Array, matchIndex: number }>}
 * @throws {Error} if `entries` fails the shape-check, or if no matching entry found
 */
export async function unwrapWithRecoveryCode(code, entries) {
  assertValidRecoveryKeys(entries);
  for (let i = 0; i < entries.length; i++) {
    const salt = await primitives.decodeBase64(entries[i].salt);
    const codeHash = await hashCode(code, salt);
    if (entries[i].hash === codeHash) {
      const normalized = code.replace(/-/g, '').toUpperCase();
      const recoveryKEK = await deriveKEK(normalized, salt, KDF_PBKDF2_LEGACY);
      const dek = await unwrapDEK(entries[i].wrappedDek, entries[i].nonce, recoveryKEK);
      return { dek, matchIndex: i };
    }
  }
  throw new Error('Invalid recovery code');
}

// ── Key-agnostic wrapping (K_shared under the master DEK or K_pair) ──
// K_pair or the master DEK are both just 32-byte wrapping keys; wrapDEK is used
// verbatim. Bind a wrapped key to its context (dynamic id) with ./sealing's AAD
// helpers when you need the wrap to be non-transferable between contexts.

/**
 * Wrap raw key bytes under a base64 wrapping key. Thin alias over wrapDEK.
 * @returns {Promise<{ wrapped: string, nonce: string }>} base64
 */
export async function wrapKeyUnder(keyBytes, wrapKeyB64) {
  const wrapKey = await primitives.decodeBase64(wrapKeyB64);
  const { wrappedDek, nonce } = await wrapDEK(keyBytes, wrapKey);
  return { wrapped: wrappedDek, nonce };
}

/**
 * Unwrap key bytes wrapped under a base64 wrapping key.
 * @returns {Promise<Uint8Array>}
 * @throws if the wrapping key is wrong or the data was tampered
 */
export async function unwrapKeyUnder(wrappedB64, nonceB64, wrapKeyB64) {
  const wrapKey = await primitives.decodeBase64(wrapKeyB64);
  return unwrapDEK(wrappedB64, nonceB64, wrapKey);
}

/**
 * Sanitize a storage key to [A-Za-z0-9._-]. Device keychains (expo-secure-store)
 * reject other characters, so every composite-derived key passes through here.
 */
export function sanitizeStoreKey(key) {
  return key.replace(/[^A-Za-z0-9._-]/g, '-');
}

function dynSharedStoreKey(dynamicId) {
  return sanitizeStoreKey(`${STORE_KEY_DYN_SHARED_PREFIX}${dynamicId}`);
}

// ── Storage-bound vault (needs a KeyStore) ──

/**
 * Bind the storage-touching operations to an injected KeyStore. Everything that
 * reads/writes persistent secret slots (the session DEK, per-dynamic K_shared)
 * lives here; the pure crypto above needs no storage.
 * @param {import('./interfaces.js').KeyStore} keyStore
 */
export function createKeyVault(keyStore) {
  /** Store the session DEK (base64). */
  async function storeDEK(dekBase64) {
    await keyStore.setItem(STORE_KEY_DEK, dekBase64);
  }
  /** Load the session DEK (base64) or null. */
  async function loadDEK() {
    return keyStore.getItem(STORE_KEY_DEK);
  }
  /** Clear the session DEK. */
  async function clearDEK() {
    await keyStore.removeItem(STORE_KEY_DEK);
  }

  /** Wrap a raw key under the session master DEK. */
  async function wrapKeyToMaster(keyBytes) {
    const dekB64 = await loadDEK();
    if (!dekB64) throw new Error('No master DEK loaded');
    return wrapKeyUnder(keyBytes, dekB64);
  }
  /** Unwrap a key that was wrapped under the session master DEK. */
  async function unwrapKeyFromMaster(wrappedB64, nonceB64) {
    const dekB64 = await loadDEK();
    if (!dekB64) throw new Error('No master DEK loaded');
    return unwrapKeyUnder(wrappedB64, nonceB64, dekB64);
  }

  /** Store K_shared (base64) for a dynamic. */
  async function storeDynamicSharedKey(dynamicId, keyB64) {
    await keyStore.setItem(dynSharedStoreKey(dynamicId), keyB64);
  }
  /** Load K_shared (base64) for a dynamic, or null. */
  async function loadDynamicSharedKey(dynamicId) {
    return keyStore.getItem(dynSharedStoreKey(dynamicId));
  }
  /** Crypto-shred a dynamic's K_shared locally (delete its slot). */
  async function cryptoShredDynamic(dynamicId) {
    await keyStore.removeItem(dynSharedStoreKey(dynamicId));
  }
  /** Shred every supplied dynamic's local K_shared (keychains have no enumeration). */
  async function clearAllDynamicKeys(dynamicIds) {
    for (const id of dynamicIds || []) await cryptoShredDynamic(id);
  }

  return {
    storeDEK,
    loadDEK,
    clearDEK,
    wrapKeyToMaster,
    unwrapKeyFromMaster,
    storeDynamicSharedKey,
    loadDynamicSharedKey,
    cryptoShredDynamic,
    clearAllDynamicKeys,
  };
}
