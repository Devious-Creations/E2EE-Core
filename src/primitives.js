// primitives.js — the platform-agnostic crypto wrapper.
//
// This is a faithful extraction of the app's `cryptoUtils.js`. The ONLY change
// from the shipped code is the PRNG bootstrap: the app wires a React-Native /
// Expo fallback for `tweetnacl`'s CSPRNG; here we rely on `globalThis.crypto`
// (present in Node >=20 and every browser). No behaviour of the algorithms
// themselves changed.
//
// Everything is a thin wrapper over audited libraries — no home-rolled
// primitives:
//   - tweetnacl        : XSalsa20-Poly1305 secretbox, X25519 box (key agreement)
//   - tweetnacl-util   : base64 / utf-8 codecs
//   - @noble/hashes    : scrypt, PBKDF2, SHA-256, HMAC-SHA256
//
// Libraries are lazy-imported so a consumer that only needs, say, hashing never
// pays to load secretbox — and so the app can keep the same tree-shaking it has
// today when it depends on this package.

let _nacl = null;
let _util = null;

async function getNacl() {
  if (!_nacl) {
    const mod = await import('tweetnacl');
    _nacl = mod.default || mod;

    // tweetnacl checks a CSPRNG at first use. In Node >=20 and browsers,
    // `globalThis.crypto.getRandomValues` exists; wire it in if tweetnacl's
    // built-in probe fails (it won't on a modern Node, but this keeps the
    // wrapper honest on exotic runtimes).
    try {
      _nacl.randomBytes(1);
    } catch {
      if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
        _nacl.setPRNG((x, n) => {
          const arr = new Uint8Array(n);
          globalThis.crypto.getRandomValues(arr);
          for (let i = 0; i < n; i++) x[i] = arr[i];
        });
      } else {
        throw new Error('No CSPRNG available: globalThis.crypto.getRandomValues is required');
      }
    }
  }
  return _nacl;
}

async function getUtil() {
  if (!_util) {
    const mod = await import('tweetnacl-util');
    _util = mod.default || mod; // tweetnacl-util is CJS; its exports sit on .default under ESM
  }
  return _util;
}

/**
 * Generate an X25519 keypair.
 * @returns {Promise<{ publicKey: Uint8Array, secretKey: Uint8Array }>}
 */
export async function generateKeypair() {
  const nacl = await getNacl();
  return nacl.box.keyPair();
}

/**
 * Derive a shared key from the partner's public key and our secret key.
 * Uses X25519 + HSalsa20 (nacl.box.before).
 * @param {Uint8Array} theirPublicKey
 * @param {Uint8Array} mySecretKey
 * @returns {Promise<Uint8Array>} 32-byte shared key
 */
export async function deriveSharedKey(theirPublicKey, mySecretKey) {
  const nacl = await getNacl();
  return nacl.box.before(theirPublicKey, mySecretKey);
}

/**
 * Encrypt with XSalsa20-Poly1305 (secretbox). Generates a random nonce.
 * @param {Uint8Array} plainBytes
 * @param {Uint8Array} keyBytes - 32-byte shared key
 * @returns {Promise<{ nonce: Uint8Array, ciphertext: Uint8Array }>}
 */
export async function encryptSecretbox(plainBytes, keyBytes) {
  const nacl = await getNacl();
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const ciphertext = nacl.secretbox(plainBytes, nonce, keyBytes);
  return { nonce, ciphertext };
}

/**
 * Decrypt with XSalsa20-Poly1305 (secretbox.open).
 * @param {Uint8Array} cipherBytes
 * @param {Uint8Array} nonceBytes
 * @param {Uint8Array} keyBytes - 32-byte shared key
 * @returns {Promise<Uint8Array>} plaintext bytes
 * @throws {Error} if decryption fails (tampered or wrong key)
 */
export async function decryptSecretbox(cipherBytes, nonceBytes, keyBytes) {
  const nacl = await getNacl();
  const result = nacl.secretbox.open(cipherBytes, nonceBytes, keyBytes);
  if (!result) throw new Error('Decryption failed — invalid key or tampered message');
  return result;
}

/**
 * Generate cryptographically random bytes.
 * @param {number} n
 * @returns {Promise<Uint8Array>}
 */
export async function randomBytes(n) {
  const nacl = await getNacl();
  return nacl.randomBytes(n);
}

/**
 * Generate a UUID v4 from random bytes.
 * @returns {Promise<string>}
 */
export async function generateUUID() {
  const bytes = await randomBytes(16);
  // Set version (4) and variant (10xx) bits per RFC 4122
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Encode Uint8Array to base64 string.
 * @param {Uint8Array} arr
 * @returns {Promise<string>}
 */
export async function encodeBase64(arr) {
  const util = await getUtil();
  return util.encodeBase64(arr);
}

/**
 * Decode base64 string to Uint8Array.
 * @param {string} str
 * @returns {Promise<Uint8Array>}
 */
export async function decodeBase64(str) {
  const util = await getUtil();
  return util.decodeBase64(str);
}

/**
 * Encode string to Uint8Array (UTF-8).
 * @param {string} str
 * @returns {Promise<Uint8Array>}
 */
export async function encodeUTF8(str) {
  const util = await getUtil();
  return util.decodeUTF8(str); // tweetnacl-util: decodeUTF8 = string → Uint8Array
}

/**
 * Decode Uint8Array to string (UTF-8).
 * @param {Uint8Array} arr
 * @returns {Promise<string>}
 */
export async function decodeUTF8(arr) {
  const util = await getUtil();
  return util.encodeUTF8(arr); // tweetnacl-util: encodeUTF8 = Uint8Array → string
}

/**
 * SHA-256 digest.
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>} 32-byte digest
 */
export async function sha256Bytes(bytes) {
  const { sha256 } = await import('@noble/hashes/sha2.js');
  return sha256(bytes);
}

/**
 * HMAC-SHA256.
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} messageBytes
 * @returns {Promise<Uint8Array>} 32-byte tag
 */
export async function hmacSha256(keyBytes, messageBytes) {
  const { hmac } = await import('@noble/hashes/hmac.js');
  const { sha256 } = await import('@noble/hashes/sha2.js');
  return hmac(sha256, keyBytes, messageBytes);
}

/**
 * Constant-time byte array comparison (for MAC/commitment verification).
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Uniform random integer in [0, maxExclusive) via rejection sampling —
 * plain modulo over random bytes biases the low values.
 * @param {number} maxExclusive - must be <= 65536
 * @returns {Promise<number>}
 */
export async function randomInt(maxExclusive) {
  if (!Number.isInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 65536) {
    throw new Error('randomInt: maxExclusive must be an integer in [1, 65536]');
  }
  const limit = Math.floor(65536 / maxExclusive) * maxExclusive;
  for (;;) {
    const b = await randomBytes(2);
    const v = (b[0] << 8) | b[1];
    if (v < limit) return v % maxExclusive;
  }
}

/**
 * Derive a key from a password and salt using PBKDF2-SHA256.
 * @param {string|Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} iterations - e.g. 100_000
 * @param {number} keyLength - output length in bytes, e.g. 32
 * @returns {Promise<Uint8Array>}
 */
export async function pbkdf2(password, salt, iterations, keyLength) {
  const { pbkdf2: _pbkdf2 } = await import('@noble/hashes/pbkdf2.js');
  const { sha256 } = await import('@noble/hashes/sha2.js');
  return _pbkdf2(sha256, password, salt, { c: iterations, dkLen: keyLength });
}

/**
 * Derive a key from a password and salt using scrypt (memory-hard, so GPU/ASIC
 * offline brute force can't be parallelized cheaply the way PBKDF2 can).
 *
 * Uses @noble/hashes' ASYNC scrypt (chunked with event-loop yields) rather
 * than the sync one — on React Native the sync version blocks the JS thread
 * for 10-40s at these params, freezing the app. Same algorithm, same output.
 * @param {string|Uint8Array} password
 * @param {Uint8Array} salt
 * @param {{ N: number, r: number, p: number, dkLen: number }} params
 * @param {(fraction: number) => void} [onProgress] - optional, called with a
 *   value in (0, 1] as the derivation progresses.
 * @returns {Promise<Uint8Array>}
 */
export async function scrypt(password, salt, { N, r, p, dkLen }, onProgress) {
  const { scryptAsync: _scryptAsync } = await import('@noble/hashes/scrypt.js');
  return _scryptAsync(password, salt, { N, r, p, dkLen, onProgress });
}
