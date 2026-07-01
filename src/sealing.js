// sealing.js — authenticated encryption of app data under a 32-byte key.
//
// Extracted from the app's `cloudEncryption.js` (JSON-object sealing under the
// master DEK) and the pure crypto of `proofStorage.js` (raw-blob sealing under a
// per-relationship K_shared). Everything here is PURE: you pass the key in as
// base64, so there is no storage or network dependency. The app's Supabase
// Storage upload/download and FileSystem I/O are deliberately NOT part of this
// package — this module only produces and consumes the sealed bytes.
//
// All sealing is XSalsa20-Poly1305 (NaCl secretbox): a fresh random 24-byte
// nonce per message, authenticated ciphertext (open() throws on any tampering
// or wrong key). secretbox has no associated-data slot; when you need to bind a
// ciphertext to a context (e.g. a relationship id), put the context INSIDE the
// authenticated plaintext and check it on open — see ./dynamicKeys, which does
// exactly this for K_shared grants.

import * as primitives from './primitives.js';

const NONCE_LEN = 24; // nacl.secretbox nonce length

// ── JSON object under a key (wire form: base64 ciphertext + base64 nonce) ──

/**
 * Seal a JSON-serialisable object under a base64 key.
 * @param {object} plaintextObj
 * @param {string} keyBase64 - 32-byte key, base64
 * @returns {Promise<{ ciphertext: string, nonce: string }>} base64 wire format
 */
export async function encryptDataWithKey(plaintextObj, keyBase64) {
  const plainBytes = await primitives.encodeUTF8(JSON.stringify(plaintextObj));
  const keyBytes = await primitives.decodeBase64(keyBase64);
  const { nonce, ciphertext } = await primitives.encryptSecretbox(plainBytes, keyBytes);
  return {
    ciphertext: await primitives.encodeBase64(ciphertext),
    nonce: await primitives.encodeBase64(nonce),
  };
}

/**
 * Open a sealed JSON object under a base64 key.
 * @param {string} ciphertextB64
 * @param {string} nonceB64
 * @param {string} keyBase64
 * @returns {Promise<object>} the parsed object
 * @throws {Error} if decryption or JSON parsing fails
 */
export async function decryptDataWithKey(ciphertextB64, nonceB64, keyBase64) {
  const cipherBytes = await primitives.decodeBase64(ciphertextB64);
  const nonceBytes = await primitives.decodeBase64(nonceB64);
  const keyBytes = await primitives.decodeBase64(keyBase64);
  const plainBytes = await primitives.decryptSecretbox(cipherBytes, nonceBytes, keyBytes);
  return JSON.parse(await primitives.decodeUTF8(plainBytes));
}

// ── Raw blob under a key (wire form: self-contained nonce || ciphertext) ──

/**
 * Seal raw bytes (given as base64) under a base64 key into a self-contained
 * `nonce || ciphertext` byte array (e.g. an encrypted image for object storage).
 * @param {string} dataB64
 * @param {string} keyB64
 * @returns {Promise<Uint8Array>}
 */
export async function sealBytes(dataB64, keyB64) {
  const dataBytes = await primitives.decodeBase64(dataB64);
  const keyBytes = await primitives.decodeBase64(keyB64);
  const { nonce, ciphertext } = await primitives.encryptSecretbox(dataBytes, keyBytes);
  const sealed = new Uint8Array(nonce.length + ciphertext.length);
  sealed.set(nonce, 0);
  sealed.set(ciphertext, nonce.length);
  return sealed;
}

/**
 * Open a self-contained sealed blob (base64 of `nonce || ciphertext`) under a
 * base64 key, returning the plaintext bytes as base64. Throws on a wrong key or
 * tampered blob.
 * @param {string} sealedB64
 * @param {string} keyB64
 * @returns {Promise<string>}
 */
export async function openBytes(sealedB64, keyB64) {
  const sealed = await primitives.decodeBase64(sealedB64);
  const keyBytes = await primitives.decodeBase64(keyB64);
  const nonce = sealed.slice(0, NONCE_LEN);
  const ciphertext = sealed.slice(NONCE_LEN);
  const dataBytes = await primitives.decryptSecretbox(ciphertext, nonce, keyBytes);
  return primitives.encodeBase64(dataBytes);
}
