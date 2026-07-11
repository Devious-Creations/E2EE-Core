// dynamicKeys.js — establish a per-relationship shared key (K_shared) between
// two paired members, with AAD binding.
//
// Faithful extraction of the app's `dynamicProvisioning.js`. The server-side
// grant CRUD (Supabase rows) is NOT here — this module is pure crypto over the
// injected KeyStore (via a keyVault) + ./sealing.
//
// Flow:
//   Creator (least-uid member): generate K_shared, store it locally, wrap it
//     under their master DEK (the at-rest "own grant"), and seal it under the
//     pairing key K_pair for a one-time delivery to the partner.
//   Accepter: open the delivery with K_pair, store K_shared locally, wrap it
//     under their OWN master DEK (their own grant).
//   Both members end up holding the SAME K_shared, each wrapped under their own
//   master DEK — so a dynamic shred (deleting both grants + local slots) makes
//   K_shared unrecoverable while each master DEK is untouched.
//
// AAD binding (secretbox has no AAD slot): a grant/delivery embeds its dynamicId
// in the AUTHENTICATED plaintext ({ d, k }), and unwrap REJECTS a blob whose
// bound id differs. Without this, a malicious server could swap a grant between
// two of a user's dynamics (both are under the same master DEK, so a swap would
// otherwise unwrap cleanly).

import { encryptDataWithKey, decryptDataWithKey } from './sealing.js';
import { generateSharedKey } from './keyVault.js';
import * as primitives from './primitives.js';

/** Wrap K_shared (base64) under wrapKey, binding it to its dynamicId. */
async function wrapSharedKey(dynamicId, kSharedB64, wrapKeyB64) {
  const { ciphertext, nonce } = await encryptDataWithKey({ d: dynamicId, k: kSharedB64 }, wrapKeyB64);
  return { wrapped: ciphertext, nonce };
}

/** Unwrap K_shared, REJECTING a blob bound to a different dynamicId. */
async function unwrapSharedKey(dynamicId, wrappedB64, nonceB64, wrapKeyB64) {
  const obj = await decryptDataWithKey(wrappedB64, nonceB64, wrapKeyB64);
  if (!obj || obj.d !== dynamicId || !obj.k) {
    throw new Error('grant/delivery is bound to a different dynamic');
  }
  return obj.k;
}

/**
 * Bind the provisioning flow to a keyVault (which owns the injected KeyStore).
 * @param {ReturnType<import('./keyVault.js').createKeyVault>} keyVault
 * @param {{ onUnwrapFault?: (err: Error) => void }} [opts] - onUnwrapFault is
 *   called when an own-grant unwrap fails during loadDynamicKeys (wrong key,
 *   tampered, or bound to a different dynamic). That failure silently makes the
 *   whole shared plane un-decryptable, so a consumer will usually want to
 *   surface it (telemetry lives in the consumer, never here).
 */
export function createDynamicKeys(keyVault, { onUnwrapFault } = {}) {
  /**
   * Creator side. Generates K_shared and returns the at-rest own grant (wrapped
   * under this member's master DEK) plus the one-time delivery (sealed under
   * K_pair). Both are bound to dynamicId. Re-running (re-pair) reuses an existing
   * local K_shared so the two members never diverge.
   * @param {string} dynamicId
   * @param {string} pairKeyB64 - K_pair (the X25519 pairing shared key), base64
   * @returns {Promise<{ ownGrant: {wrapped:string,nonce:string}, delivery: {wrapped:string,nonce:string} }>}
   */
  async function provisionDynamic(dynamicId, pairKeyB64) {
    const existingB64 = await keyVault.loadDynamicSharedKey(dynamicId);
    const kSharedB64 = existingB64 ?? (await primitives.encodeBase64(await generateSharedKey()));

    // Wrap BEFORE persisting the slot: a missing DEK must throw without leaving a
    // local key that has no recoverable cloud grant.
    const dekB64 = await keyVault.loadDEK();
    if (!dekB64) throw new Error('No master DEK loaded');

    const ownGrant = await wrapSharedKey(dynamicId, kSharedB64, dekB64);
    const delivery = await wrapSharedKey(dynamicId, kSharedB64, pairKeyB64);
    if (!existingB64) await keyVault.storeDynamicSharedKey(dynamicId, kSharedB64);

    return { ownGrant, delivery };
  }

  /**
   * Accepter side. Opens the creator's delivery with K_pair (rejecting a delivery
   * bound to a different dynamic), stores K_shared locally, and returns this
   * member's own grant (wrapped under their master DEK).
   * @param {string} dynamicId
   * @param {{ wrapped: string, nonce: string }} delivery
   * @param {string} pairKeyB64 - K_pair, base64
   * @returns {Promise<{ ownGrant: {wrapped:string,nonce:string} }>}
   * @throws if K_pair is wrong or the delivery is bound to a different dynamic
   */
  async function acceptDynamicGrant(dynamicId, delivery, pairKeyB64) {
    const kSharedB64 = await unwrapSharedKey(dynamicId, delivery.wrapped, delivery.nonce, pairKeyB64);

    // Wrap to the master DEK FIRST: a missing DEK must throw before we persist the
    // local slot, so the accepter never holds a local key with no cloud grant.
    const dekB64 = await keyVault.loadDEK();
    if (!dekB64) throw new Error('No master DEK loaded');
    const ownGrant = await wrapSharedKey(dynamicId, kSharedB64, dekB64);

    await keyVault.storeDynamicSharedKey(dynamicId, kSharedB64);
    return { ownGrant };
  }

  /**
   * Load K_shared (base64) for a dynamic, rehydrating from the own grant (wrapped
   * under the master DEK) when the local slot is empty — e.g. after recovery on a
   * fresh device, where the grant survives but the slot does not.
   * @param {string} dynamicId
   * @param {{ wrapped?:string, nonce?:string }} [ownGrant]
   * @returns {Promise<string|null>} K_shared base64, or null if unavailable
   */
  async function loadDynamicKeys(dynamicId, ownGrant) {
    const cached = await keyVault.loadDynamicSharedKey(dynamicId);
    if (cached) return cached;
    if (!ownGrant) return null;

    const wrapped = ownGrant.wrapped ?? ownGrant.shared_key_wrapped;
    const nonce = ownGrant.nonce ?? ownGrant.shared_key_nonce;
    if (!wrapped || !nonce) return null;

    const dekB64 = await keyVault.loadDEK();
    if (!dekB64) return null;

    let kSharedB64;
    try {
      kSharedB64 = await unwrapSharedKey(dynamicId, wrapped, nonce, dekB64);
    } catch (err) {
      // wrong key, tampered, or bound to a different dynamic
      try {
        onUnwrapFault?.(err);
      } catch {
        /* the observer must never break the load path */
      }
      return null;
    }
    await keyVault.storeDynamicSharedKey(dynamicId, kSharedB64);
    return kSharedB64;
  }

  /** Local crypto-shred for a dynamic — delete the K_shared slot. */
  async function shredDynamicLocal(dynamicId) {
    await keyVault.cryptoShredDynamic(dynamicId);
  }

  return { provisionDynamic, acceptDynamicGrant, loadDynamicKeys, shredDynamicLocal };
}
