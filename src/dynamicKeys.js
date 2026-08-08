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
    // Gate on the master DEK FIRST, before any key is loaded, generated, or
    // wrapped. The old order still threw before storeDynamicSharedKey/return,
    // so a doomed call never persisted, returned, or delivered anything — but
    // it would still read the local slot and (on a miss) generate 32 bytes of
    // key material that could never be used. Gating first means no key
    // material is produced at all when the DEK is absent (board #416).
    const dekB64 = await keyVault.loadDEK();
    if (!dekB64) throw new Error('No master DEK loaded');

    // A rejection here (locked keystore, invalidated key, platform error —
    // see the KeyStore contract in interfaces.js) propagates and aborts
    // BEFORE anything is minted. A `null` resolution, by contrast, is the
    // slot's truthful "nothing stored yet" answer.
    const existingB64 = await keyVault.loadDynamicSharedKey(dynamicId);

    let kSharedB64;
    if (existingB64) {
      kSharedB64 = existingB64;
    } else {
      // Fresh mint: store first, then read the slot back and require it
      // returns exactly what was just stored. A key the device cannot prove
      // it retains must never be wrapped for the partner (board #450) — a
      // spurious null (or a stale different value) on this read used to be
      // indistinguishable from "no key exists yet" and would mint a second,
      // divergent K_shared for the same dynamic.
      const minted = await primitives.encodeBase64(await generateSharedKey());
      // Re-read the slot before overwriting it (board #450, review finding 1):
      // the reuse-check read above may have answered a spurious null from a
      // contract-violating adapter, and store-then-read-back cannot catch that
      // case — the store would overwrite the partner-shared key and destroy
      // the only evidence of the lie. Minting therefore requires TWO reads
      // that agree the slot is empty; a transient lie fails the second read.
      // Deliberately NO shred on this abort: a differing answer here may BE
      // the real key the first read lied about.
      const recheck = await keyVault.loadDynamicSharedKey(dynamicId);
      if (recheck !== existingB64) {
        throw new Error(
          'keystore gave inconsistent answers for the K_shared slot — provisioning aborted',
        );
      }
      await keyVault.storeDynamicSharedKey(dynamicId, minted);
      const readBack = await keyVault.loadDynamicSharedKey(dynamicId);
      if (readBack !== minted) {
        // The slot now holds our own failed/corrupt write; clear it so a
        // retry re-mints instead of REUSING the corrupt value through the
        // no-read-back reuse branch above. Best-effort: the shred rides the
        // same unreliable adapter that just failed. (Reaching here with the
        // slot holding a REAL key would need the adapter to lie twice and
        // then fail the store — at that point nothing it answers is
        // trustworthy anyway; the recheck above is the guard for the
        // one-transient-lie case.)
        try {
          await keyVault.cryptoShredDynamic(dynamicId);
        } catch {
          /* the throw below already reports the failure */
        }
        throw new Error('keystore failed to retain K_shared — provisioning aborted');
      }
      kSharedB64 = readBack;
    }

    const ownGrant = await wrapSharedKey(dynamicId, kSharedB64, dekB64);
    const delivery = await wrapSharedKey(dynamicId, kSharedB64, pairKeyB64);

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
    // Gate on the master DEK FIRST, before the delivery is even unwrapped.
    // The old order still threw before storeDynamicSharedKey/return, so a
    // doomed call never persisted or returned anything — but it would still
    // unwrap the delivered key material for no reason. Gating first means no
    // key material is unwrapped at all when the DEK is absent (board #416 —
    // see the matching gate in provisionDynamic).
    const dekB64 = await keyVault.loadDEK();
    if (!dekB64) throw new Error('No master DEK loaded');

    let kSharedB64 = await unwrapSharedKey(dynamicId, delivery.wrapped, delivery.nonce, pairKeyB64);

    // Same store-then-read-back invariant as the fresh-mint path in
    // provisionDynamic: never report acceptance success for a key the
    // keystore can't prove it retained.
    await keyVault.storeDynamicSharedKey(dynamicId, kSharedB64);
    const readBack = await keyVault.loadDynamicSharedKey(dynamicId);
    if (readBack !== kSharedB64) {
      // Clear our own failed write so a retry (same delivery) re-stores
      // rather than reusing a corrupt slot — mirrors provisionDynamic.
      try {
        await keyVault.cryptoShredDynamic(dynamicId);
      } catch {
        /* the throw below already reports the failure */
      }
      throw new Error('keystore failed to retain K_shared — provisioning aborted');
    }
    // Wrap the VERIFIED value, mirroring provisionDynamic — keeps the guard
    // and the wrap coupled to the same variable in both sites.
    kSharedB64 = readBack;

    const ownGrant = await wrapSharedKey(dynamicId, kSharedB64, dekB64);
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
