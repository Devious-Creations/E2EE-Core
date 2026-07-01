// ratchet.js — a symmetric-key (hash) double ratchet over a pairing shared key.
//
// WHAT THIS IS
// A "double ratchet" normally means a Diffie–Hellman ratchet crossed with a
// symmetric-key (hashing) ratchet. This module is the symmetric-key half: it
// runs a forward hash chain per direction of a pairing so that each message
// gets a fresh, single-use key. There is no per-message DH step here — the DH
// contribution is folded in once, up front, as the pairing root key.
//
// ROOT KEY (K_pair)
// Two devices pair via an X25519 exchange + short-authentication-string check
// (elsewhere in this package) and end up holding a shared 32-byte root key,
// K_pair, passed in here base64-encoded as `session.sharedKey`. From that root
// each direction seeds its own chain key, keyed by the *sender's* user id so
// the two directions never collide:
//
//   ck_0(sender) = HMAC(K_pair, 'e2ee-core-relay-chain-v1|' + senderUserId)
//   mk_n         = HMAC(ck_n, 0x01)   — per-message key (XSalsa20-Poly1305)
//   ck_{n+1}     = HMAC(ck_n, 0x02)   — next chain key; ck_n is then discarded
//
// Because ck_n is discarded after each step, compromising a device's current
// chain state exposes only future traffic and the bounded skipped-key cache —
// not the message history (forward secrecy for the archive).
//
// OUT-OF-ORDER DELIVERY
// Handled Signal-style: a forward jump derives and caches the skipped message
// keys (bounded by MAX_SKIPPED_KEYS), and an older counter is decrypted from
// that cache. Receiver state is persisted ONLY after a successful decrypt, so
// garbage/forged counters cannot corrupt or advance the chain. Forward jumps
// are capped (MAX_SKIP) to bound CPU per message.
//
// PERSISTENCE
// Chain state persists through an INJECTED KeyStore (see ../src/interfaces.js):
// getItem/setItem/removeItem over opaque string values. In the app this is the
// device keychain via expo-secure-store; for tests/audit inject the in-memory
// adapter. This module is transport-agnostic: it operates on wire objects and
// counters and knows nothing about how ciphertext is shipped.
//
// This is a faithful extraction of the app's relayRatchet.js. The only changes
// are the two platform seams: the crypto wrapper (now ./primitives.js) and the
// secret storage (now the injected KeyStore). No ratchet math, key derivation,
// nonce handling, counter logic, or the MAX_SKIPPED_KEYS bound was altered.

import * as primitives from './primitives.js';

export const RATCHET_LABEL = 'e2ee-core-relay-chain-v1|';
export const MAX_SKIP = 2000; // max forward jump accepted in one message
// Cached out-of-order keys per channel. This cap must comfortably exceed the
// largest realistic reconnect backlog, because anything evicted here is a
// message that is then PERMANENTLY DROPPED:
//
//   On reconnect the live onMessage handler and fetchMissedMessages both
//   decrypt under the per-channel lock. If a fresh live broadcast wins the lock
//   before a large missed-message backlog has drained, ratchetDecrypt caches
//   the skipped keys, evicts down to this cap, and advances recv.next. The
//   still-unreplayed older backlog messages then arrive with ctr < recv.next
//   and no cached key, hitting "no key for old counter" and being dropped for
//   good.
//
// CR-78 shrank this to 64 to keep the serialized chain state small (the old
// 1000 could balloon it past Android SecureStore's ~2 KB value guidance), but
// 64 silently loses any reconnect backlog deeper than 64 messages. Restore a
// safe ~1000 cap: it spans a full server-side replay window with margin while
// still bounding state growth. Normal traffic holds ~0 skipped keys, so only
// pathological reordering ever approaches this size.
export const MAX_SKIPPED_KEYS = 1000;

const MK_INPUT = new Uint8Array([0x01]);
const CK_INPUT = new Uint8Array([0x02]);

// ── Storage key namespacing (pure) ──────────────────────────────────────────

function storageKey(selfId, channelName) {
  // Keyed by selfId too: each account's chain state is independent, and the
  // unit tests run both ends of a channel in one process.
  const raw = `relay_ratchet_${selfId}_${channelName}`;
  return raw.replace(/[^A-Za-z0-9._-]/g, '-');
}

// ── Crypto helpers (pure over ./primitives.js) ──────────────────────────────

async function hmac(keyBytes, msgBytes) {
  return primitives.hmacSha256(keyBytes, msgBytes);
}

async function fingerprint(sharedKeyB64) {
  const digest = await primitives.sha256Bytes(await primitives.decodeBase64(sharedKeyB64));
  return (await primitives.encodeBase64(digest)).slice(0, 16);
}

function partnerIdFromChannel(channelName, selfId) {
  // channelName = 'relay:<uuidA>:<uuidB>' (uuids sorted by buildRelayChannelName)
  const parts = String(channelName).split(':');
  if (parts.length !== 3) throw new Error('[ratchet] malformed channel name');
  const partner = parts[1] === selfId ? parts[2] : parts[1];
  if (partner === selfId || (parts[1] !== selfId && parts[2] !== selfId)) {
    throw new Error('[ratchet] selfId is not a participant of this channel');
  }
  return partner;
}

async function initState(sharedKeyB64, channelName, selfId) {
  const root = await primitives.decodeBase64(sharedKeyB64);
  const partnerId = partnerIdFromChannel(channelName, selfId);
  const enc = new TextEncoder();
  const sendCk = await hmac(root, enc.encode(RATCHET_LABEL + selfId));
  const recvCk = await hmac(root, enc.encode(RATCHET_LABEL + partnerId));
  return {
    fp: await fingerprint(sharedKeyB64),
    send: { ctr: 0, ck: await primitives.encodeBase64(sendCk) },
    recv: { next: 0, ck: await primitives.encodeBase64(recvCk), skipped: {} },
  };
}

async function stepChain(ckB64) {
  const ck = await primitives.decodeBase64(ckB64);
  const mk = await hmac(ck, MK_INPUT);
  const nextCk = await hmac(ck, CK_INPUT);
  return { mk, nextCk: await primitives.encodeBase64(nextCk) };
}

/**
 * Build a ratchet bound to a KeyStore. Each ratchet owns its own write-through
 * state cache and per-channel lock map (in the app these were process globals;
 * scoping them to the instance keeps two ratchets in one process — e.g. both
 * ends of a channel in a test — cleanly independent).
 *
 * @param {import('./interfaces.js').KeyStore} keyStore
 * @returns {{
 *   ratchetEncrypt: (envelope: object, session: object) => Promise<{ctr:number,nonce:string,ciphertext:string}>,
 *   ratchetDecrypt: (wire: object, session: object) => Promise<object>,
 *   clearRatchetState: (channelName: string) => Promise<void>,
 * }}
 */
export function createRatchet(keyStore) {
  if (!keyStore || typeof keyStore.getItem !== 'function') {
    throw new Error('[ratchet] createRatchet requires a KeyStore { getItem, setItem, removeItem }');
  }

  // Write-through cache of chain state per storage key. Two jobs:
  // 1. (CR-17) a transient KeyStore read failure must not be mistaken for
  //    "no state stored" — reinitializing would overwrite a live chain with
  //    ctr 0 and brick the channel until re-pair.
  // 2. (CR-78) every encrypt/decrypt — and each of up to 50 inner wires in a
  //    batch — used to pay a keystore round-trip deserializing the full state.
  //    All mutations go through writeState/deleteState (which keep this map
  //    current), so within this instance the cached copy is authoritative and
  //    reads only touch the keystore once per channel per launch.
  const _lastGood = new Map();

  async function readState(selfId, channelName) {
    const key = storageKey(selfId, channelName);
    const hot = _lastGood.get(key);
    if (hot) return hot;

    let raw;
    try {
      raw = await keyStore.getItem(key);
    } catch (err) {
      // Transient read failure with an empty cache — fail this operation.
      // Never report "no state" here.
      throw new Error(`[ratchet] chain state read failed: ${err.message}`);
    }
    if (!raw) return null;
    try {
      const state = JSON.parse(raw);
      _lastGood.set(key, state);
      return state;
    } catch {
      // Corrupt blob: the chain keys are unrecoverable either way. Delete it
      // and fail this operation; the next one reinitializes fresh chains
      // explicitly instead of silently mid-operation.
      try {
        await deleteState(selfId, channelName);
      } catch {
        /* best effort */
      }
      throw new Error('[ratchet] stored chain state was corrupted — channel state reset');
    }
  }

  async function writeState(selfId, channelName, state) {
    const key = storageKey(selfId, channelName);
    const raw = JSON.stringify(state);
    await keyStore.setItem(key, raw);
    // Cache only after the persist succeeded — callers abort on write failure.
    _lastGood.set(key, state);
  }

  async function deleteState(selfId, channelName) {
    const key = storageKey(selfId, channelName);
    _lastGood.delete(key);
    await keyStore.removeItem(key);
  }

  // Load the chain state; (re)initialize when absent or when the pairing key
  // changed (re-pair with the same partner rotates the root → fresh chains).
  async function loadState(session) {
    const { sharedKey, channelName, selfId } = session;
    const stored = await readState(selfId, channelName);
    const fp = await fingerprint(sharedKey);
    if (stored && stored.fp === fp) return stored;
    return initState(sharedKey, channelName, selfId);
  }

  // ── Per-channel async lock (serialize read-modify-write of chain state) ──
  const _locks = new Map();

  function withLock(lockKey, fn) {
    const prev = _locks.get(lockKey) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    _locks.set(
      lockKey,
      next.catch(() => {}),
    );
    return next;
  }

  /**
   * Encrypt an envelope under the next key of our sending chain.
   * The advanced chain state is persisted BEFORE returning, so a message key is
   * never reused even if the send itself fails afterwards.
   * @param {Object} envelope - JSON-serializable plaintext
   * @param {{ sharedKey: string, channelName: string, selfId: string }} session
   * @returns {Promise<{ ctr: number, nonce: string, ciphertext: string }>}
   */
  async function ratchetEncrypt(envelope, session) {
    return withLock(storageKey(session.selfId, session.channelName), async () => {
      const state = await loadState(session);
      const ctr = state.send.ctr;
      const { mk, nextCk } = await stepChain(state.send.ck);

      await writeState(session.selfId, session.channelName, {
        ...state,
        send: { ctr: ctr + 1, ck: nextCk },
      });

      const plainBytes = await primitives.encodeUTF8(JSON.stringify(envelope));
      const { nonce, ciphertext } = await primitives.encryptSecretbox(plainBytes, mk);
      return {
        ctr,
        nonce: await primitives.encodeBase64(nonce),
        ciphertext: await primitives.encodeBase64(ciphertext),
      };
    });
  }

  /**
   * Decrypt a wire message with the partner's chain.
   * Handles forward jumps (caches skipped keys) and out-of-order arrivals
   * (consumes cached keys). State is persisted only after a successful decrypt.
   * @param {{ ctr: number, nonce: string, ciphertext: string }} wire
   * @param {{ sharedKey: string, channelName: string, selfId: string }} session
   * @returns {Promise<Object>} decrypted envelope
   * @throws {Error} bad counter, missing skipped key, or failed decrypt
   */
  async function ratchetDecrypt(wire, session) {
    return withLock(storageKey(session.selfId, session.channelName), async () => {
      if (!Number.isInteger(wire.ctr) || wire.ctr < 0) {
        throw new Error('[ratchet] missing or invalid message counter');
      }
      const state = await loadState(session);
      const nonceBytes = await primitives.decodeBase64(wire.nonce);
      const cipherBytes = await primitives.decodeBase64(wire.ciphertext);

      // Older than the chain head: only a cached skipped key can decrypt it.
      if (wire.ctr < state.recv.next) {
        const mkB64 = state.recv.skipped[wire.ctr];
        if (!mkB64) {
          throw new Error('[ratchet] no key for old counter (duplicate or expired)');
        }
        const plain = await primitives.decryptSecretbox(
          cipherBytes,
          nonceBytes,
          await primitives.decodeBase64(mkB64),
        );
        const { [wire.ctr]: _used, ...rest } = state.recv.skipped;
        await writeState(session.selfId, session.channelName, {
          ...state,
          recv: { ...state.recv, skipped: rest },
        });
        return JSON.parse(await primitives.decodeUTF8(plain));
      }

      if (wire.ctr - state.recv.next > MAX_SKIP) {
        throw new Error('[ratchet] counter too far ahead');
      }

      // Walk the chain forward in memory; nothing is committed until the
      // message authenticates, so junk counters cannot poison the state.
      let ck = state.recv.ck;
      const skipped = { ...state.recv.skipped };
      for (let i = state.recv.next; i < wire.ctr; i++) {
        const step = await stepChain(ck);
        skipped[i] = await primitives.encodeBase64(step.mk);
        ck = step.nextCk;
      }
      const { mk, nextCk } = await stepChain(ck);
      const plain = await primitives.decryptSecretbox(cipherBytes, nonceBytes, mk); // throws on tamper

      // Bound the skipped cache (evict oldest counters first).
      const keys = Object.keys(skipped)
        .map(Number)
        .sort((a, b) => a - b);
      while (keys.length > MAX_SKIPPED_KEYS) {
        delete skipped[keys.shift()];
      }

      await writeState(session.selfId, session.channelName, {
        ...state,
        recv: { next: wire.ctr + 1, ck: nextCk, skipped },
      });
      return JSON.parse(await primitives.decodeUTF8(plain));
    });
  }

  /**
   * Wipe the chain state for a channel (unpair / sign-out).
   * The channel name carries both participant ids and only one has state on
   * this device — both candidate slots are deleted so callers don't need to
   * know which side they are.
   * @param {string} channelName
   */
  async function clearRatchetState(channelName) {
    const parts = String(channelName).split(':');
    for (const id of parts.slice(1)) {
      await deleteState(id, channelName);
    }
  }

  return { ratchetEncrypt, ratchetDecrypt, clearRatchetState };
}
