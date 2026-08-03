// pairing.test.js — drive BOTH sides of the interactive pairing handshake
// (initiator + joiner) over a paired in-memory transport, in one process, and
// prove the security-relevant invariants:
//   - both ends derive the SAME 32-byte root key and the SAME 6-digit SAS;
//   - the SAS is stable and matches on both ends (this is the out-of-band value
//     the two humans compare — a mismatch would abort the pairing);
//   - after simulating the user confirming the matching SAS, the pairing is
//     stored and its root key is retrievable via getSharedKey.
//
// The transport here is the dumb, untrusted in-memory pipe — the whole point is
// that correctness comes from the handshake + SAS, not from the transport.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createPairing,
  buildRelayChannelName,
  PAIRING_WORDS,
  CONTESTED_ERROR,
  TAMPERED_ERROR,
  CONTESTED_CODE,
  TAMPERED_CODE,
} from '../src/pairing.js';
import { pairing as pairingNamespace } from '../src/index.js';
import { createMemoryTransportPair } from '../adapters/memoryTransport.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';
import * as primitives from '../src/primitives.js';

// Two distinct, well-formed v4 UUIDs (must satisfy the handshake's UUID_RE and
// differ — a party never pairs with its own id).
const UUID_A = '11111111-1111-4111-8111-111111111111';
const UUID_B = '22222222-2222-4222-8222-222222222222';
// A THIRD identity, used to simulate a second device answering the same code
// (the contested-path tests below).
const UUID_C = '33333333-3333-4333-8333-333333333333';

// Run one full handshake and return both resolved results plus the state logs.
async function runHandshake(code = 'WOLF-7392') {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const statesA = [];
  const statesB = [];

  // Let the joiner subscribe first, then start the initiator. This is one
  // realistic ordering (the joiner has the code entered and is waiting when the
  // initiator's broadcast arrives) and, because the in-memory transport does not
  // buffer, it avoids relying on the 2s retransmit to recover a first-message
  // drop — keeping the suite fast. The retransmit loop still covers the reverse
  // ordering in production; correctness does not depend on who starts first.
  const joinP = B.joinPairing(code, UUID_B, (s) => statesB.push(s));
  await new Promise((r) => setTimeout(r, 0)); // yield a macrotask so the joiner's handlers register
  const initP = A.initiatePairing(code, UUID_A, (s) => statesA.push(s));

  const [rB, rA] = await Promise.all([joinP, initP]);

  return { A, B, rA, rB, statesA, statesB };
}

test('handshake: both sides derive the same root key and SAS', async () => {
  const { rA, rB, statesA, statesB } = await runHandshake();

  assert.equal(rA.role, 'initiator');
  assert.equal(rB.role, 'joiner');

  // Each side locked onto the other's identity.
  assert.equal(rA.partnerId, UUID_B);
  assert.equal(rB.partnerId, UUID_A);

  // Same derived X25519 root key on both ends.
  assert.equal(rA.sharedKey, rB.sharedKey);

  // Same SAS, and it is a 6-digit string (the value the humans compare).
  assert.equal(rA.sas, rB.sas);
  assert.match(rA.sas, /^[0-9]{6}$/);

  // Both sides compute the same deterministic relay channel name.
  assert.equal(rA.channelName, rB.channelName);
  assert.equal(rA.channelName, buildRelayChannelName(UUID_A, UUID_B));

  // Progress callbacks fired the 'exchanging' state on both ends.
  assert.ok(statesA.includes('exchanging'));
  assert.ok(statesB.includes('exchanging'));
});

test('SAS: stable across independent handshakes and matched on both ends', async () => {
  // Different ephemeral keys each run ⇒ (almost certainly) a different SAS, but
  // the invariant we care about is that WITHIN a run both ends agree.
  for (let i = 0; i < 3; i++) {
    const { rA, rB } = await runHandshake();
    assert.equal(rA.sas, rB.sas, 'both ends must display the same SAS');
    assert.match(rA.sas, /^[0-9]{6}$/);
    assert.equal(rA.sharedKey, rB.sharedKey);
  }
});

test('confirm + store: a completed pairing is stored and retrievable via getSharedKey', async () => {
  const { A, B, rA, rB } = await runHandshake();

  // Out-of-band step: the users compare the SAS. It matches ⇒ each side confirms
  // by persisting the pairing (nothing was stored during the handshake itself).
  assert.equal(rA.sas, rB.sas);

  const idA = await A.storePairing(rA.partnerId, rA.sharedKey, rA.channelName);
  const idB = await B.storePairing(rB.partnerId, rB.sharedKey, rB.channelName);

  // The root key round-trips through each device's KeyStore.
  assert.equal(await A.getSharedKey(idA), rA.sharedKey);
  assert.equal(await B.getSharedKey(idB), rB.sharedKey);
  assert.equal(await A.getSharedKey(idA), await B.getSharedKey(idB));

  // getStoredPairing surfaces the active pairing with its partner + key.
  const storedA = await A.getStoredPairing();
  assert.deepEqual(
    { partnerId: storedA.partnerId, sharedKey: storedA.sharedKey, channelName: storedA.channelName },
    { partnerId: UUID_B, sharedKey: rA.sharedKey, channelName: rA.channelName },
  );

  const listA = await A.getStoredPairings();
  assert.equal(listA.length, 1);
  assert.equal(listA[0].partnerId, UUID_B);
  assert.equal(await A.getActivePartnerId(), idA);
});

test('store: re-pairing the same partner rotates the key in place (no duplicate)', async () => {
  const { A, rA } = await runHandshake();
  const id1 = await A.storePairing(rA.partnerId, rA.sharedKey, rA.channelName);

  // Second pairing with the same partner but a rotated key.
  const rotatedKey = await (await import('../src/primitives.js')).encodeBase64(
    await (await import('../src/primitives.js')).randomBytes(32),
  );
  const id2 = await A.storePairing(rA.partnerId, rotatedKey, rA.channelName);

  assert.equal(id1, id2, 'same partner ⇒ same pairing id, updated in place');
  assert.equal(await A.getSharedKey(id1), rotatedKey);
  const list = await A.getStoredPairings();
  assert.equal(list.length, 1, 'no duplicate entry for the same partner');
});

test('clearPairing + removePairing wipe the stored root key', async () => {
  const { A, rA } = await runHandshake();
  const id = await A.storePairing(rA.partnerId, rA.sharedKey, rA.channelName);

  await A.removePairing(id);
  assert.equal(await A.getSharedKey(id), null);
  assert.equal(await A.getStoredPairing(), null);

  // Store again then clear everything.
  const id2 = await A.storePairing(rA.partnerId, rA.sharedKey, rA.channelName);
  assert.equal(await A.getSharedKey(id2), rA.sharedKey);
  await A.clearPairing();
  assert.equal(await A.getSharedKey(id2), null);
  assert.deepEqual(await A.getStoredPairings(), []);
});

test('generatePairingCode: WORD-WORD-NNNN shape from the known word list', async () => {
  const { generatePairingCode } = createPairing({
    keyStore: createMemoryKeyStore(),
    transport: createMemoryTransportPair()[0],
  });
  for (let i = 0; i < 20; i++) {
    const code = await generatePairingCode();
    assert.match(code, /^[A-Z]{4}-[A-Z]{4}-[0-9]{4}$/);
    const [w1, w2] = code.split('-');
    assert.ok(PAIRING_WORDS.includes(w1));
    assert.ok(PAIRING_WORDS.includes(w2));
  }
});

test('createPairing: rejects a missing KeyStore; a Transport is only needed to handshake', async () => {
  assert.throws(() => createPairing({ transport: createMemoryTransportPair()[0] }), /KeyStore/);

  // Store-only controller: no transport, stored-pairing management still works…
  const storeOnly = createPairing({ keyStore: createMemoryKeyStore() });
  assert.deepEqual(await storeOnly.getStoredPairings(), []);
  const id = await storeOnly.storePairing('partner-1', 'a-root-key', 'relay:a:b');
  assert.equal(await storeOnly.getSharedKey(id), 'a-root-key');

  // …but attempting a handshake without a transport throws.
  await assert.rejects(() => storeOnly.initiatePairing('WOLF-0001', 'user-1', () => {}), /Transport/);
});

// ── Contested-path tests ──────────────────────────────────────────────────────
// The handshake locks to the first responding identity; ANY second identity
// (or a mismatching duplicate) aborts fatally — the `settled` flag it sets
// makes the handshake promise reject and ignore every subsequent message. These
// tests craft the extra/conflicting messages directly, the same way the
// "transport.onError fails an in-flight handshake immediately" test above
// manipulates the transport object directly, rather than running two
// cooperating controllers.
//
// createRawTransport (rather than createMemoryTransportPair) is used here on
// purpose: its `close()` is a no-op, so a probe message sent AFTER the
// handshake has already failed can only be blocked by the handshake's own
// `settled` guard, not by the transport tearing itself down. That is what
// proves the abort is fatal at the pairing.js level, not just "the pipe closed."
function createRawTransport() {
  const handlers = new Map();
  return {
    send() {}, // this file drives the handshake purely by injecting inbound messages
    on(event, handler) {
      if (!handlers.has(event)) handlers.set(event, new Set());
      handlers.get(event).add(handler);
    },
    close() {},
    // Directly deliver a crafted/duplicate message to the handshake's handler(s)
    // for `event`, simulating another device broadcasting on the same code.
    emit(event, payload) {
      const set = handlers.get(event);
      if (!set) return;
      for (const h of [...set]) h(payload);
    },
  };
}

// A base64 string that decodes to exactly 32 bytes — satisfies the handshake's
// decode32() shape check for a publicKey/commit/mac field without needing to
// correspond to any real key (the contested paths below fail before any such
// correspondence would be checked).
async function random32Base64() {
  return primitives.encodeBase64(await primitives.randomBytes(32));
}

test('contested: a second, different partner id after lock rejects fatally and blocks revival', async () => {
  const transport = createRawTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const states = [];
  const attempt = A.initiatePairing('WOLF-9001', UUID_A, (s) => states.push(s));
  const rejection = assert.rejects(() => attempt, /Pairing contested/);

  await new Promise((r) => setTimeout(r, 20)); // let the initiator register its handlers

  // First responder locks partnerId = UUID_B.
  transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });
  await new Promise((r) => setTimeout(r, 20)); // let deriveSession + the pair_reveal send settle

  // A second, different (but otherwise well-formed) device answers the same
  // code — contested.
  transport.emit('pair_response', { userId: UUID_C, publicKey: await random32Base64() });

  await rejection;
  const statesAtReject = states.length;

  // Fatal: a subsequent, well-formed message for the same handshake (even a
  // confirm from the ORIGINAL locked partner) must not revive it — no further
  // state progress, no second settlement, and (implicitly) no unhandled
  // rejection since the promise only ever settles once.
  const revivalMac = await random32Base64();
  assert.doesNotThrow(() => transport.emit('pair_confirm', { userId: UUID_B, mac: revivalMac }));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(states.length, statesAtReject, 'no further onStateChange after the fatal abort');
});

test('contested: a duplicate commit with a mismatched value rejects fatally', async () => {
  const transport = createRawTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const states = [];
  const attempt = B.joinPairing('WOLF-9002', UUID_B, (s) => states.push(s));
  const rejection = assert.rejects(() => attempt, /Pairing contested/);

  await new Promise((r) => setTimeout(r, 20)); // let the joiner register its handlers

  // First commit from the (locked) initiator identity.
  transport.emit('pair_commit', { userId: UUID_A, commit: await random32Base64() });
  await new Promise((r) => setTimeout(r, 20));

  // A second commit, same identity, but a DIFFERENT value — contested.
  transport.emit('pair_commit', { userId: UUID_A, commit: await random32Base64() });

  await rejection;
  const statesAtReject = states.length;

  // Fatal: a well-formed reveal for the same handshake does not revive it.
  const revivalKey = await random32Base64();
  assert.doesNotThrow(() =>
    transport.emit('pair_reveal', { userId: UUID_A, publicKey: revivalKey }),
  );
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(states.length, statesAtReject, 'no further onStateChange after the fatal abort');
});

test('contested: a duplicate response with a different public key rejects fatally', async () => {
  const transport = createRawTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const states = [];
  const attempt = A.initiatePairing('WOLF-9003', UUID_A, (s) => states.push(s));
  const rejection = assert.rejects(() => attempt, /Pairing contested/);

  await new Promise((r) => setTimeout(r, 20)); // let the initiator register its handlers

  // First response locks the partner id AND the partner public key.
  transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });
  await new Promise((r) => setTimeout(r, 20)); // let deriveSession settle

  // A duplicate response, same partner id, but a DIFFERENT public key —
  // contested (this is not the "missed our reveal, resend" case, which
  // requires the SAME key).
  transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });

  await rejection;
  const statesAtReject = states.length;

  // Fatal: a well-formed confirm for the same handshake does not revive it.
  const revivalMac = await random32Base64();
  assert.doesNotThrow(() => transport.emit('pair_confirm', { userId: UUID_B, mac: revivalMac }));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(states.length, statesAtReject, 'no further onStateChange after the fatal abort');
});

// ── Error codes (board #288) ──────────────────────────────────────────────────
// CONTESTED_ERROR and TAMPERED_ERROR are exported alongside a stable err.code
// (following the QR_COMMITMENT_MISMATCH precedent from #8/#9), so callers can
// branch on err.code instead of matching on message text. Message text itself
// is unchanged — these are additive assertions on top of the same abort paths
// the tripwire tests above already pin; they do not alter those tests.

test('CONTESTED_ERROR / TAMPERED_ERROR are exported and reachable via the package index', () => {
  assert.equal(typeof CONTESTED_ERROR, 'string');
  assert.equal(typeof TAMPERED_ERROR, 'string');
  assert.equal(typeof CONTESTED_CODE, 'string');
  assert.equal(typeof TAMPERED_CODE, 'string');
  assert.equal(pairingNamespace.CONTESTED_ERROR, CONTESTED_ERROR);
  assert.equal(pairingNamespace.TAMPERED_ERROR, TAMPERED_ERROR);
  assert.equal(pairingNamespace.CONTESTED_CODE, CONTESTED_CODE);
  assert.equal(pairingNamespace.TAMPERED_CODE, TAMPERED_CODE);
});

test('CONTESTED_CODE / TAMPERED_CODE are the literal machine-readable code constants', () => {
  // Pin the literal values (same style as
  // pairing.qrCommitment.test.js:464's QR_COMMITMENT_MISMATCH_CODE pin) — a
  // future accidental rename of the code string is exactly what callers
  // branching on err.code would silently break on.
  assert.equal(CONTESTED_CODE, 'CONTESTED');
  assert.equal(TAMPERED_CODE, 'TAMPERED');
});

test('CONTESTED_ERROR / TAMPERED_ERROR message prose is unchanged (this PR does not reword them)', () => {
  // This PR's central claim is that message text is untouched — only err.code
  // is new — so existing prose-matching consumers keep working until they
  // migrate. Pin the prose itself, not just its type, so a future edit that
  // rewords either message trips this test rather than silently breaking a
  // live consumer that still matches on message text.
  assert.match(CONTESTED_ERROR, /^Pairing contested — more than one device answered this code\./);
  assert.match(TAMPERED_ERROR, /^Pairing aborted — the key exchange failed verification\./);
});

test('contested: a second, different partner id rejects with err.code === CONTESTED_CODE', async () => {
  const transport = createRawTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const attempt = A.initiatePairing('WOLF-9004', UUID_A, () => {});
  const rejection = assert.rejects(
    () => attempt,
    (err) => err.message === CONTESTED_ERROR && err.code === CONTESTED_CODE,
  );

  await new Promise((r) => setTimeout(r, 20));
  transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });
  await new Promise((r) => setTimeout(r, 20));
  transport.emit('pair_response', { userId: UUID_C, publicKey: await random32Base64() });

  await rejection;
});

test('tampered: a malformed commit rejects with err.code === TAMPERED_CODE', async () => {
  const transport = createRawTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const attempt = B.joinPairing('WOLF-9005', UUID_B, () => {});
  const rejection = assert.rejects(
    () => attempt,
    (err) => err.message === TAMPERED_ERROR && err.code === TAMPERED_CODE,
  );

  await new Promise((r) => setTimeout(r, 20)); // let the joiner register its handlers

  // A commit that cannot decode to a 32-byte digest — malformed, not merely
  // contested.
  transport.emit('pair_commit', { userId: UUID_A, commit: 'not-a-valid-commitment' });

  await rejection;
});

test('transport.onError fails an in-flight handshake immediately', async () => {
  const [tA] = createMemoryTransportPair();
  let fireError;
  tA.onError = (handler) => {
    fireError = handler;
  };
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });

  // No partner ever answers; the error signal must reject long before the
  // 120s handshake timeout.
  const attempt = A.initiatePairing('WOLF-0002', 'user-a', () => {});
  const rejected = assert.rejects(() => attempt, /channel died/);
  // Give the handshake a beat to register the onError handler.
  await new Promise((r) => setTimeout(r, 20));
  fireError('channel died');
  await rejected;
});
