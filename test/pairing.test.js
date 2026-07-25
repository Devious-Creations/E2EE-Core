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

import { createPairing, buildRelayChannelName, PAIRING_WORDS } from '../src/pairing.js';
import { createMemoryTransportPair } from '../adapters/memoryTransport.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';

// Two distinct, well-formed v4 UUIDs (must satisfy the handshake's UUID_RE and
// differ — a party never pairs with its own id).
const UUID_A = '11111111-1111-4111-8111-111111111111';
const UUID_B = '22222222-2222-4222-8222-222222222222';

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
