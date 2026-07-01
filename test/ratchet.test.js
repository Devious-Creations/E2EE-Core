// ratchet.test.js — the relay symmetric-key double ratchet behaves as claimed.
//
// Two ratchets (Alice + Bob) share a base64 root key (K_pair) but each seeds its
// own send/recv chains from it, keyed by user id. We exercise: in-order
// round-trips, out-of-order (skipped-key) delivery, replay/duplicate handling,
// the forward-jump cap, and persistence of chain state across a fresh
// createRatchet() on the same KeyStore.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as P from '../src/primitives.js';
import { createRatchet, MAX_SKIP } from '../src/ratchet.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';

// Build a fresh pairing: one shared root key, two sorted participant ids, and a
// channel name in the 'relay:<idA>:<idB>' shape the ratchet parses.
async function pairing() {
  const root = await P.randomBytes(32);
  const sharedKey = await P.encodeBase64(root);
  const [idA, idB] = [await P.generateUUID(), await P.generateUUID()].sort();
  const channelName = `relay:${idA}:${idB}`;
  return {
    sharedKey,
    channelName,
    aliceSession: { sharedKey, channelName, selfId: idA },
    bobSession: { sharedKey, channelName, selfId: idB },
  };
}

test('in-order: encrypt/decrypt round-trips and counters increment', async () => {
  const { aliceSession, bobSession } = await pairing();
  const alice = createRatchet(createMemoryKeyStore());
  const bob = createRatchet(createMemoryKeyStore());

  for (let i = 0; i < 5; i++) {
    const envelope = { n: i, body: `message ${i} — héllo 世界` };
    const wire = await alice.ratchetEncrypt(envelope, aliceSession);
    assert.equal(wire.ctr, i, 'send counter advances by one per message');
    assert.equal(typeof wire.nonce, 'string');
    assert.equal(typeof wire.ciphertext, 'string');

    const got = await bob.ratchetDecrypt(wire, bobSession);
    assert.deepEqual(got, envelope);
  }
});

test('the ciphertext is real: a tampered wire fails to decrypt', async () => {
  const { aliceSession, bobSession } = await pairing();
  const alice = createRatchet(createMemoryKeyStore());
  const bob = createRatchet(createMemoryKeyStore());

  const wire = await alice.ratchetEncrypt({ secret: 42 }, aliceSession);
  const bytes = await P.decodeBase64(wire.ciphertext);
  bytes[0] ^= 0x01;
  const tampered = { ...wire, ciphertext: await P.encodeBase64(bytes) };
  await assert.rejects(() => bob.ratchetDecrypt(tampered, bobSession), /Decryption failed/);
});

test('out-of-order: a forward jump caches skipped keys, older counters decrypt from cache', async () => {
  const { aliceSession, bobSession } = await pairing();
  const alice = createRatchet(createMemoryKeyStore());
  const bob = createRatchet(createMemoryKeyStore());

  // Alice sends 0..3 in order; the network delivers them 0, 2, 1, 3.
  const wires = [];
  for (let i = 0; i < 4; i++) {
    wires.push(await alice.ratchetEncrypt({ n: i }, aliceSession));
  }

  assert.deepEqual(await bob.ratchetDecrypt(wires[0], bobSession), { n: 0 });
  // Skips 1: caches mk_1, advances recv.next to 3.
  assert.deepEqual(await bob.ratchetDecrypt(wires[2], bobSession), { n: 2 });
  // Delivered late: decrypts from the skipped-key cache.
  assert.deepEqual(await bob.ratchetDecrypt(wires[1], bobSession), { n: 1 });
  // Back in order at the head.
  assert.deepEqual(await bob.ratchetDecrypt(wires[3], bobSession), { n: 3 });
});

test('replay/duplicate: a re-delivered message is rejected (no key for old counter)', async () => {
  const { aliceSession, bobSession } = await pairing();
  const alice = createRatchet(createMemoryKeyStore());
  const bob = createRatchet(createMemoryKeyStore());

  // In-order message, then replayed: recv.next has advanced past it and no
  // skipped key was cached, so the duplicate is rejected.
  const w0 = await alice.ratchetEncrypt({ n: 0 }, aliceSession);
  assert.deepEqual(await bob.ratchetDecrypt(w0, bobSession), { n: 0 });
  await assert.rejects(
    () => bob.ratchetDecrypt(w0, bobSession),
    /no key for old counter/,
  );

  // A skipped message consumed from the cache is likewise single-use: the key
  // is deleted on use, so replaying it is rejected too.
  const w1 = await alice.ratchetEncrypt({ n: 1 }, aliceSession);
  const w2 = await alice.ratchetEncrypt({ n: 2 }, aliceSession);
  assert.deepEqual(await bob.ratchetDecrypt(w2, bobSession), { n: 2 }); // caches mk_1
  assert.deepEqual(await bob.ratchetDecrypt(w1, bobSession), { n: 1 }); // consumes mk_1
  await assert.rejects(
    () => bob.ratchetDecrypt(w1, bobSession),
    /no key for old counter/,
  );
});

test('forward-jump cap: a counter more than MAX_SKIP ahead is rejected', async () => {
  const { aliceSession, bobSession } = await pairing();
  const alice = createRatchet(createMemoryKeyStore());
  const bob = createRatchet(createMemoryKeyStore());

  // First real message so Bob's recv chain is established at next=0 (loadState
  // would init the same either way, but keep it explicit).
  const w0 = await alice.ratchetEncrypt({ n: 0 }, aliceSession);
  assert.deepEqual(await bob.ratchetDecrypt(w0, bobSession), { n: 0 });

  // Forge a wire whose counter is absurdly far ahead. It never authenticates,
  // but the too-far-ahead guard trips before any key derivation.
  const bogus = { ctr: 1 + MAX_SKIP + 1, nonce: w0.nonce, ciphertext: w0.ciphertext };
  await assert.rejects(() => bob.ratchetDecrypt(bogus, bobSession), /counter too far ahead/);
});

test('persistence: chain state survives a fresh createRatchet on the same KeyStore', async () => {
  const { aliceSession, bobSession } = await pairing();
  const aliceStore = createMemoryKeyStore();
  const bobStore = createMemoryKeyStore();
  const alice = createRatchet(aliceStore);

  const w0 = await alice.ratchetEncrypt({ n: 0 }, aliceSession);
  const w1 = await alice.ratchetEncrypt({ n: 1 }, aliceSession);

  // Bob decrypts the first message; recv.next advances to 1 and is persisted.
  const bob = createRatchet(bobStore);
  assert.deepEqual(await bob.ratchetDecrypt(w0, bobSession), { n: 0 });

  // A brand-new ratchet over the SAME KeyStore (empty in-memory cache) must
  // load the advanced recv state and continue the chain, not restart at 0.
  const bobReborn = createRatchet(bobStore);
  assert.deepEqual(await bobReborn.ratchetDecrypt(w1, bobSession), { n: 1 });

  // And it enforces the persisted counter: replaying message 0 is rejected.
  await assert.rejects(
    () => bobReborn.ratchetDecrypt(w0, bobSession),
    /no key for old counter/,
  );

  // Alice's send counter also persisted: a fresh sender continues at ctr 2.
  const aliceReborn = createRatchet(aliceStore);
  const w2 = await aliceReborn.ratchetEncrypt({ n: 2 }, aliceSession);
  assert.equal(w2.ctr, 2);
  assert.deepEqual(await bobReborn.ratchetDecrypt(w2, bobSession), { n: 2 });
});

test('clearRatchetState wipes both participant slots for a channel', async () => {
  const { aliceSession, bobSession, channelName } = await pairing();
  const store = createMemoryKeyStore();
  const alice = createRatchet(store);
  const bob = createRatchet(store);

  const w0 = await alice.ratchetEncrypt({ n: 0 }, aliceSession);
  await bob.ratchetDecrypt(w0, bobSession);

  // Wipe via a fresh instance so it must read/delete from the KeyStore itself.
  const janitor = createRatchet(store);
  await janitor.clearRatchetState(channelName);

  // After a wipe, both directions reinitialize from scratch: sender restarts
  // at ctr 0.
  const aliceReborn = createRatchet(store);
  const wFresh = await aliceReborn.ratchetEncrypt({ n: 'restart' }, aliceSession);
  assert.equal(wFresh.ctr, 0);
});
