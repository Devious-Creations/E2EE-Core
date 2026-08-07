// dynamicKeys.test.js — per-relationship K_shared provisioning + AAD binding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as V from '../src/keyVault.js';
import { createDynamicKeys } from '../src/dynamicKeys.js';
import * as P from '../src/primitives.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';
import { decryptDataWithKey } from '../src/sealing.js';

async function memberWithDEK() {
  const vault = V.createKeyVault(createMemoryKeyStore());
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  return vault;
}

test('creator + accepter end up with the SAME K_shared, each under their own DEK', async () => {
  const creatorVault = await memberWithDEK();
  const accepterVault = await memberWithDEK();
  const creator = createDynamicKeys(creatorVault);
  const accepter = createDynamicKeys(accepterVault);

  const kPair = await P.encodeBase64(await P.randomBytes(32)); // the X25519 pairing key
  const DYN = 'dyn-abc';

  const { delivery } = await creator.provisionDynamic(DYN, kPair);
  await accepter.acceptDynamicGrant(DYN, delivery, kPair);

  const kCreator = await creatorVault.loadDynamicSharedKey(DYN);
  const kAccepter = await accepterVault.loadDynamicSharedKey(DYN);
  assert.ok(kCreator);
  assert.equal(kCreator, kAccepter);
});

test('AAD binding: a delivery cannot be accepted under a DIFFERENT dynamic id', async () => {
  const creator = createDynamicKeys(await memberWithDEK());
  const accepter = createDynamicKeys(await memberWithDEK());
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  const { delivery } = await creator.provisionDynamic('dyn-real', kPair);
  await assert.rejects(
    () => accepter.acceptDynamicGrant('dyn-attacker-swap', delivery, kPair),
    /different dynamic/,
  );
});

test('a wrong K_pair cannot open the delivery', async () => {
  const creator = createDynamicKeys(await memberWithDEK());
  const accepter = createDynamicKeys(await memberWithDEK());
  const kPair = await P.encodeBase64(await P.randomBytes(32));
  const wrongPair = await P.encodeBase64(await P.randomBytes(32));

  const { delivery } = await creator.provisionDynamic('dyn-x', kPair);
  await assert.rejects(() => accepter.acceptDynamicGrant('dyn-x', delivery, wrongPair));
});

test('loadDynamicKeys rehydrates K_shared from the own grant after a local shred', async () => {
  const creatorVault = await memberWithDEK();
  const accepterVault = await memberWithDEK();
  const creator = createDynamicKeys(creatorVault);
  const accepter = createDynamicKeys(accepterVault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));
  const DYN = 'dyn-rehydrate';

  const { delivery } = await creator.provisionDynamic(DYN, kPair);
  const { ownGrant } = await accepter.acceptDynamicGrant(DYN, delivery, kPair);
  const original = await accepterVault.loadDynamicSharedKey(DYN);

  await accepter.shredDynamicLocal(DYN);
  assert.equal(await accepterVault.loadDynamicSharedKey(DYN), null);

  const rehydrated = await accepter.loadDynamicKeys(DYN, ownGrant);
  assert.equal(rehydrated, original);
  // and it's back in the local slot
  assert.equal(await accepterVault.loadDynamicSharedKey(DYN), original);

  // a grant for a different dynamic must not rehydrate this one
  await accepter.shredDynamicLocal(DYN);
  assert.equal(await accepter.loadDynamicKeys('dyn-mismatch', ownGrant), null);
});

test('onUnwrapFault observes a failed own-grant unwrap (and null is still returned)', async () => {
  const vault = await memberWithDEK();
  const faults = [];
  const dyn = createDynamicKeys(vault, { onUnwrapFault: (err) => faults.push(err) });

  const kPair = await P.encodeBase64(await P.randomBytes(32));
  const DYN = 'dyn-fault';
  const { ownGrant } = await dyn.provisionDynamic(DYN, kPair);

  // Fresh slot + a DIFFERENT master DEK → the own grant no longer unwraps.
  await vault.cryptoShredDynamic(DYN);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));

  assert.equal(await dyn.loadDynamicKeys(DYN, ownGrant), null);
  assert.equal(faults.length, 1);
  assert.ok(faults[0] instanceof Error);

  // A missing grant is NOT a fault — nothing to unwrap, nothing to observe.
  assert.equal(await dyn.loadDynamicKeys('dyn-absent'), null);
  assert.equal(faults.length, 1);

  // A throwing observer must never break the load path.
  const explosive = createDynamicKeys(vault, {
    onUnwrapFault: () => {
      throw new Error('observer bug');
    },
  });
  assert.equal(await explosive.loadDynamicKeys(DYN, ownGrant), null);
});

// board #416 — the DEK gate must run BEFORE any other key-material read/
// write, so a spurious SecureStore null (locked device, Android Keystore
// invalidation) can never leave a stray local slot, or unwrap/publish key
// material, ahead of the throw. NOTE: the old order already threw before
// storeDynamicSharedKey and before the return, so this is hardening (no
// key material produced when the DEK is absent), not a fix for a leak —
// see docs/subsystems/key-hierarchy.md.

test('provisionDynamic reads the DEK first and nothing else before throwing', async (t) => {
  const store = createMemoryKeyStore(); // no DEK stored -> keystore getItem resolves null
  const getSpy = t.mock.method(store, 'getItem');
  const vault = V.createKeyVault(store);
  const storeSharedSpy = t.mock.method(vault, 'storeDynamicSharedKey');
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  await assert.rejects(() => dyn.provisionDynamic('dyn-gate', kPair), /No master DEK loaded/);
  // The DEK read is the ONLY keystore read that happened, and it came first —
  // this proves the existing-key lookup (and, transitively, generation on a
  // miss) never ran. generateSharedKey itself is not observable through this
  // seam, so this is what the test can actually prove.
  assert.equal(getSpy.mock.callCount(), 1);
  assert.deepEqual(getSpy.mock.calls[0].arguments, ['cloud_dek']);
  assert.equal(storeSharedSpy.mock.callCount(), 0);
});

test('acceptDynamicGrant reads the DEK first and never unwraps or persists before throwing', async (t) => {
  const store = createMemoryKeyStore(); // no DEK stored -> keystore getItem resolves null
  const getSpy = t.mock.method(store, 'getItem');
  const vault = V.createKeyVault(store);
  const storeSharedSpy = t.mock.method(vault, 'storeDynamicSharedKey');
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));
  // If the delivery were unwrapped before the gate, this malformed blob would
  // surface a decrypt/base64 error instead of the DEK-gate error.
  const bogusDelivery = { wrapped: 'not-valid-base64!!', nonce: 'also-not-valid!!' };

  await assert.rejects(() => dyn.acceptDynamicGrant('dyn-gate', bogusDelivery, kPair), /No master DEK loaded/);
  // The DEK read is the ONLY keystore read that happened, and it came first.
  assert.equal(getSpy.mock.callCount(), 1);
  assert.deepEqual(getSpy.mock.calls[0].arguments, ['cloud_dek']);
  assert.equal(storeSharedSpy.mock.callCount(), 0);
});

// board #450 — a spurious null (or a differing value) on the K_shared slot
// read is not the same as "no key exists yet"; the DEK gate (#416) says
// nothing about that read. These pin: a slot-read rejection aborts before
// anything is minted, and the fresh-mint path proves retention by reading
// the slot back before it wraps/delivers anything.

/**
 * A memory-backed KeyStore whose getItem rejects for a chosen key (all other
 * keys behave normally) — models a keystore slot that is locked/invalidated
 * while the DEK slot itself is still readable.
 */
function keyStoreRejectingRead(rejectKey, message = 'keystore locked') {
  const inner = createMemoryKeyStore();
  return {
    async getItem(key) {
      if (key === rejectKey) throw new Error(message);
      return inner.getItem(key);
    },
    async setItem(key, value) {
      return inner.setItem(key, value);
    },
    async removeItem(key) {
      return inner.removeItem(key);
    },
  };
}

test('provisionDynamic: a rejecting K_shared slot read aborts before anything is minted', async (t) => {
  const DYN = 'dyn-read-reject';
  const failingStore = keyStoreRejectingRead(`dyn_shared_${DYN}`);
  const vault = V.createKeyVault(failingStore);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const setSpy = t.mock.method(failingStore, 'setItem'); // installed AFTER the DEK setup write
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  await assert.rejects(() => dyn.provisionDynamic(DYN, kPair), /keystore locked/);
  // Nothing was ever written — the slot-read rejection propagated before any
  // mint/store was attempted.
  assert.equal(setSpy.mock.callCount(), 0);
});

test('provisionDynamic fresh-mint: read-back happens after setItem, before resolving, and grants wrap the read-back value', async () => {
  const inner = createMemoryKeyStore();
  const calls = []; // combined, ordered log of every getItem/setItem call
  const store = {
    async getItem(key) {
      const value = await inner.getItem(key);
      calls.push({ op: 'get', key });
      return value;
    },
    async setItem(key, value) {
      await inner.setItem(key, value);
      calls.push({ op: 'set', key, value });
    },
    async removeItem(key) {
      return inner.removeItem(key);
    },
  };
  const vault = V.createKeyVault(store);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));
  const DYN = 'dyn-fresh-mint';
  calls.length = 0; // ignore the storeDEK setup call

  const { delivery } = await dyn.provisionDynamic(DYN, kPair);

  const dynKey = `dyn_shared_${DYN}`;
  const dynSlotOps = calls.filter((c) => c.key === dynKey);
  // Three reads of the dyn slot — the reuse-check miss, the pre-store
  // recheck that must AGREE with it (board #450 review), then the
  // post-store read-back — around exactly one write, in that order.
  assert.deepEqual(
    dynSlotOps.map((c) => c.op),
    ['get', 'get', 'set', 'get'],
  );

  const kShared = await vault.loadDynamicSharedKey(DYN);
  assert.equal(dynSlotOps[2].value, kShared); // what was stored is what was read back

  // The resolved delivery wraps the SAME key bytes the read-back returned.
  const opened = await decryptDataWithKey(delivery.wrapped, delivery.nonce, kPair);
  assert.equal(opened.k, kShared);
});

test('provisionDynamic fresh-mint: a null read-back (write silently lost) aborts with the named error', async (t) => {
  const store = createMemoryKeyStore();
  const vault = V.createKeyVault(store);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const DYN = 'dyn-lost-write';
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  const dynKey = `dyn_shared_${DYN}`;
  // Once storeDynamicSharedKey writes the fresh mint, silently drop it before
  // the read-back happens, modelling a write the keystore didn't retain.
  const realSetItem = store.setItem.bind(store);
  t.mock.method(store, 'setItem', async (key, value) => {
    await realSetItem(key, value);
    if (key === dynKey) await store.removeItem(key);
  });

  await assert.rejects(
    () => dyn.provisionDynamic(DYN, kPair),
    /keystore failed to retain K_shared — provisioning aborted/,
  );
  assert.equal(await vault.loadDynamicSharedKey(DYN), null);
});

test('provisionDynamic fresh-mint: a different read-back value aborts with the named error', async (t) => {
  const store = createMemoryKeyStore();
  const vault = V.createKeyVault(store);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const DYN = 'dyn-corrupted-write';
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  const dynKey = `dyn_shared_${DYN}`;
  const realSetItem = store.setItem.bind(store);
  t.mock.method(store, 'setItem', async (key, value) => {
    if (key === dynKey) {
      await realSetItem(key, 'a-completely-different-value');
      return;
    }
    await realSetItem(key, value);
  });

  await assert.rejects(
    () => dyn.provisionDynamic(DYN, kPair),
    /keystore failed to retain K_shared — provisioning aborted/,
  );
  // The corrupt write was shredded on abort — a retry re-mints instead of
  // REUSING the corrupt slot through the no-read-back reuse branch.
  assert.equal(await vault.loadDynamicSharedKey(DYN), null);
});

test('acceptDynamicGrant: a null read-back (write silently lost) aborts with the named error', async (t) => {
  const creatorVault = await memberWithDEK();
  const accepterStore = createMemoryKeyStore();
  const accepterVault = V.createKeyVault(accepterStore);
  await accepterVault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const creator = createDynamicKeys(creatorVault);
  const accepter = createDynamicKeys(accepterVault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));
  const DYN = 'dyn-accept-lost-write';

  const { delivery } = await creator.provisionDynamic(DYN, kPair);

  const dynKey = `dyn_shared_${DYN}`;
  const realSetItem = accepterStore.setItem.bind(accepterStore);
  t.mock.method(accepterStore, 'setItem', async (key, value) => {
    await realSetItem(key, value);
    if (key === dynKey) await accepterStore.removeItem(key);
  });

  await assert.rejects(
    () => accepter.acceptDynamicGrant(DYN, delivery, kPair),
    /keystore failed to retain K_shared — provisioning aborted/,
  );
  assert.equal(await accepterVault.loadDynamicSharedKey(DYN), null);
});

test('acceptDynamicGrant: a different read-back value aborts with the named error', async (t) => {
  const creatorVault = await memberWithDEK();
  const accepterStore = createMemoryKeyStore();
  const accepterVault = V.createKeyVault(accepterStore);
  await accepterVault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const creator = createDynamicKeys(creatorVault);
  const accepter = createDynamicKeys(accepterVault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));
  const DYN = 'dyn-accept-corrupted-write';

  const { delivery } = await creator.provisionDynamic(DYN, kPair);

  const dynKey = `dyn_shared_${DYN}`;
  const realSetItem = accepterStore.setItem.bind(accepterStore);
  t.mock.method(accepterStore, 'setItem', async (key, value) => {
    if (key === dynKey) {
      await realSetItem(key, 'a-completely-different-value');
      return;
    }
    await realSetItem(key, value);
  });

  await assert.rejects(
    () => accepter.acceptDynamicGrant(DYN, delivery, kPair),
    /keystore failed to retain K_shared — provisioning aborted/,
  );
  // Mirrors provisionDynamic: the corrupt write was shredded on abort so a
  // retry with the same delivery re-stores from clean.
  assert.equal(await accepterVault.loadDynamicSharedKey(DYN), null);
});

test('provisionDynamic: a transient spurious null on the reuse read cannot overwrite the real key', async (t) => {
  const inner = createMemoryKeyStore();
  const DYN = 'dyn-transient-lie';
  const dynKey = `dyn_shared_${DYN}`;
  // A contract-VIOLATING adapter: the first read of the K_shared slot answers
  // null while the slot really holds a key; every later read tells the truth.
  // This is the exact board-#450 trigger — the two-reads-must-agree guard is
  // the only thing standing between it and a divergent second mint.
  let lied = false;
  const store = {
    async getItem(key) {
      if (key === dynKey && !lied) {
        lied = true;
        return null;
      }
      return inner.getItem(key);
    },
    async setItem(key, value) {
      return inner.setItem(key, value);
    },
    async removeItem(key) {
      return inner.removeItem(key);
    },
  };
  const vault = V.createKeyVault(store);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const K_OLD = await P.encodeBase64(await P.randomBytes(32));
  await inner.setItem(dynKey, K_OLD);
  const setSpy = t.mock.method(store, 'setItem');
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  await assert.rejects(
    () => dyn.provisionDynamic(DYN, kPair),
    /keystore gave inconsistent answers for the K_shared slot — provisioning aborted/,
  );
  // The real key was neither overwritten nor shredded: the abort happened
  // BEFORE any write, and the deliberate no-shred on this abort path is what
  // preserved the value the first read lied about.
  assert.equal(setSpy.mock.callCount(), 0);
  assert.equal(await inner.getItem(dynKey), K_OLD);
});

test('provisionDynamic: an empty-string slot is treated as absent and healed by a fresh mint', async () => {
  const store = createMemoryKeyStore();
  const vault = V.createKeyVault(store);
  await vault.storeDEK(await P.encodeBase64(await V.generateDEK()));
  const DYN = 'dyn-empty-string-slot';
  await store.setItem(`dyn_shared_${DYN}`, '');
  const dyn = createDynamicKeys(vault);
  const kPair = await P.encodeBase64(await P.randomBytes(32));

  // '' is not a usable key; both pre-store reads agreeing on '' routes to the
  // mint path, which overwrites nothing of value. (Main's `??` would have
  // reused '' and failed later inside secretbox.)
  const { ownGrant, delivery } = await dyn.provisionDynamic(DYN, kPair);
  assert.ok(ownGrant && delivery);
  const healed = await vault.loadDynamicSharedKey(DYN);
  assert.ok(healed && healed !== '');
});
