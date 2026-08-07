// dynamicKeys.test.js — per-relationship K_shared provisioning + AAD binding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as V from '../src/keyVault.js';
import { createDynamicKeys } from '../src/dynamicKeys.js';
import * as P from '../src/primitives.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';

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
