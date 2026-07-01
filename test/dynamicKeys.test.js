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
