// keyVault.test.js — the master key hierarchy and per-dynamic key storage.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as V from '../src/keyVault.js';
import * as P from '../src/primitives.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';

test('DEK wrap/unwrap under a scrypt KEK round-trips; wrong password fails', async () => {
  const dek = await V.generateDEK();
  const salt = await P.randomBytes(32);
  const kek = await V.deriveKEK('hunter2', salt); // current KDF = scrypt
  const { wrappedDek, nonce } = await V.wrapDEK(dek, kek);

  const back = await V.unwrapDEK(wrappedDek, nonce, kek);
  assert.deepEqual(back, dek);

  const wrongKek = await V.deriveKEK('wrong', salt);
  await assert.rejects(() => V.unwrapDEK(wrappedDek, nonce, wrongKek));
});

test('recovery codes recover the DEK; a wrong code is rejected', async () => {
  const dek = await V.generateDEK();
  const codes = await V.generateRecoveryCodes(4);
  assert.equal(codes.length, 4);
  assert.match(codes[0], /^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/);

  const entries = await V.buildRecoveryEntries(dek, codes);
  const { dek: recovered, matchIndex } = await V.unwrapWithRecoveryCode(codes[2], entries);
  assert.deepEqual(recovered, dek);
  assert.equal(matchIndex, 2);

  await assert.rejects(() => V.unwrapWithRecoveryCode('ZZZZ-ZZZZ-ZZZZ', entries), /Invalid recovery code/);
});

test('buildRecoveryEntries: same code built twice yields different hash values (salt feeds the hash)', async () => {
  const dek = await V.generateDEK();
  const code = (await V.generateRecoveryCodes(1))[0];

  const [entry1] = await V.buildRecoveryEntries(dek, [code]);
  const [entry2] = await V.buildRecoveryEntries(dek, [code]);

  // Salts are random, so hashes must differ (collision probability ≈ 2^-256).
  assert.notEqual(entry1.hash, entry2.hash);
});

test('createKeyVault: DEK persistence + wrap-to-master round-trips', async () => {
  const vault = V.createKeyVault(createMemoryKeyStore());
  assert.equal(await vault.loadDEK(), null);

  const dekB64 = await P.encodeBase64(await V.generateDEK());
  await vault.storeDEK(dekB64);
  assert.equal(await vault.loadDEK(), dekB64);

  const key = await P.randomBytes(32);
  const { wrapped, nonce } = await vault.wrapKeyToMaster(key);
  const back = await vault.unwrapKeyFromMaster(wrapped, nonce);
  assert.deepEqual(back, key);

  await vault.clearDEK();
  assert.equal(await vault.loadDEK(), null);
  await assert.rejects(() => vault.wrapKeyToMaster(key), /No master DEK/);
});

test('createKeyVault: per-dynamic key store/load/shred', async () => {
  const vault = V.createKeyVault(createMemoryKeyStore());
  const kB64 = await P.encodeBase64(await V.generateSharedKey());

  await vault.storeDynamicSharedKey('dyn:1', kB64);
  assert.equal(await vault.loadDynamicSharedKey('dyn:1'), kB64);

  await vault.cryptoShredDynamic('dyn:1');
  assert.equal(await vault.loadDynamicSharedKey('dyn:1'), null);
});
