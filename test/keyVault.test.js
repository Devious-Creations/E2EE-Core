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

test('assertValidRecoveryKeys: valid list passes', async () => {
  const dek = await V.generateDEK();
  const codes = await V.generateRecoveryCodes(2);
  const entries = await V.buildRecoveryEntries(dek, codes);
  assert.doesNotThrow(() => V.assertValidRecoveryKeys(entries));
});

test('assertValidRecoveryKeys: non-array is rejected', () => {
  assert.throws(() => V.assertValidRecoveryKeys(null), /expected an array/);
  assert.throws(() => V.assertValidRecoveryKeys('not-an-array'), /expected an array/);
  assert.throws(() => V.assertValidRecoveryKeys({ hash: 'x' }), /expected an array/);
});

test('assertValidRecoveryKeys: empty list is rejected', () => {
  assert.throws(() => V.assertValidRecoveryKeys([]), /must not be empty/);
});

test('assertValidRecoveryKeys: oversized list is rejected', () => {
  const entry = { hash: 'a'.repeat(44), wrappedDek: 'b'.repeat(64), nonce: 'c'.repeat(32), salt: 'd'.repeat(44) };
  assert.throws(() => V.assertValidRecoveryKeys(Array(21).fill(entry)), /too many entries/);
});

test('assertValidRecoveryKeys: malformed entries are rejected', () => {
  const valid = { hash: 'a'.repeat(44), wrappedDek: 'b'.repeat(64), nonce: 'c'.repeat(32), salt: 'd'.repeat(44) };
  assert.throws(() => V.assertValidRecoveryKeys([null]), /malformed entry/);
  assert.throws(() => V.assertValidRecoveryKeys(['not-an-object']), /malformed entry/);
  assert.throws(() => V.assertValidRecoveryKeys([{ ...valid, hash: 12345 }]), /entry\.hash must be a string/);
  assert.throws(() => V.assertValidRecoveryKeys([{ ...valid, nonce: 'short' }]), /entry\.nonce has an invalid length/);
  assert.throws(() => V.assertValidRecoveryKeys([{ ...valid, salt: 'x'.repeat(300) }]), /entry\.salt has an invalid length/);
  const missingField = { hash: valid.hash, wrappedDek: valid.wrappedDek, nonce: valid.nonce };
  assert.throws(() => V.assertValidRecoveryKeys([missingField]), /entry\.salt must be a string/);
});

test('unwrapWithRecoveryCode: rejects an invalid recovery_keys shape before touching entries', async () => {
  await assert.rejects(() => V.unwrapWithRecoveryCode('ZZZZ-ZZZZ-ZZZZ', 'not-an-array'), /expected an array/);
  await assert.rejects(() => V.unwrapWithRecoveryCode('ZZZZ-ZZZZ-ZZZZ', []), /must not be empty/);
});

test('createKeyVault: per-dynamic key store/load/shred', async () => {
  const vault = V.createKeyVault(createMemoryKeyStore());
  const kB64 = await P.encodeBase64(await V.generateSharedKey());

  await vault.storeDynamicSharedKey('dyn:1', kB64);
  assert.equal(await vault.loadDynamicSharedKey('dyn:1'), kB64);

  await vault.cryptoShredDynamic('dyn:1');
  assert.equal(await vault.loadDynamicSharedKey('dyn:1'), null);
});
