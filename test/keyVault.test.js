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

test('KDF descriptors: v1 and v2 stay intact, v3 is current', () => {
  // v1/v2 are load-bearing for vaults already in the field — freezing their
  // exact shape here means a re-tune can never silently orphan them.
  assert.deepEqual({ ...V.KDF_PBKDF2_LEGACY }, { v: 1, algo: 'pbkdf2-sha256', iterations: 10_000 });
  assert.deepEqual({ ...V.KDF_SCRYPT }, { v: 2, algo: 'scrypt', N: 32768, r: 8, p: 3 });
  assert.deepEqual({ ...V.KDF_SCRYPT_V3 }, { v: 3, algo: 'scrypt', N: 65536, r: 8, p: 1 });
  assert.equal(V.CURRENT_KDF, V.KDF_SCRYPT_V3);
});

test('KDF re-tune never weakens: working set grows, version is monotonic', () => {
  // @noble allocates one contiguous 128*r*N scratch buffer; p costs time, not
  // memory. The new params must not shrink that buffer below what v2 forced.
  const workingSet = (k) => 128 * k.r * k.N;
  assert.equal(workingSet(V.KDF_SCRYPT), 32 * 1024 * 1024);
  assert.equal(workingSet(V.KDF_SCRYPT_V3), 64 * 1024 * 1024);
  assert.ok(workingSet(V.CURRENT_KDF) >= workingSet(V.KDF_SCRYPT));
  assert.ok(V.CURRENT_KDF.v > V.KDF_SCRYPT.v);
  assert.ok(V.KDF_SCRYPT.v > V.KDF_PBKDF2_LEGACY.v);
});

test('a vault wrapped under v2 still opens after the re-tune, then re-wraps to v3', async () => {
  // The upgrade path in the app, end to end against real crypto: unwrap with
  // the descriptor the vault was WRITTEN with, then re-wrap under CURRENT_KDF.
  const dek = await V.generateDEK();
  const oldSalt = await P.randomBytes(32);
  const oldKek = await V.deriveKEK('hunter2', oldSalt, V.KDF_SCRYPT);
  const oldWrap = await V.wrapDEK(dek, oldKek);

  // Still openable under v2 — this is the "existing vaults keep working" claim.
  const reopened = await V.deriveKEK('hunter2', oldSalt, V.KDF_SCRYPT);
  assert.deepEqual(await V.unwrapDEK(oldWrap.wrappedDek, oldWrap.nonce, reopened), dek);

  // Transparent upgrade: fresh salt, current KDF, same DEK.
  const newSalt = await P.randomBytes(32);
  const newKek = await V.deriveKEK('hunter2', newSalt, V.CURRENT_KDF);
  const newWrap = await V.wrapDEK(dek, newKek);
  assert.deepEqual(await V.unwrapDEK(newWrap.wrappedDek, newWrap.nonce, newKek), dek);

  // The v2 KEK must not open the v3 wrap — proves the descriptor is really
  // what selects the parameters, rather than both paths landing on one default.
  assert.notDeepEqual(oldKek, newKek);
  await assert.rejects(() => V.unwrapDEK(newWrap.wrappedDek, newWrap.nonce, oldKek));
});

test('a v1 (PBKDF2) vault opens and jumps straight to v3, skipping v2', async () => {
  const dek = await V.generateDEK();
  const oldSalt = await P.randomBytes(32);
  const oldKek = await V.deriveKEK('hunter2', oldSalt, V.KDF_PBKDF2_LEGACY);
  const oldWrap = await V.wrapDEK(dek, oldKek);
  assert.deepEqual(await V.unwrapDEK(oldWrap.wrappedDek, oldWrap.nonce, oldKek), dek);

  // Nothing in the re-wrap depends on the OLD algorithm having been scrypt.
  const newSalt = await P.randomBytes(32);
  const newKek = await V.deriveKEK('hunter2', newSalt, V.CURRENT_KDF);
  const newWrap = await V.wrapDEK(dek, newKek);
  assert.deepEqual(await V.unwrapDEK(newWrap.wrappedDek, newWrap.nonce, newKek), dek);
});

test('recovery codes stay on PBKDF2-10k, unaffected by the scrypt re-tune', async () => {
  // Deliberate: ~60 bits of entropy needs no stretching. If a re-tune ever
  // dragged recovery onto scrypt, redeeming 8 codes would cost 8 x 64 MiB.
  const dek = await V.generateDEK();
  const codes = await V.generateRecoveryCodes(2);
  const entries = await V.buildRecoveryEntries(dek, codes);

  // Rebuild the KEK by hand under v1 and confirm it opens the recovery wrap.
  const salt = await P.decodeBase64(entries[0].salt);
  const kek = await V.deriveKEK(codes[0].replace(/-/g, ''), salt, V.KDF_PBKDF2_LEGACY);
  assert.deepEqual(await V.unwrapDEK(entries[0].wrappedDek, entries[0].nonce, kek), dek);
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
