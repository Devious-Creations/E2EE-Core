// primitives.test.js — the wrapper over the audited libraries behaves as claimed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as P from '../src/primitives.js';

test('secretbox: round-trips and rejects a tampered ciphertext', async () => {
  const key = await P.randomBytes(32);
  const msg = await P.encodeUTF8('the treaty is signed at dawn');
  const { nonce, ciphertext } = await P.encryptSecretbox(msg, key);

  const back = await P.decryptSecretbox(ciphertext, nonce, key);
  assert.deepEqual(back, msg);

  const tampered = Uint8Array.from(ciphertext);
  tampered[0] ^= 0x01;
  await assert.rejects(() => P.decryptSecretbox(tampered, nonce, key), /Decryption failed/);
});

test('secretbox: a wrong key fails to open', async () => {
  const key = await P.randomBytes(32);
  const wrong = await P.randomBytes(32);
  const { nonce, ciphertext } = await P.encryptSecretbox(await P.encodeUTF8('hi'), key);
  await assert.rejects(() => P.decryptSecretbox(ciphertext, nonce, wrong));
});

test('X25519: both parties derive the same shared key', async () => {
  const a = await P.generateKeypair();
  const b = await P.generateKeypair();
  const ab = await P.deriveSharedKey(b.publicKey, a.secretKey);
  const ba = await P.deriveSharedKey(a.publicKey, b.secretKey);
  assert.deepEqual(ab, ba);
  assert.equal(ab.length, 32);
});

test('scrypt: deterministic for the same input, memory-hard params', async () => {
  const pw = 'correct horse battery staple';
  const salt = await P.randomBytes(32);
  const params = { N: 32768, r: 8, p: 3, dkLen: 32 };
  const k1 = await P.scrypt(pw, salt, params);
  const k2 = await P.scrypt(pw, salt, params);
  assert.deepEqual(k1, k2);
  assert.equal(k1.length, 32);

  const otherSalt = await P.randomBytes(32);
  const k3 = await P.scrypt(pw, otherSalt, params);
  assert.notDeepEqual(k1, k3);
});

test('scrypt: async output is byte-identical to the sync implementation (KAT)', async () => {
  const { scrypt: _scryptSync } = await import('@noble/hashes/scrypt.js');
  const pw = 'correct horse battery staple';
  const salt = Uint8Array.from(
    Array.from({ length: 32 }, (_, i) => i),
  );
  const params = { N: 1024, r: 8, p: 1, dkLen: 32 }; // small N — this is a KAT, not a perf test
  const expected = _scryptSync(pw, salt, params);
  const actual = await P.scrypt(pw, salt, params);
  assert.deepEqual(actual, expected);
});

test('scrypt: onProgress is invoked with a fraction in (0, 1]', async () => {
  const pw = 'progress check';
  const salt = await P.randomBytes(32);
  const params = { N: 1024, r: 8, p: 1, dkLen: 32 };
  const fractions = [];
  await P.scrypt(pw, salt, params, (fraction) => fractions.push(fraction));
  assert.ok(fractions.length >= 1);
  for (const f of fractions) {
    assert.ok(typeof f === 'number' && f > 0 && f <= 1);
  }
});

test('pbkdf2 + sha256 + hmac produce fixed-length output', async () => {
  const salt = await P.randomBytes(16);
  const k = await P.pbkdf2('pw', salt, 10_000, 32);
  assert.equal(k.length, 32);

  const digest = await P.sha256Bytes(await P.encodeUTF8('abc'));
  assert.equal(digest.length, 32);

  const tag = await P.hmacSha256(await P.randomBytes(32), await P.encodeUTF8('m'));
  assert.equal(tag.length, 32);
});

test('timingSafeEqual: length-independent equality', async () => {
  const a = Uint8Array.from([1, 2, 3, 4]);
  const b = Uint8Array.from([1, 2, 3, 4]);
  const c = Uint8Array.from([1, 2, 3, 5]);
  assert.equal(P.timingSafeEqual(a, b), true);
  assert.equal(P.timingSafeEqual(a, c), false);
  assert.equal(P.timingSafeEqual(a, Uint8Array.from([1, 2, 3])), false);
});

test('randomInt: stays in range and rejects bad bounds', async () => {
  for (let i = 0; i < 500; i++) {
    const v = await P.randomInt(10);
    assert.ok(v >= 0 && v < 10);
  }
  await assert.rejects(() => P.randomInt(0));
  await assert.rejects(() => P.randomInt(100000));
});

test('generateUUID: RFC-4122 v4 shape', async () => {
  const id = await P.generateUUID();
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('base64 and utf8 codecs round-trip', async () => {
  const bytes = await P.randomBytes(40);
  const b64 = await P.encodeBase64(bytes);
  assert.deepEqual(await P.decodeBase64(b64), bytes);

  const s = 'héllo — 世界';
  assert.equal(await P.decodeUTF8(await P.encodeUTF8(s)), s);
});
