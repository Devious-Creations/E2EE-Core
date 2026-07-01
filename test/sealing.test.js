// sealing.test.js — per-key JSON and raw-blob sealing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../src/sealing.js';
import * as P from '../src/primitives.js';

test('encryptDataWithKey/decryptDataWithKey round-trips a JSON object', async () => {
  const key = await P.encodeBase64(await P.randomBytes(32));
  const obj = { hello: 'world', n: 42, nested: { a: [1, 2, 3] } };

  const { ciphertext, nonce } = await S.encryptDataWithKey(obj, key);
  assert.deepEqual(await S.decryptDataWithKey(ciphertext, nonce, key), obj);

  const wrong = await P.encodeBase64(await P.randomBytes(32));
  await assert.rejects(() => S.decryptDataWithKey(ciphertext, nonce, wrong));
});

test('sealBytes/openBytes round-trips a raw blob and rejects tampering', async () => {
  const key = await P.encodeBase64(await P.randomBytes(32));
  const data = await P.encodeBase64(await P.randomBytes(50));

  const sealed = await S.sealBytes(data, key);
  assert.ok(sealed instanceof Uint8Array);
  assert.equal(sealed.length, 24 + 50 + 16); // nonce || (plaintext + poly1305 tag)

  const sealedB64 = await P.encodeBase64(sealed);
  assert.equal(await S.openBytes(sealedB64, key), data);

  const tampered = Uint8Array.from(sealed);
  tampered[30] ^= 0x01;
  const tamperedB64 = await P.encodeBase64(tampered);
  await assert.rejects(() => S.openBytes(tamperedB64, key));
});
