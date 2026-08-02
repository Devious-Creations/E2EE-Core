// pairing.qrCommitment.test.js — the two out-of-band QR-commitment hooks added
// on top of src/pairing.js's committed X25519 + SAS handshake (board #233 step
// 6, phase A): `onCommit` (initiator: hand the commitment to the caller so it
// can be rendered into a QR) and `expectedCommit` (joiner: verify a
// scanned/out-of-band commitment against BOTH the wire's pair_commit and the
// independently re-hashed pair_reveal, aborting fatally on any mismatch).
//
// This file is additive — it does not touch pairing.test.js's pinned
// contested-abort tripwire tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createPairing,
  QR_COMMITMENT_MISMATCH_ERROR,
} from '../src/pairing.js';
import { createMemoryTransportPair } from '../adapters/memoryTransport.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';
import * as primitives from '../src/primitives.js';

const UUID_A = '11111111-1111-4111-8111-111111111111';
const UUID_B = '22222222-2222-4222-8222-222222222222';

// A base64 string that decodes to exactly 32 bytes — satisfies decode32()'s
// shape check for a commit/publicKey field without corresponding to any real
// key material (the paths exercised here fail before that would matter).
async function random32Base64() {
  return primitives.encodeBase64(await primitives.randomBytes(32));
}

// A tracking Transport: records every event this endpoint SENDS (so a test can
// assert something was never sent, e.g. no pair_response leaking to an
// impostor) while letting the test inject inbound messages directly via
// emit(), the same technique pairing.test.js's createRawTransport uses for the
// contested-path tests.
function createTrackingTransport() {
  const handlers = new Map();
  const sent = [];
  return {
    sent,
    send(event, payload) {
      sent.push({ event, payload });
    },
    on(event, handler) {
      if (!handlers.has(event)) handlers.set(event, new Set());
      handlers.get(event).add(handler);
    },
    close() {},
    emit(event, payload) {
      const set = handlers.get(event);
      if (!set) return;
      for (const h of [...set]) h(payload);
    },
  };
}

test('onCommit: fires once on the initiator with base64(sha256(pk_I)), before any partner responds', async () => {
  const transport = createTrackingTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const commits = [];
  const attempt = A.initiatePairing('WOLF-QR01', UUID_A, () => {}, (commit) => commits.push(commit));
  await new Promise((r) => setTimeout(r, 20)); // let generateKeypair + myCommit settle

  assert.equal(commits.length, 1, 'onCommit fires exactly once');
  const decoded = await primitives.decodeBase64(commits[0]);
  assert.equal(decoded.length, 32, 'the commit is a base64-encoded 32-byte sha256 digest');

  // The value handed to onCommit is exactly the wire commit already broadcast
  // in pair_commit — proving it is "sha256(pk_I)" as the initiator itself
  // computes and sends it, not some other derivation.
  const wireCommit = transport.sent.find((m) => m.event === 'pair_commit')?.payload?.commit;
  assert.equal(commits[0], wireCommit);

  A.cancelActiveHandshake();
  await assert.rejects(() => attempt, /Pairing cancelled/);
});

test('QR path: matching expectedCommit completes the handshake exactly like the no-QR path', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  // Capture the initiator's commitment as the app would via onCommit, to hand
  // to the joiner as the "scanned QR" value.
  let resolveCommit;
  const commitCaptured = new Promise((resolve) => {
    resolveCommit = resolve;
  });
  const initP = A.initiatePairing('WOLF-QR02', UUID_A, () => {}, (commit) => resolveCommit(commit));
  const scannedCommit = await commitCaptured;

  const joinP = B.joinPairing('WOLF-QR02', UUID_B, () => {}, scannedCommit);
  const [rA, rB] = await Promise.all([initP, joinP]);

  // Same resolve shape/values as the plain (no expectedCommit) handshake.
  assert.equal(rA.role, 'initiator');
  assert.equal(rB.role, 'joiner');
  assert.equal(rA.partnerId, UUID_B);
  assert.equal(rB.partnerId, UUID_A);
  assert.equal(rA.sharedKey, rB.sharedKey);
  assert.equal(rA.sas, rB.sas);
  assert.match(rA.sas, /^[0-9]{6}$/);
  assert.equal(rA.channelName, rB.channelName);
});

test('QR path: no expectedCommit and no onCommit — behavior unchanged, a normal pairing still succeeds', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-QR03', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-QR03', UUID_A, () => {});

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.equal(rA.sharedKey, rB.sharedKey);
  assert.equal(rA.sas, rB.sas);
});

test('QR path: wrong expectedCommit aborts at pair_commit, before pair_response is ever sent', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const wrongExpected = await random32Base64();
  const attempt = B.joinPairing('WOLF-QR04', UUID_B, () => {}, wrongExpected);
  const rejection = assert.rejects(
    () => attempt,
    (err) => err.message === QR_COMMITMENT_MISMATCH_ERROR,
  );

  await new Promise((r) => setTimeout(r, 20)); // let the joiner register its handlers

  // A real (but different from expectedCommit) commit arrives on the wire —
  // as it would from a MITM standing between the joiner and whatever it
  // actually holds a session with.
  const wireCommit = await random32Base64();
  transport.emit('pair_commit', { userId: UUID_A, commit: wireCommit });

  await rejection;

  assert.equal(
    transport.sent.filter((m) => m.event === 'pair_response').length,
    0,
    'no pair_response ever leaked to the impostor on the other end of the transport',
  );
});

test('QR path: a pair_reveal that does not hash to expectedCommit aborts before session derivation', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  // The scanned commitment. A substituting transport can pass THIS through
  // verbatim as the wire pair_commit (so the pair_commit-stage check above
  // passes) yet still reveal a DIFFERENT key at pair_reveal — that is exactly
  // the case the independent, revealed-key re-hash must catch.
  const expectedCommit = await random32Base64();
  const attempt = B.joinPairing('WOLF-QR05', UUID_B, () => {}, expectedCommit);
  const rejection = assert.rejects(
    () => attempt,
    (err) => err.message === QR_COMMITMENT_MISMATCH_ERROR,
  );

  await new Promise((r) => setTimeout(r, 20));

  // Stage 1: the wire commit matches expectedCommit — passes the pair_commit
  // check, locks partnerCommit, and (in a real run) sends pair_response.
  transport.emit('pair_commit', { userId: UUID_A, commit: expectedCommit });
  await new Promise((r) => setTimeout(r, 20));

  // Stage 2: reveal a key that does NOT hash to expectedCommit — a
  // substituting MITM presenting a key the human never scanned.
  const substitutedKey = await random32Base64();
  transport.emit('pair_reveal', { userId: UUID_A, publicKey: substitutedKey });

  await rejection;

  assert.equal(
    transport.sent.filter((m) => m.event === 'pair_confirm').length,
    0,
    'no session/confirm is ever produced from the mismatched reveal',
  );
});
