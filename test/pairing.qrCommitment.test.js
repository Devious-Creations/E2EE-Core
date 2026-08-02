// pairing.qrCommitment.test.js — the two out-of-band QR-commitment hooks added
// on top of src/pairing.js's committed X25519 + SAS handshake (board #233 step
// 6, phase A): `onCommit` (initiator: hand the commitment to the caller so it
// can be rendered into a QR) and `expectedCommit` (joiner: verify a
// scanned/out-of-band commitment against BOTH the wire's pair_commit — the
// PRIMARY defence — and the independently re-hashed pair_reveal — defence in
// depth — aborting fatally on any mismatch). Both are passed via a trailing
// options bag: `initiatePairing(code, userId, onStateChange, { onCommit })`
// / `joinPairing(code, userId, onStateChange, { expectedCommit })`.
//
// This file is additive — it does not touch pairing.test.js's pinned
// contested-abort tripwire tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createPairing, QR_COMMITMENT_MISMATCH_ERROR } from '../src/pairing.js';
import { pairing as pairingNamespace } from '../src/index.js';
import { createMemoryTransportPair } from '../adapters/memoryTransport.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';
import * as primitives from '../src/primitives.js';

const UUID_A = '11111111-1111-4111-8111-111111111111';
const UUID_B = '22222222-2222-4222-8222-222222222222';

// A base64 string that decodes to exactly 32 bytes — satisfies decode32()'s
// shape check for a commit/publicKey field without corresponding to any real
// key material.
async function random32Base64() {
  return primitives.encodeBase64(await primitives.randomBytes(32));
}

// A REAL ephemeral keypair + its genuine commitment (sha256 of the raw public
// key bytes, base64-encoded) — computed exactly the way pairing.js computes
// `myCommit`. Used where a test needs to model a genuine forwarded
// commitment/key pair rather than opaque random bytes.
async function realKeyAndCommit() {
  const kp = await primitives.generateKeypair();
  const publicKeyB64 = await primitives.encodeBase64(kp.publicKey);
  const commit = await primitives.encodeBase64(await primitives.sha256Bytes(kp.publicKey));
  return { publicKeyB64, commit };
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
  const attempt = A.initiatePairing('WOLF-QR01', UUID_A, () => {}, {
    onCommit: (commit) => commits.push(commit),
  });
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

test('onCommit: the joiner never receives it (gated to role === initiator)', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinerCommits = [];
  const joinP = B.joinPairing('WOLF-QR02', UUID_B, () => {}, {
    onCommit: (c) => joinerCommits.push(c),
  });
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-QR02', UUID_A, () => {});

  await Promise.all([joinP, initP]);
  assert.equal(
    joinerCommits.length,
    0,
    'onCommit is initiator-only; passing it in the joiner options bag must never fire it',
  );
});

test('onCommit: a throwing synchronous callback does not break the handshake', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-QR03', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-QR03', UUID_A, () => {}, {
    onCommit: () => {
      throw new Error('caller QR-rendering bug');
    },
  });

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.equal(rA.sharedKey, rB.sharedKey, 'a throwing onCommit does not stop the handshake completing');
});

test('onCommit: a rejecting async callback does not crash the process or break the handshake', async () => {
  const unhandled = [];
  const onUnhandledRejection = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandledRejection);
  try {
    const [tA, tB] = createMemoryTransportPair();
    const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
    const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

    const joinP = B.joinPairing('WOLF-QR04', UUID_B, () => {});
    await new Promise((r) => setTimeout(r, 0));
    const initP = A.initiatePairing('WOLF-QR04', UUID_A, () => {}, {
      onCommit: async () => {
        throw new Error('async QR render failed');
      },
    });

    const [rB, rA] = await Promise.all([joinP, initP]);
    assert.equal(rA.sharedKey, rB.sharedKey, 'a rejecting async onCommit does not stop the handshake completing');

    // Give the rejected promise's microtask a turn — an unhandled rejection
    // would already have fired the process-level event by now.
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(unhandled.length, 0, 'the async onCommit rejection never surfaces as an unhandled rejection');
  } finally {
    process.off('unhandledRejection', onUnhandledRejection);
  }
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
  const initP = A.initiatePairing('WOLF-QR05', UUID_A, () => {}, {
    onCommit: (commit) => resolveCommit(commit),
  });
  const scannedCommit = await commitCaptured;

  const joinP = B.joinPairing('WOLF-QR05', UUID_B, () => {}, { expectedCommit: scannedCommit });
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

test('QR path: no expectedCommit and no onCommit — a normal pairing still succeeds', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-QR06', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-QR06', UUID_A, () => {});

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.equal(rA.sharedKey, rB.sharedKey);
  assert.equal(rA.sas, rB.sas);
});

test('QR path: wrong expectedCommit aborts at pair_commit, before pair_response is ever sent', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const wrongExpected = await random32Base64();
  const attempt = B.joinPairing('WOLF-QR07', UUID_B, () => {}, { expectedCommit: wrongExpected });
  const rejection = assert.rejects(
    () => attempt,
    (err) => err.message === QR_COMMITMENT_MISMATCH_ERROR && err.code === 'QR_COMMITMENT_MISMATCH',
  );

  await new Promise((r) => setTimeout(r, 20)); // let the joiner register its handlers

  // A real (but different from expectedCommit) commit arrives on the wire —
  // as it would from a MITM standing between the joiner and whatever it
  // actually holds a session with.
  const wireCommit = await random32Base64();
  transport.emit('pair_commit', { userId: UUID_A, commit: wireCommit });

  try {
    await attempt;
    assert.fail('expected the handshake to reject');
  } catch (err) {
    assert.equal(err.message, QR_COMMITMENT_MISMATCH_ERROR);
    assert.equal('sharedKey' in err, false, 'the rejection carries no sharedKey');
    assert.equal('session' in err, false, 'the rejection carries no session');
  }
  await rejection;

  assert.equal(
    transport.sent.filter((m) => m.event === 'pair_response').length,
    0,
    'no pair_response ever leaked to the impostor on the other end of the transport',
  );
});

test('QR path: a genuinely different revealed key that does not hash to expectedCommit aborts before session derivation', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  // A real keypair + its genuine commitment — the "scanned QR" value.
  const scanned = await realKeyAndCommit();
  // A SECOND, different real keypair — what a substituting MITM reveals
  // instead of the key the human actually scanned.
  const substituted = await realKeyAndCommit();

  const attempt = B.joinPairing('WOLF-QR08', UUID_B, () => {}, {
    expectedCommit: scanned.commit,
  });
  const rejection = assert.rejects(
    () => attempt,
    (err) => err.message === QR_COMMITMENT_MISMATCH_ERROR && err.code === 'QR_COMMITMENT_MISMATCH',
  );

  await new Promise((r) => setTimeout(r, 20));

  // Stage 1: the wire commit matches expectedCommit exactly (both are the
  // real, genuine commitment of `scanned`'s keypair) — passes the
  // pair_commit-stage gate, locks partnerCommit, and (in a real run) sends
  // pair_response.
  transport.emit('pair_commit', { userId: UUID_A, commit: scanned.commit });
  await new Promise((r) => setTimeout(r, 20));

  // Stage 2: reveal `substituted`'s REAL public key — a genuinely different,
  // validly-formed key that does not hash to `scanned.commit`. Models an
  // actual forwarded-then-substituted reveal, not just opaque random bytes.
  transport.emit('pair_reveal', { userId: UUID_A, publicKey: substituted.publicKeyB64 });

  try {
    await attempt;
    assert.fail('expected the handshake to reject');
  } catch (err) {
    assert.equal(err.message, QR_COMMITMENT_MISMATCH_ERROR);
    assert.equal('sharedKey' in err, false, 'the rejection carries no sharedKey');
    assert.equal('session' in err, false, 'the rejection carries no session');
  }
  await rejection;

  assert.equal(
    transport.sent.filter((m) => m.event === 'pair_confirm').length,
    0,
    'no session/confirm is ever produced from the mismatched reveal',
  );
});

test('QR path: pair_reveal with no prior pair_commit is silently ignored — stays pending, nothing sent', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  const expectedCommit = await random32Base64();
  const attempt = B.joinPairing('WOLF-QR09', UUID_B, () => {}, { expectedCommit });
  await new Promise((r) => setTimeout(r, 20));

  const substitutedKey = await random32Base64();
  transport.emit('pair_reveal', { userId: UUID_A, publicKey: substitutedKey });
  await new Promise((r) => setTimeout(r, 20));

  const PENDING = Symbol('pending');
  const outcome = await Promise.race([
    attempt.then(
      () => 'resolved',
      () => 'rejected',
    ),
    new Promise((r) => setTimeout(() => r(PENDING), 20)),
  ]);
  assert.equal(
    outcome,
    PENDING,
    'a reveal before any commit is ignored (existing behaviour), not a fatal abort — the handshake is still pending',
  );
  assert.equal(transport.sent.length, 0, 'no messages sent in response to an out-of-order reveal');

  // Cleanup: don't leave a live timer/interval running past this test.
  B.cancelActiveHandshake();
  await assert.rejects(() => attempt, /Pairing cancelled/);
});

test('expectedCommit validation: null is a programmer-error throw, not an attack error', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  await assert.rejects(
    () => B.joinPairing('WOLF-QR10', UUID_B, () => {}, { expectedCommit: null }),
    (err) =>
      err.message === '[pairing] options.expectedCommit must be a base64-encoded 32-byte digest' &&
      err.code === undefined &&
      err.message !== QR_COMMITMENT_MISMATCH_ERROR,
  );
  assert.equal(transport.sent.length, 0, 'the handshake never even starts on a caller-typing bug');
});

test('expectedCommit validation: an empty string is a programmer-error throw, not an attack error', async () => {
  const transport = createTrackingTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });

  await assert.rejects(
    () => B.joinPairing('WOLF-QR11', UUID_B, () => {}, { expectedCommit: '' }),
    (err) =>
      err.message === '[pairing] options.expectedCommit must be a base64-encoded 32-byte digest' &&
      err.code === undefined &&
      err.message !== QR_COMMITMENT_MISMATCH_ERROR,
  );
  assert.equal(transport.sent.length, 0);
});

test('onCommit validation: a non-function value is a programmer-error throw', async () => {
  const transport = createTrackingTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });

  await assert.rejects(
    () => A.initiatePairing('WOLF-QR12', UUID_A, () => {}, { onCommit: 'not-a-function' }),
    /\[pairing\] options\.onCommit must be a function/,
  );
  assert.equal(transport.sent.length, 0, 'a wrong-typed onCommit must not silently proceed unauthenticated');
});

test('QR_COMMITMENT_MISMATCH_ERROR is reachable via the package index (protects against an index refactor dropping it)', () => {
  assert.equal(pairingNamespace.QR_COMMITMENT_MISMATCH_ERROR, QR_COMMITMENT_MISMATCH_ERROR);
});

// Tripwire for the byte-compare at the commit-stage gate (adversarial review
// finding 5 / M2). `expectedCommit` round-trips through a QR code, and QR
// encoders routinely re-encode base64: the final data character of a 32-byte
// digest carries two bits that decode() ignores, so two DIFFERENT strings can
// decode to the SAME 32 bytes. A string comparison there would abort an honest
// in-person pairing with a "someone may be intercepting" warning. If anyone
// reverts the gate to `payload.commit !== expectedCommit`, this test fails.
test('QR path: a byte-equivalent re-encoding of the commitment still completes', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  let resolveCommit;
  const commitCaptured = new Promise((resolve) => {
    resolveCommit = resolve;
  });
  const initP = A.initiatePairing('WOLF-QR10', UUID_A, () => {}, {
    onCommit: (commit) => resolveCommit(commit),
  });
  const scannedCommit = await commitCaptured;

  // Flip the lowest (ignored) bit of the last data character.
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lastIdx = scannedCommit.length - 2; // -1 is the '=' pad
  const variantChar = ALPHABET[ALPHABET.indexOf(scannedCommit[lastIdx]) ^ 1];
  const reEncoded = scannedCommit.slice(0, lastIdx) + variantChar + '=';

  assert.notEqual(reEncoded, scannedCommit, 'the variant must be a different string');
  assert.deepEqual(
    Array.from(await primitives.decodeBase64(reEncoded)),
    Array.from(await primitives.decodeBase64(scannedCommit)),
    'the variant must decode to the identical 32 bytes',
  );

  const joinP = B.joinPairing('WOLF-QR10', UUID_B, () => {}, { expectedCommit: reEncoded });
  const [rA, rB] = await Promise.all([initP, joinP]);
  assert.equal(rA.sharedKey, rB.sharedKey);
  assert.equal(rA.sas, rB.sas);
});

// Validation tripwires for the stricter expectedCommit shape check and the
// unknown-option guard (review findings M1 and the options-bag footgun): a
// caller's wiring bug must reject as a PROGRAMMER error, never surface to the
// user as QR_COMMITMENT_MISMATCH ("someone may be intercepting").
test('QR path: a malformed expectedCommit rejects as a caller error, not an attack', async () => {
  for (const bad of ['not-base64!!', 'aGVsbG8', 'AAAA']) {
    const [, tB] = createMemoryTransportPair();
    const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });
    await assert.rejects(
      B.joinPairing('WOLF-QR11', UUID_B, () => {}, { expectedCommit: bad }),
      (err) => {
        assert.match(err.message, /options\.expectedCommit/);
        assert.notEqual(err.message, QR_COMMITMENT_MISMATCH_ERROR);
        assert.equal(err.code, undefined);
        return true;
      },
      `expected a caller error for ${JSON.stringify(bad)}`,
    );
  }
});

test('QR path: a misspelled option key rejects instead of silently skipping verification', async () => {
  const [, tB] = createMemoryTransportPair();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });
  await assert.rejects(
    B.joinPairing('WOLF-QR12', UUID_B, () => {}, { expectedCommmit: await random32Base64() }),
    /unknown option: expectedCommmit/,
  );
});

test('QR path: the machine-readable code constant is exported from the package entry point', () => {
  assert.equal(pairingNamespace.QR_COMMITMENT_MISMATCH_CODE, 'QR_COMMITMENT_MISMATCH');
});
