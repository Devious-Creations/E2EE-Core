// pairing.admitPartner.test.js — the partner-admission gate added on top of
// src/pairing.js's committed X25519 + SAS handshake: `options.admitPartner`
// lets the caller's app answer "may I pair with this self-asserted user id?"
// BEFORE either side reveals/responds, so a refusal aborts the handshake
// before anything is ever stored. This closes the ghost-pairing case where an
// at-limit side meets a stranger on a QR code (which auto-confirms the
// joiner) and would otherwise leave the stranger holding a one-sided pairing.
//
// This file is additive — it does not touch pairing.test.js's or
// pairing.qrCommitment.test.js's pinned tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createPairing,
  PAIRING_TIMEOUT_MS,
  PARTNER_NOT_ADMITTED_ERROR,
  PARTNER_NOT_ADMITTED_CODE,
  PEER_REFUSED_ERROR,
  PEER_REFUSED_CODE,
  CONTESTED_CODE,
  QR_COMMITMENT_MISMATCH_CODE,
} from '../src/pairing.js';
import { pairing as pairingNamespace } from '../src/index.js';
import { createMemoryTransportPair } from '../adapters/memoryTransport.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';
import * as primitives from '../src/primitives.js';

const UUID_A = '11111111-1111-4111-8111-111111111111';
const UUID_B = '22222222-2222-4222-8222-222222222222';
const UUID_C = '33333333-3333-4333-8333-333333333333';

// A base64 string that decodes to exactly 32 bytes — satisfies decode32()'s
// shape check for a commit/publicKey field without corresponding to any real
// key material (the tests below fail/refuse before any such correspondence
// would matter).
async function random32Base64() {
  return primitives.encodeBase64(await primitives.randomBytes(32));
}

// ── Send-spy transport ─────────────────────────────────────────────────────
// memoryTransport can't record what it sends — wrap a real pair so every
// "never sent"/"sent exactly once" assertion below can inspect the wire
// traffic while still delivering messages normally between the two sides.
function createSpyTransportPair() {
  const [a, b] = createMemoryTransportPair();
  const wrap = (endpoint) => {
    const sentEvents = [];
    return {
      sentEvents,
      send(event, payload) {
        sentEvents.push({ event, payload });
        return endpoint.send(event, payload);
      },
      on: endpoint.on.bind(endpoint),
      close: endpoint.close.bind(endpoint),
    };
  };
  return [wrap(a), wrap(b)];
}

// A single-sided, driven-by-hand transport: `send` only records (no partner to
// deliver to), `emit` calls this handshake's own registered handler(s)
// directly — the same technique pairing.test.js's createRawTransport uses for
// its contested-path tests. Used wherever a test needs fine control over
// exactly when a message arrives, e.g. to hold a handshake mid-admission.
function createRawTransport() {
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

// A transport that records every send() but never delivers anything anywhere
// (no partner) — used for the option-validation tests, where the assertion is
// "nothing was sent before the validation throw".
function createTrackingTransport() {
  const sent = [];
  return {
    sent,
    send(event, payload) {
      sent.push({ event, payload });
    },
    on() {},
    close() {},
  };
}

// Wraps one real endpoint of a memoryTransport pair so a test can both let
// the handshake run normally AND inject an extra, hand-crafted inbound
// message via emit() (e.g. a bogus pair_abort), and/or hook every outbound
// send() (e.g. to inject a message at a precise point in the protocol).
function wrapWithEmit(endpoint, { onSend } = {}) {
  const handlers = new Map();
  const wrapped = {
    send(event, payload) {
      if (onSend) onSend(event, payload);
      return endpoint.send(event, payload);
    },
    on(event, handler) {
      if (!handlers.has(event)) handlers.set(event, new Set());
      handlers.get(event).add(handler);
      endpoint.on(event, handler);
    },
    close: endpoint.close.bind(endpoint),
    emit(event, payload) {
      const set = handlers.get(event);
      if (!set) return;
      for (const h of [...set]) h(payload);
    },
  };
  return wrapped;
}

// Simulates an OLD peer that predates this feature: it never registers a
// 'pair_abort' handler at all (the real library today has no such event), so
// a partner's pair_abort is simply dropped by the transport with no listener
// — exactly memoryTransport's existing "unknown events are dropped" behaviour
// (adapters/memoryTransport.js — a send with no registered handler set is a
// no-op).
function makeOldPeerTransport(endpoint) {
  return {
    send: endpoint.send.bind(endpoint),
    on(event, handler) {
      if (event === 'pair_abort') return;
      endpoint.on(event, handler);
    },
    close: endpoint.close.bind(endpoint),
  };
}

test('admission: no admitPartner supplied → behaves exactly as before (no admission gate)', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-AD00', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD00', UUID_A, () => {});

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.equal(rA.sharedKey, rB.sharedKey);
  assert.equal(rA.sas, rB.sas);
});

test('option validation: an unknown option key is still rejected (allowlist now includes admitPartner)', async () => {
  const transport = createTrackingTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });
  await assert.rejects(
    () => A.initiatePairing('WOLF-AD01', UUID_A, () => {}, { admitPartnerTypo: () => true }),
    /unknown option: admitPartnerTypo/,
  );
  assert.deepEqual(transport.sent, [], 'nothing must be sent before the validation throw');
});

test('admission: a non-function admitPartner rejects immediately, before any transport activity', async () => {
  const transport = createTrackingTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });
  await assert.rejects(
    () => A.initiatePairing('WOLF-AD02', UUID_A, () => {}, { admitPartner: 'nope' }),
    /options\.admitPartner must be a function/,
  );
  assert.deepEqual(transport.sent, [], 'nothing must be sent before the validation throw');
});

test('admission: initiator refuses → initiator rejects PARTNER_NOT_ADMITTED, joiner rejects PEER_REFUSED, pair_reveal never sent', async () => {
  const [tA, tB] = createSpyTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-AD03', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD03', UUID_A, () => {}, {
    admitPartner: async () => false,
  });

  await Promise.all([
    assert.rejects(
      () => initP,
      (err) => err.message === PARTNER_NOT_ADMITTED_ERROR && err.code === PARTNER_NOT_ADMITTED_CODE,
    ),
    assert.rejects(
      () => joinP,
      (err) => err.message === PEER_REFUSED_ERROR && err.code === PEER_REFUSED_CODE,
    ),
  ]);

  assert.ok(
    !tA.sentEvents.some((m) => m.event === 'pair_reveal'),
    'pair_reveal must never be sent once the initiator refuses',
  );
});

test('admission: joiner refuses → joiner rejects PARTNER_NOT_ADMITTED; the (unlocked) initiator honours the pre-lock abort promptly; pair_response never sent', async () => {
  const [tA, tB] = createSpyTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const start = Date.now();
  const joinP = B.joinPairing('WOLF-AD04', UUID_B, () => {}, {
    admitPartner: async () => false,
  });
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD04', UUID_A, () => {});

  await Promise.all([
    assert.rejects(
      () => joinP,
      (err) => err.message === PARTNER_NOT_ADMITTED_ERROR && err.code === PARTNER_NOT_ADMITTED_CODE,
    ),
    assert.rejects(
      () => initP,
      (err) => err.message === PEER_REFUSED_ERROR && err.code === PEER_REFUSED_CODE,
    ),
  ]);

  const elapsedMs = Date.now() - start;
  assert.ok(
    elapsedMs < 5000,
    `the initiator must reject promptly via the abort, not the ${PAIRING_TIMEOUT_MS}ms handshake timeout (took ${elapsedMs}ms)`,
  );
  assert.ok(
    !tB.sentEvents.some((m) => m.event === 'pair_response'),
    'pair_response must never be sent once the joiner refuses',
  );
});

test('admission: both sides admit → completes exactly like today; admitPartner is called with the locked partner id', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const calledWithA = [];
  const calledWithB = [];
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-AD05', UUID_B, () => {}, {
    admitPartner: async (id) => {
      calledWithB.push(id);
      return true;
    },
  });
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD05', UUID_A, () => {}, {
    admitPartner: async (id) => {
      calledWithA.push(id);
      return true;
    },
  });

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.equal(rA.sharedKey, rB.sharedKey);
  assert.equal(rA.sas, rB.sas);
  assert.deepEqual(calledWithA, [UUID_B], 'the initiator asks about the locked joiner id, exactly once');
  assert.deepEqual(calledWithB, [UUID_A], 'the joiner asks about the locked initiator id, exactly once');
});

for (const [label, result] of [
  ['false', false],
  ['undefined', undefined],
  ["a truthy non-boolean ('yes')", 'yes'],
]) {
  test(`admission: admitPartner resolving to ${label} refuses (fail closed)`, async () => {
    const [tA, tB] = createMemoryTransportPair();
    const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
    const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

    const joinP = B.joinPairing('WOLF-AD06', UUID_B, () => {});
    await new Promise((r) => setTimeout(r, 0));
    const initP = A.initiatePairing('WOLF-AD06', UUID_A, () => {}, {
      admitPartner: async () => result,
    });

    await assert.rejects(() => initP, (err) => err.code === PARTNER_NOT_ADMITTED_CODE);
    await assert.rejects(() => joinP, (err) => err.code === PEER_REFUSED_CODE);
  });
}

test('admission: admitPartner throwing synchronously refuses (fail closed)', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-AD07', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD07', UUID_A, () => {}, {
    admitPartner: () => {
      throw new Error('caller policy check blew up');
    },
  });

  await assert.rejects(() => initP, (err) => err.code === PARTNER_NOT_ADMITTED_CODE);
  await assert.rejects(() => joinP, (err) => err.code === PEER_REFUSED_CODE);
});

test('admission: admitPartner rejecting refuses (fail closed)', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

  const joinP = B.joinPairing('WOLF-AD08', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD08', UUID_A, () => {}, {
    admitPartner: async () => {
      throw new Error('async policy check failed');
    },
  });

  await assert.rejects(() => initP, (err) => err.code === PARTNER_NOT_ADMITTED_CODE);
  await assert.rejects(() => joinP, (err) => err.code === PEER_REFUSED_CODE);
});

test('admission: duplicate pair_response deliveries during pending admission call admitPartner once and never leak pair_reveal (initiator side)', async () => {
  const transport = createRawTransport();
  let calls = 0;
  let resolveAdmit;
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });
  const attempt = A.initiatePairing('WOLF-AD09', UUID_A, () => {}, {
    admitPartner: async () => {
      calls += 1;
      return new Promise((resolve) => {
        resolveAdmit = resolve;
      });
    },
  });

  await new Promise((r) => setTimeout(r, 20));
  const publicKey = await random32Base64();
  transport.emit('pair_response', { userId: UUID_B, publicKey });
  await new Promise((r) => setTimeout(r, 20)); // admission now pending

  // Duplicate response, SAME public key, while pending.
  transport.emit('pair_response', { userId: UUID_B, publicKey });
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(calls, 1, 'admitPartner is called exactly once, not once per duplicate delivery');
  assert.ok(
    !transport.sent.some((m) => m.event === 'pair_reveal'),
    'pair_reveal must not leak while admission is still pending',
  );

  resolveAdmit(true);
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(
    transport.sent.some((m) => m.event === 'pair_reveal'),
    'pair_reveal is sent once admission resolves to admitted',
  );

  A.cancelActiveHandshake();
  await assert.rejects(() => attempt, /Pairing cancelled/);
});

test('admission: duplicate pair_commit deliveries during pending admission call admitPartner once and never leak pair_response (joiner side)', async () => {
  const transport = createRawTransport();
  let calls = 0;
  let resolveAdmit;
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });
  const attempt = B.joinPairing('WOLF-AD10', UUID_B, () => {}, {
    admitPartner: async () => {
      calls += 1;
      return new Promise((resolve) => {
        resolveAdmit = resolve;
      });
    },
  });

  await new Promise((r) => setTimeout(r, 20));
  const commit = await random32Base64();
  transport.emit('pair_commit', { userId: UUID_A, commit });
  await new Promise((r) => setTimeout(r, 20)); // admission now pending

  // Duplicate commit, SAME value, while pending — the initiator's own repeat
  // loop does exactly this in production.
  transport.emit('pair_commit', { userId: UUID_A, commit });
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(calls, 1, 'admitPartner is called exactly once, not once per duplicate delivery');
  assert.ok(
    !transport.sent.some((m) => m.event === 'pair_response'),
    'pair_response must not leak while admission is still pending',
  );

  resolveAdmit(true);
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(
    transport.sent.some((m) => m.event === 'pair_response'),
    'pair_response is sent once admission resolves to admitted',
  );

  B.cancelActiveHandshake();
  await assert.rejects(() => attempt, /Pairing cancelled/);
});

test('admission: a second identity while admission is pending still triggers CONTESTED (initiator side)', async () => {
  const transport = createRawTransport();
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport });
  const attempt = A.initiatePairing('WOLF-AD11', UUID_A, () => {}, {
    admitPartner: () => new Promise(() => {}), // never resolves — stays pending
  });
  const rejection = assert.rejects(() => attempt, (err) => err.code === CONTESTED_CODE);

  await new Promise((r) => setTimeout(r, 20));
  transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });
  await new Promise((r) => setTimeout(r, 20)); // admission now pending, never resolving

  // A second, different device answers the same code while pending.
  transport.emit('pair_response', { userId: UUID_C, publicKey: await random32Base64() });

  await rejection;
});

test('admission: a duplicate pair_commit with a DIFFERENT value while admission is pending still triggers CONTESTED (joiner side)', async () => {
  const transport = createRawTransport();
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });
  const attempt = B.joinPairing('WOLF-AD12', UUID_B, () => {}, {
    admitPartner: () => new Promise(() => {}), // never resolves — stays pending
  });
  const rejection = assert.rejects(() => attempt, (err) => err.code === CONTESTED_CODE);

  await new Promise((r) => setTimeout(r, 20));
  transport.emit('pair_commit', { userId: UUID_A, commit: await random32Base64() });
  await new Promise((r) => setTimeout(r, 20)); // admission now pending, never resolving

  transport.emit('pair_commit', { userId: UUID_A, commit: await random32Base64() });

  await rejection;
});

test('pair_abort: a non-partner id on the joiner is ignored — the handshake still completes', async () => {
  const [tA, tB] = createMemoryTransportPair();
  const tBw = wrapWithEmit(tB);
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tBw });

  const joinP = B.joinPairing('WOLF-AD13', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD13', UUID_A, () => {});

  await new Promise((r) => setTimeout(r, 10));
  tBw.emit('pair_abort', { userId: UUID_C, reason: 'not_admitted' });

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.equal(rA.sharedKey, rB.sharedKey, 'a bogus abort from a non-partner id must not affect the handshake');
});

test('pair_abort: an abort delivered after the reveal window closes is ignored (joiner side) — the handshake still completes', async () => {
  const [tA, tB] = createMemoryTransportPair();
  let injected = false;
  let tBw;
  tBw = wrapWithEmit(tB, {
    onSend: (event) => {
      // B's first pair_confirm send happens only after it has already
      // accepted the reveal (partnerPublicKey set — the reveal window is
      // closed). Injecting the abort at exactly that point, from the (real)
      // locked partner id, proves the window check — not just luck of timing.
      if (event === 'pair_confirm' && !injected) {
        injected = true;
        tBw.emit('pair_abort', { userId: UUID_A, reason: 'not_admitted' });
      }
    },
  });
  const A = createPairing({ keyStore: createMemoryKeyStore(), transport: tA });
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tBw });

  const joinP = B.joinPairing('WOLF-AD14', UUID_B, () => {});
  await new Promise((r) => setTimeout(r, 0));
  const initP = A.initiatePairing('WOLF-AD14', UUID_A, () => {});

  const [rB, rA] = await Promise.all([joinP, initP]);
  assert.ok(injected, 'the abort was actually injected at the intended point');
  assert.equal(
    rA.sharedKey,
    rB.sharedKey,
    'an abort after the reveal window closes must not affect the handshake',
  );
});

test('admission: a resolution arriving after cancelActiveHandshake has no effect and never surfaces as an unhandled rejection', async () => {
  const unhandled = [];
  const onUnhandledRejection = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandledRejection);
  try {
    const transport = createRawTransport();
    let resolveAdmit;
    const A = createPairing({ keyStore: createMemoryKeyStore(), transport });
    const attempt = A.initiatePairing('WOLF-AD15', UUID_A, () => {}, {
      admitPartner: () =>
        new Promise((resolve) => {
          resolveAdmit = resolve;
        }),
    });
    const rejection = assert.rejects(() => attempt, /Pairing cancelled/);

    await new Promise((r) => setTimeout(r, 20));
    transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });
    await new Promise((r) => setTimeout(r, 20)); // admission now pending

    A.cancelActiveHandshake();
    await rejection;

    // The admission promise resolves LATE — well after cancellation already
    // settled the handshake — must be a silent no-op.
    resolveAdmit(true);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(unhandled.length, 0, 'a late admission resolution must never produce an unhandled rejection');
  } finally {
    process.off('unhandledRejection', onUnhandledRejection);
  }
});

test('admission: a rejection arriving after cancelActiveHandshake has no effect and never surfaces as an unhandled rejection', async () => {
  const unhandled = [];
  const onUnhandledRejection = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandledRejection);
  try {
    const transport = createRawTransport();
    let rejectAdmit;
    const A = createPairing({ keyStore: createMemoryKeyStore(), transport });
    const attempt = A.initiatePairing('WOLF-AD16', UUID_A, () => {}, {
      admitPartner: () =>
        new Promise((_resolve, reject) => {
          rejectAdmit = reject;
        }),
    });
    const rejection = assert.rejects(() => attempt, /Pairing cancelled/);

    await new Promise((r) => setTimeout(r, 20));
    transport.emit('pair_response', { userId: UUID_B, publicKey: await random32Base64() });
    await new Promise((r) => setTimeout(r, 20)); // admission now pending

    A.cancelActiveHandshake();
    await rejection;

    rejectAdmit(new Error('late rejection after the handshake already settled'));
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(unhandled.length, 0, 'a late admission rejection must never produce an unhandled rejection');
  } finally {
    process.off('unhandledRejection', onUnhandledRejection);
  }
});

test('old peer: a side whose transport drops pair_abort (no listener) rejects via its own timeout, and never resolves', async (t) => {
  // Warm up the lazy `tweetnacl`/`tweetnacl-util` dynamic imports BEFORE
  // mocking timers: on a cold module cache, primitives.js's `await
  // import('tweetnacl')` resolves through real module-loader I/O (not just
  // microtasks), which can outlast a short synchronous burst of
  // `await Promise.resolve()` below and would otherwise make the handshake's
  // OWN `setTimeout(..., PAIRING_TIMEOUT_MS)` register only AFTER `tick()`
  // already ran — the exact hang this warm-up avoids.
  const warmKeypair = await primitives.generateKeypair();
  await primitives.encodeBase64(warmKeypair.publicKey);
  await primitives.sha256Bytes(warmKeypair.publicKey);

  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const [tA, tB] = createMemoryTransportPair();
    const oldA = makeOldPeerTransport(tA); // simulates a peer that predates pair_abort entirely
    const A = createPairing({ keyStore: createMemoryKeyStore(), transport: oldA });
    const B = createPairing({ keyStore: createMemoryKeyStore(), transport: tB });

    let resolved = false;
    let rejectedErr = null;
    const initDone = A.initiatePairing('WOLF-AD17', UUID_A, () => {}).then(
      () => {
        resolved = true;
      },
      (err) => {
        rejectedErr = err;
      },
    );
    const joinDone = B.joinPairing('WOLF-AD17', UUID_B, () => {}, {
      admitPartner: async () => false,
    }).catch(() => {});

    // Let the handshake run its microtask-driven exchange far enough for B to
    // receive A's commit, refuse, and (best-effort) send a pair_abort that
    // A's transport silently drops — all of this happens without any real
    // timer firing. A REAL setImmediate round-trip (not `mock.timers`, which
    // only fakes setTimeout/setInterval) drains the ENTIRE pending microtask
    // queue between event-loop turns, however many awaits deep the two
    // concurrent handshakes' setup chains are — a fixed count of bare
    // `await Promise.resolve()` calls only pops one level per call and can
    // undercount that depth.
    const flush = () => new Promise((resolve) => setImmediate(resolve));
    for (let i = 0; i < 5; i++) {
      await flush();
    }
    assert.equal(resolved, false, 'A must not resolve while its own transport drops the abort');
    assert.equal(rejectedErr, null, 'A must not have rejected yet either — it is still waiting');

    // Advance past the full handshake timeout — A's own no-store guarantee
    // (reject on timeout) must never depend on the abort arriving.
    t.mock.timers.tick(PAIRING_TIMEOUT_MS);
    for (let i = 0; i < 5; i++) {
      await flush();
    }
    await initDone;
    await joinDone;

    assert.ok(rejectedErr, 'A must eventually reject');
    assert.match(rejectedErr.message, /Pairing timed out/);
    assert.equal(resolved, false, 'A must never resolve — the library never stores mid-handshake either way');
  } finally {
    t.mock.timers.reset();
  }
});

test('QR path: an expectedCommit mismatch still aborts before admitPartner is ever consulted', async () => {
  const transport = createRawTransport();
  let admitCalls = 0;
  const B = createPairing({ keyStore: createMemoryKeyStore(), transport });
  const attempt = B.joinPairing('WOLF-AD18', UUID_B, () => {}, {
    expectedCommit: await random32Base64(), // will not match the wire commit below
    admitPartner: async () => {
      admitCalls += 1;
      return true;
    },
  });
  const rejection = assert.rejects(() => attempt, (err) => err.code === QR_COMMITMENT_MISMATCH_CODE);

  await new Promise((r) => setTimeout(r, 20));
  transport.emit('pair_commit', { userId: UUID_A, commit: await random32Base64() });

  await rejection;
  assert.equal(admitCalls, 0, 'admitPartner must never be consulted once a QR commitment mismatch aborts first');
});

test('exported constants: PARTNER_NOT_ADMITTED_* / PEER_REFUSED_* are reachable via the package index', () => {
  assert.equal(typeof PARTNER_NOT_ADMITTED_ERROR, 'string');
  assert.equal(typeof PEER_REFUSED_ERROR, 'string');
  assert.equal(PARTNER_NOT_ADMITTED_CODE, 'PARTNER_NOT_ADMITTED');
  assert.equal(PEER_REFUSED_CODE, 'PEER_REFUSED');
  assert.equal(pairingNamespace.PARTNER_NOT_ADMITTED_ERROR, PARTNER_NOT_ADMITTED_ERROR);
  assert.equal(pairingNamespace.PARTNER_NOT_ADMITTED_CODE, PARTNER_NOT_ADMITTED_CODE);
  assert.equal(pairingNamespace.PEER_REFUSED_ERROR, PEER_REFUSED_ERROR);
  assert.equal(pairingNamespace.PEER_REFUSED_CODE, PEER_REFUSED_CODE);
});
