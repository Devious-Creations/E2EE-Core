// pairing.js — the interactive pairing handshake: an ephemeral X25519 key
// exchange authenticated by a Short Authentication String (SAS).
//
// WHAT THIS IS
// Two devices that share no prior secret establish a 32-byte pairing root key
// over an UNTRUSTED transport. Each side generates a fresh, ephemeral X25519
// keypair; the initiator first sends a *commitment* to its public key
// (sha256(pk)) and only reveals the key after the joiner has committed to its
// own by publishing it. Both sides then derive the same shared key (X25519 +
// HSalsa20) and a 6-digit SAS bound to the whole transcript. The user compares
// the SAS out-of-band (read it aloud / eyeball both screens); a match proves no
// machine-in-the-middle sits between them. Only then does the caller persist the
// pairing (storePairing), which is the moment trust is committed.
//
// Protocol v2 (committed key exchange with SAS verification):
//   1. initiator → pair_commit   { userId, commit: sha256(pk_I) }
//   2. joiner    → pair_response { userId, publicKey: pk_J }
//   3. initiator → pair_reveal   { userId, publicKey: pk_I }   (joiner checks the commitment)
//   4. both      → pair_confirm  { userId, mac: HMAC(K, role|ids) }  (key confirmation)
//   5. both devices display a 6-digit SAS derived from the transcript; the user
//      must compare it with the partner out-of-band and explicitly confirm
//      before the pairing is stored (the caller does this via storePairing).
//
// The commitment stops a MITM from grinding its keys to collide the SAS; the
// handshake is locked to the first responder and ANY second identity (or a
// conflicting key/commit) aborts. In the app the channel was also a private,
// authenticated-only Realtime channel — but that is a transport hardening
// detail, NOT where the security comes from.
//
// THE TRANSPORT IS UNTRUSTED
// The injected Transport carries these public messages between two devices that
// do not yet share a key. It can reorder, drop, duplicate, or forge messages;
// none of that can break the pairing. Confidentiality and authenticity of the
// final key come entirely from the committed X25519 exchange plus the
// out-of-band SAS comparison — never from the transport. In the app the
// Transport is a Supabase Realtime broadcast channel scoped to the pairing code;
// here it is injected (see ./interfaces.js).
//
// PERSISTENCE
// The derived pairing root key persists through an INJECTED KeyStore
// (getItem/setItem/removeItem over opaque strings). In the app this is the
// device keychain via expo-secure-store; for tests/audit inject the in-memory
// adapter. The key strings ('relay_pairings', 'relay_active_partner',
// 'pairing_key_<id>', and the legacy slots) are preserved verbatim.
//
// This is a faithful extraction of the app's pairingAuth.js. The ONLY changes
// are the two platform seams: the crypto wrapper (now ./primitives.js), and the
// SecureStore + Supabase channel (now the injected KeyStore + Transport). The
// handshake ordering, commitment, key agreement, SAS derivation, key-confirm
// MACs, and all constants are unchanged. App-only side effects that cannot be
// separated from the transport/relay layer (double-ratchet purge, offline-queue
// purge, best-effort server-side pairing registration) are dropped and flagged
// with TODO comments; they are not part of the cryptographic handshake.

import * as primitives from './primitives.js';

// ── Constants (verbatim from the app: relayConfig.js + pairingAuth.js) ────────

/** @type {number} Max time to complete a pairing handshake (ms). */
export const PAIRING_TIMEOUT_MS = 120_000;

const PROTO = 'e2ee-core-pair-v2';
const REPEAT_MS = 2000;

// Exported error messages — the message text is for humans (a UI string);
// each has a stable, machine-readable err.code (below, attached at every throw
// site via fail()) for callers to branch on instead of matching on message
// text, which silently breaks if the copy is ever reworded. Message text is
// UNCHANGED from before these were exported — existing callers that still
// match on message text keep working.
/** @type {string} */
export const CONTESTED_ERROR =
  'Pairing contested — more than one device answered this code. Generate a new code and try again.';
/** @type {string} */
export const TAMPERED_ERROR =
  'Pairing aborted — the key exchange failed verification. Generate a new code and try again.';

/** @type {string} */
export const CONTESTED_CODE = 'CONTESTED';
/** @type {string} */
export const TAMPERED_CODE = 'TAMPERED';

// Distinct, exported error message for an out-of-band (QR-delivered) commitment
// mismatch — the caller must be able to tell this apart from CONTESTED_ERROR/
// TAMPERED_ERROR so it can render a louder UI: this is not "a duplicate device
// answered" or "the wire failed verification", it is "the thing that scanned
// the QR is not who's on the other end of this transport at all".
/** @type {string} */
export const QR_COMMITMENT_MISMATCH_ERROR =
  'Pairing aborted — the scanned code does not match this device. Do not proceed; scan the correct code.';

// A stable, machine-readable code on top of the message above — the message
// text is for humans (a UI string), the code is for callers to branch on.
// This was the first exported pairing error in this file, setting the
// precedent (CONTESTED_ERROR/TAMPERED_ERROR are now retrofitted with codes
// the same way — CONTESTED_CODE/TAMPERED_CODE above).
export const QR_COMMITMENT_MISMATCH_CODE = 'QR_COMMITMENT_MISMATCH';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** @type {string[]} Memorable 4-letter words for pairing code generation. */
export const PAIRING_WORDS = [
  'WOLF', 'BEAR', 'HAWK', 'LION', 'FROG', 'FISH', 'DEER', 'DUCK',
  'CROW', 'GOAT', 'SEAL', 'MOTH', 'WASP', 'DOVE', 'LYNX', 'MULE',
  'SWAN', 'BULL', 'COLT', 'FOAL', 'HARE', 'TOAD', 'WREN', 'LARK',
  'PUMA', 'NEWT', 'CRAB', 'CLAM', 'KITE', 'ORCA', 'IBIS', 'PIKE',
  'BASS', 'RUST', 'BOLT', 'IRON', 'JADE', 'ONYX', 'RUBY', 'OPAL',
  'GOLD', 'GALE', 'SURF', 'TIDE', 'DUSK', 'DAWN', 'FERN', 'PALM',
];

// ── Pure helpers (no seams) ───────────────────────────────────────────────────

/**
 * Generate a human-readable pairing code: WORD-WORD-NNNN (e.g. WOLF-DAWN-7392).
 * The code is a rendezvous identifier, not the trust anchor — trust comes
 * from the SAS comparison after the committed key exchange. Two words + four
 * digits give 48*48*10000 ≈ 23M codes: with the 120s code lifetime that makes
 * online guessing of an active rendezvous statistically dead even without a
 * server-side join rate limit (DeviousByDC#433 — the old WORD-NNNN space of
 * 480k was small enough to worry about).
 * @returns {Promise<string>}
 */
export async function generatePairingCode() {
  const wordIdx = await primitives.randomInt(PAIRING_WORDS.length);
  const wordIdx2 = await primitives.randomInt(PAIRING_WORDS.length);
  const num = await primitives.randomInt(10000);
  return `${PAIRING_WORDS[wordIdx]}-${PAIRING_WORDS[wordIdx2]}-${String(num).padStart(4, '0')}`;
}

/**
 * Deterministic relay channel name from two user IDs.
 * Sorts UUIDs so both sides compute the same channel.
 * @param {string} userId1
 * @param {string} userId2
 * @returns {string}
 */
export function buildRelayChannelName(userId1, userId2) {
  const [a, b] = [userId1, userId2].sort();
  return `relay:${a}:${b}`;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Build a pairing controller bound to a KeyStore (persists the pairing root
 * key) and a Transport (carries the public handshake messages to the OTHER
 * party). Both seams are injected — this module imports neither expo-secure-store
 * nor Supabase. The Transport may be omitted for a controller that only manages
 * stored pairings (a handshake attempt without one throws).
 *
 * The Transport is expected to already be scoped to the pairing code (in the app
 * a `supabase.channel('pairing:<code>')`); the crypto core does not build channel
 * names from the code — it only uses the code inside the SAS transcript binding.
 *
 * @param {{ keyStore: import('./interfaces.js').KeyStore,
 *           transport: import('./interfaces.js').Transport }} deps
 */
export function createPairing({ keyStore, transport } = {}) {
  if (!keyStore || typeof keyStore.getItem !== 'function') {
    throw new Error('[pairing] createPairing requires a KeyStore { getItem, setItem, removeItem }');
  }
  // The transport is only needed to run a handshake — a controller built just to
  // manage stored pairings (list/rotate/remove/clear) may omit it. The check
  // lives in performHandshake.

  // SecureStore seam → KeyStore. Same key strings as the app.
  const secureGet = (key) => keyStore.getItem(key);
  const secureSet = (key, value) => keyStore.setItem(key, value);
  const secureDelete = (key) => keyStore.removeItem(key);

  // ── Handshake cancellation (CR-26) ──────────────────────────────────────────
  // One handshake at a time per controller: starting a new one (or resetting the
  // pairing UI) aborts the previous, so an abandoned attempt can neither hold its
  // transport subscribed for the full timeout nor reject minutes later into a
  // newer attempt's UI state. Instance-scoped (was a module global in the app).
  let _abortActiveHandshake = null;

  function cancelActiveHandshake() {
    const abort = _abortActiveHandshake;
    _abortActiveHandshake = null;
    if (abort) abort();
  }

  /**
   * Initiate pairing (device that GENERATES the code).
   * Resolves once keys are exchanged and confirmed — the pairing is NOT stored
   * yet: the caller must show `sas` for out-of-band comparison and call
   * storePairing() only after the user confirms the match.
   * @param {string} code
   * @param {string} userId
   * @param {(state: string) => void} onStateChange
   * @param {{ onCommit?: (commit: string) => void }} [options] - a trailing
   *   options bag, NOT a positional callback: a role-dependent value in a
   *   shared positional slot (this vs. joinPairing's expectedCommit, a
   *   string) is a footgun, and a future 5th positional would make this
   *   unmaintainable. `options.onCommit`, if given, is called once with the
   *   base64 commitment (sha256(pk_I)) as soon as it exists, so the caller can
   *   render it into a QR for out-of-band delivery to the joiner. It is
   *   validated at the top of performHandshake (must be a function if
   *   present) and, once invoked, can never break or stall the handshake —
   *   see performHandshake for the guard, including the async-rejection case.
   * @returns {Promise<{ role: string, partnerId: string, sharedKey: string, channelName: string, sas: string }>}
   */
  function initiatePairing(code, userId, onStateChange, options = {}) {
    return performHandshake(code, userId, 'initiator', onStateChange, options);
  }

  /**
   * Join pairing (device that ENTERS the code). Same resolve contract as
   * initiatePairing (pending pairing + SAS, nothing stored yet).
   * @param {string} code
   * @param {string} userId
   * @param {(state: string) => void} onStateChange
   * @param {{ expectedCommit?: string }} [options] - trailing options bag (see
   *   initiatePairing's `options` doc for why). `options.expectedCommit`, if
   *   given, is the base64 commitment obtained out-of-band (e.g. scanned from
   *   the initiator's QR) and is validated at the top of performHandshake
   *   (must be a string if present — a caller passing `null`/non-string is a
   *   programmer bug, not an attack, and is rejected as such, not silently
   *   ignored or treated as a mismatch). When present: the wire's
   *   `pair_commit` is checked against it, decoded and byte-compared (abort
   *   before responding on a mismatch), and the `pair_reveal`'d key is
   *   independently re-hashed and checked against it too (abort before
   *   deriving a session) — both are fatal, non-recoverable
   *   `QR_COMMITMENT_MISMATCH_ERROR` (`err.code ===
   *   'QR_COMMITMENT_MISMATCH'`) aborts. Omitted: no behavioural change on
   *   the shipped (link/typed-code) path.
   * @returns {Promise<{ role: string, partnerId: string, sharedKey: string, channelName: string, sas: string }>}
   */
  function joinPairing(code, userId, onStateChange, options = {}) {
    return performHandshake(code, userId, 'joiner', onStateChange, options);
  }

  async function performHandshake(code, userId, role, onStateChange, options = {}) {
    const { onCommit, expectedCommit } = options ?? {};
    // An unknown key is almost always a typo (`expectedCommmit`), and silently
    // ignoring it reads as "no verification requested" — i.e. the handshake
    // runs unauthenticated. That is the same silent-fail-open class the
    // validation below closes, so reject it rather than guess the intent.
    for (const key of Object.keys(options ?? {})) {
      if (key !== 'onCommit' && key !== 'expectedCommit') {
        throw new Error(`[pairing] unknown option: ${key}`);
      }
    }
    // Validate the two new hooks BEFORE anything else runs. Both slots used to
    // fail OPEN: a wrong-typed onCommit was silently ignored (QR never
    // rendered, handshake proceeds unauthenticated with no signal to the
    // caller) and a wrong-typed expectedCommit (e.g. a `null` from a caller's
    // `useState(null)`) would previously have been compared as a value and
    // could render an attack warning for what is a programmer bug. Both are
    // now rejected immediately, before any transport activity or key
    // generation — a caller wiring bug must never be indistinguishable from
    // "the handshake ran and decided something was fine" or from "a MITM was
    // detected". (performHandshake is async, so this surfaces as a rejected
    // promise, not a synchronous throw: callers must await or .catch it.)
    if (onCommit !== undefined && typeof onCommit !== 'function') {
      throw new Error('[pairing] options.onCommit must be a function');
    }
    // Shape-check the digest itself, not merely "a non-empty string". Anything
    // that is not a base64-encoded 32 bytes cannot be a commitment, and letting
    // it through means the caller's own encoding bug (base64url from a QR
    // round-trip, a truncated value) surfaces to the USER as "the scanned code
    // does not match this device" — an attack warning for a wiring mistake.
    if (
      expectedCommit !== undefined &&
      (typeof expectedCommit !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(expectedCommit))
    ) {
      throw new Error('[pairing] options.expectedCommit must be a base64-encoded 32-byte digest');
    }

    if (!transport || typeof transport.send !== 'function' || typeof transport.on !== 'function') {
      throw new Error('[pairing] a handshake requires a Transport { send, on, close }');
    }
    cancelActiveHandshake();

    // Only the joiner jumps straight to 'exchanging'. The initiator stays in
    // 'waiting' (so the code remains visible) until the partner responds.
    if (role === 'joiner') {
      onStateChange('exchanging');
    }

    // Generate an EPHEMERAL keypair. It is never persisted — the secret lives
    // only in this closure, so concurrent handshakes can never cross-derive
    // (the app kept the secret in a local to dodge a shared SecureStore slot;
    // here there is no shared slot at all).
    const keypair = await primitives.generateKeypair();
    const myPublicKey = await primitives.encodeBase64(keypair.publicKey);
    const mySecretBytes = keypair.secretKey;
    const myCommit = await primitives.encodeBase64(
      await primitives.sha256Bytes(await primitives.decodeBase64(myPublicKey)),
    );

    // Hand the commitment to the caller as soon as it exists, so it can be
    // rendered into a QR for out-of-band delivery — this fires once, on the
    // INITIATOR path only, before the pair_commit broadcast loop starts below.
    // A throwing or slow SYNCHRONOUS callback is caught and cannot break the
    // handshake or eat into its timeout budget — it is NOT true that it "can
    // never stall": a slow synchronous callback still blocks this turn of the
    // event loop for as long as it runs, same as any other synchronous call
    // here. An ASYNC callback that later REJECTS is the sharper danger: that
    // rejection happens after this try/catch has already returned, so it
    // would otherwise become an unhandled promise rejection — which, under
    // Node's default, terminates the process. QR rendering is exactly the
    // kind of thing a caller writes as async, so we explicitly attach a
    // rejection handler to any thenable onCommit returns.
    if (role === 'initiator' && onCommit) {
      try {
        const r = onCommit(myCommit);
        if (r && typeof r.then === 'function') r.then(undefined, () => {});
      } catch {
        // Caller's QR-rendering callback misbehaved — never let that abort or
        // stall a pairing attempt that is otherwise fine.
      }
    }

    // Decode a base64 field that must be exactly 32 bytes; null if malformed.
    async function decode32(b64) {
      if (typeof b64 !== 'string') return null;
      try {
        const bytes = await primitives.decodeBase64(b64);
        return bytes.length === 32 ? bytes : null;
      } catch {
        return null;
      }
    }

    return new Promise((resolve, reject) => {
      let timeout;
      let repeatTimer;
      let settled = false;
      let partnerId = null; // locked to the first responding identity
      let partnerCommit = null; // joiner side: initiator's key commitment
      let partnerPublicKey = null; // base64, set at response (initiator) / reveal (joiner)
      let session = null; // { sharedKeyBase64, sharedKeyBytes, sas }

      // channel.send({type:'broadcast', event, payload}) → transport.send(event, payload).
      // The transport broadcasts to the OTHER party only (never echoed back).
      const send = (event, payload) => transport.send(event, { userId, ...payload });

      function cleanup() {
        if (_abortActiveHandshake === abortSelf) _abortActiveHandshake = null;
        if (timeout) clearTimeout(timeout);
        if (repeatTimer) clearInterval(repeatTimer);
        // supabase.removeChannel(channel) → transport.close().
        transport.close();
      }

      function fail(message, code) {
        if (settled) return;
        settled = true;
        cleanup();
        const err = new Error(message);
        if (code) err.code = code;
        reject(err);
      }

      const abortSelf = () => fail('Pairing cancelled');
      _abortActiveHandshake = abortSelf;

      function succeed() {
        if (settled) return;
        settled = true;
        cleanup();
        resolve({
          role,
          partnerId,
          sharedKey: session.sharedKeyBase64,
          channelName: buildRelayChannelName(userId, partnerId),
          sas: session.sas,
        });
      }

      function startRepeat(fn) {
        if (repeatTimer) clearInterval(repeatTimer);
        fn();
        repeatTimer = setInterval(() => {
          if (!settled) fn();
        }, REPEAT_MS);
      }

      function stopRepeat() {
        if (repeatTimer) clearInterval(repeatTimer);
        repeatTimer = null;
      }

      // Lock the handshake to the first partner identity we see. Returns false if
      // the message should be ignored; aborts the whole handshake if a SECOND
      // identity shows up (someone else is on the code).
      function lockOrVerifyPartner(id) {
        if (typeof id !== 'string' || !UUID_RE.test(id) || id === userId) return false;
        if (partnerId === null) {
          partnerId = id;
          return true;
        }
        if (partnerId !== id) {
          fail(CONTESTED_ERROR, CONTESTED_CODE);
          return false;
        }
        return true;
      }

      // Shared key + SAS from the full transcript. The SAS binds the code, both
      // identities, and both public keys — a MITM bridging two sessions cannot
      // make both ends display the same number (the commitment removes its
      // ability to grind keys after seeing the other side's).
      async function deriveSession(initiatorId, joinerId, initiatorPub, joinerPub) {
        const theirPub = await primitives.decodeBase64(
          role === 'initiator' ? joinerPub : initiatorPub,
        );
        const sharedKeyBytes = await primitives.deriveSharedKey(theirPub, mySecretBytes);
        const sharedKeyBase64 = await primitives.encodeBase64(sharedKeyBytes);
        const transcript = `${PROTO}|sas|${code}|${initiatorId}|${joinerId}|${initiatorPub}|${joinerPub}`;
        const digest = await primitives.sha256Bytes(await primitives.encodeUTF8(transcript));
        const view = new DataView(digest.buffer, digest.byteOffset, 4);
        // 2^32 % 1e6 leaves a ~0.02% bias — irrelevant at SAS scale.
        const sas = String(view.getUint32(0) % 1_000_000).padStart(6, '0');
        return { sharedKeyBase64, sharedKeyBytes, sas };
      }

      // Key-confirmation MAC, bound to the sender's role and both identities so
      // mismatched sessions (or swapped userIds) fail closed before the SAS step.
      async function confirmMac(forRole, initiatorId, joinerId) {
        const msg = `${PROTO}|confirm|${forRole}|${initiatorId}|${joinerId}`;
        return primitives.hmacSha256(session.sharedKeyBytes, await primitives.encodeUTF8(msg));
      }

      async function verifyConfirm(payload, senderRole) {
        if (!session) return false;
        const theirMac = await decode32(payload.mac);
        if (!theirMac) return false;
        const initiatorId = role === 'initiator' ? userId : partnerId;
        const joinerId = role === 'initiator' ? partnerId : userId;
        const expected = await confirmMac(senderRole, initiatorId, joinerId);
        return primitives.timingSafeEqual(theirMac, expected);
      }

      timeout = setTimeout(() => fail('Pairing timed out'), PAIRING_TIMEOUT_MS);

      // channel.on('broadcast', { event }, cb) → transport.on(event, cb).
      // The Transport delivers the raw payload object (the app's Realtime callback
      // wrapped it as `{ payload }`; here the payload IS the argument).
      transport.on('pair_commit', async (payload) => {
        if (settled || !payload) return;
        if (role === 'initiator') {
          // We are the only initiator on this code — fail closed.
          if (payload.userId !== userId) fail(CONTESTED_ERROR, CONTESTED_CODE);
          return;
        }
        if (!lockOrVerifyPartner(payload.userId)) return;
        const commitBytes = await decode32(payload.commit);
        if (settled) return;
        if (!commitBytes) {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        if (partnerCommit === null) {
          // Out-of-band commitment check (QR path) — the PRIMARY defence: if
          // the caller supplied expectedCommit, the wire's commit must match
          // it BEFORE we send pair_response — otherwise we'd be responding to
          // whoever holds the untrusted transport, not the device the human
          // actually scanned. This pins the wire commit to the out-of-band
          // value before any response is sent, so a MITM that consistently
          // substitutes both pair_commit and pair_reveal never even reaches
          // the pair_reveal re-check below — it is stopped here. Fatal,
          // fail-fast: no response leaks to an impostor. This gate must never
          // be removed as a mere "fail-fast nicety" — it is the check that
          // actually stops a consistent-substitution MITM; the reveal-stage
          // re-hash is defence-in-depth that preserves the same guarantee if
          // this gate is ever weakened, not the primary mechanism.
          //
          // Decode-and-byte-compare, not string-compare: a caller-side QR
          // encoder may re-encode the same digest with different padding or a
          // cosmetically different (but equivalent) base64 variant — a raw
          // string compare would abort an honest pairing with an attack
          // message on routine re-encoding. commitBytes is already decoded
          // above; decode expectedCommit the same way and compare bytes.
          if (expectedCommit !== undefined) {
            const expectedCommitBytes = await decode32(expectedCommit);
            if (settled) return;
            if (!expectedCommitBytes || !primitives.timingSafeEqual(commitBytes, expectedCommitBytes)) {
              fail(QR_COMMITMENT_MISMATCH_ERROR, QR_COMMITMENT_MISMATCH_CODE);
              return;
            }
          }
          partnerCommit = payload.commit;
          // Repeat our response until the initiator reveals its key.
          startRepeat(() => send('pair_response', { publicKey: myPublicKey }));
        } else if (partnerCommit !== payload.commit) {
          fail(CONTESTED_ERROR, CONTESTED_CODE);
        }
        // Duplicate commit (initiator's repeat loop) — already responding.
      });

      transport.on('pair_response', async (payload) => {
        if (settled || !payload) return;
        if (role === 'joiner') {
          // A second joiner is answering the same code — fail closed.
          if (payload.userId !== userId) fail(CONTESTED_ERROR, CONTESTED_CODE);
          return;
        }
        if (!lockOrVerifyPartner(payload.userId)) return;
        if (partnerPublicKey !== null) {
          if (payload.publicKey !== partnerPublicKey) {
            fail(CONTESTED_ERROR, CONTESTED_CODE);
          } else {
            // Duplicate response — they missed our reveal; resend it.
            send('pair_reveal', { publicKey: myPublicKey });
          }
          return;
        }
        const pkBytes = await decode32(payload.publicKey);
        if (settled) return;
        if (!pkBytes) {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        partnerPublicKey = payload.publicKey;
        stopRepeat();
        onStateChange('exchanging');
        try {
          session = await deriveSession(userId, partnerId, myPublicKey, partnerPublicKey);
        } catch {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        if (settled) return;
        send('pair_reveal', { publicKey: myPublicKey });
      });

      transport.on('pair_reveal', async (payload) => {
        if (settled || !payload || role !== 'joiner') return;
        if (!lockOrVerifyPartner(payload.userId)) return;
        if (partnerCommit === null) return; // reveal before commit — ignore
        if (partnerPublicKey !== null) {
          if (payload.publicKey !== partnerPublicKey) fail(CONTESTED_ERROR, CONTESTED_CODE);
          return; // duplicate reveal — confirm loop already running
        }
        const pkBytes = await decode32(payload.publicKey);
        if (settled) return;
        if (!pkBytes) {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        const revealHash = await primitives.sha256Bytes(pkBytes);
        if (settled) return;
        // Out-of-band commitment check (QR path) — DEFENCE-IN-DEPTH, run
        // FIRST here but not the primary mechanism: the pair_commit-stage
        // gate above is what actually stops a consistent-substitution MITM
        // (it never lets such a MITM's pair_commit through, so it never
        // reaches this handler at all). This re-check exists to preserve the
        // same guarantee — and to surface the more specific
        // QR_COMMITMENT_MISMATCH_ERROR rather than TAMPERED_ERROR — if that
        // gate is ever weakened or bypassed; it must never be relied on as
        // the sole check. Verify the revealed key's hash against
        // expectedCommit directly, never against the already-stored
        // partnerCommit (which travelled over the same untrusted transport
        // and, absent the gate above, could have been substituted alongside
        // this reveal). Fatal, before any session/key material exists.
        if (expectedCommit !== undefined) {
          const expectedCommitBytes = await decode32(expectedCommit);
          if (settled) return;
          if (!expectedCommitBytes || !primitives.timingSafeEqual(revealHash, expectedCommitBytes)) {
            fail(QR_COMMITMENT_MISMATCH_ERROR, QR_COMMITMENT_MISMATCH_CODE);
            return;
          }
        }
        // The revealed key must match the commitment sent before our key —
        // otherwise the initiator chose its key after seeing ours.
        const commitBytes = await decode32(partnerCommit);
        if (settled) return;
        if (!commitBytes || !primitives.timingSafeEqual(revealHash, commitBytes)) {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        partnerPublicKey = payload.publicKey;
        try {
          session = await deriveSession(partnerId, userId, partnerPublicKey, myPublicKey);
        } catch {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        if (settled) return;
        const mac = await primitives.encodeBase64(await confirmMac('joiner', partnerId, userId));
        if (settled) return;
        // Repeat until the initiator's confirmation arrives.
        startRepeat(() => send('pair_confirm', { mac }));
      });

      transport.on('pair_confirm', async (payload) => {
        if (settled || !payload) return;
        if (!lockOrVerifyPartner(payload.userId)) return;
        const senderRole = role === 'initiator' ? 'joiner' : 'initiator';
        const ok = await verifyConfirm(payload, senderRole);
        if (settled) return;
        if (!ok) {
          fail(TAMPERED_ERROR, TAMPERED_CODE);
          return;
        }
        if (role === 'initiator') {
          // Answer with our own confirmation, then hand off to the SAS step.
          const initiatorId = userId;
          const mac = await primitives.encodeBase64(
            await confirmMac('initiator', initiatorId, partnerId),
          );
          if (settled) return;
          // #262: flush the confirm to the joiner BEFORE succeed() runs
          // cleanup()→transport.close(). Without awaiting, teardown races the
          // broadcast flush and can drop this single confirm — the joiner then
          // times out and never stores the pairing while we already showed the
          // SAS and stored ours (asymmetric pairing).
          await send('pair_confirm', { mac });
          if (settled) return;
        } else {
          stopRepeat();
        }
        succeed();
      });

      // A Transport that can detect fatal connection loss surfaces it through
      // the optional onError seam — the handshake then fails immediately
      // instead of letting the full timeout fire (the app's Realtime channel
      // reports CHANNEL_ERROR / TIMED_OUT through this).
      if (typeof transport.onError === 'function') {
        transport.onError((message) =>
          fail(typeof message === 'string' && message ? message : 'Pairing channel error'),
        );
      }

      // The caller hands us a LIVE transport (the app awaits the Realtime
      // channel's SUBSCRIBED status before starting the handshake), so the
      // initiator starts its commit loop now. Broadcast the commitment
      // immediately, then every 2s until a partner responds — covers transport
      // delivery races. The joiner waits for a commit (repeated by the
      // initiator).
      if (role === 'initiator') {
        startRepeat(() => send('pair_commit', { commit: myCommit }));
      }
    });
  }

  // ── Stored pairing data ──────────────────────────────────────────────────────
  // Multi-partner: pairing list stored as JSON array in the KeyStore.
  // Each entry: { id, partnerId, channelName }
  // Shared keys stored separately: `pairing_key_${id}` → base64 key string.
  // Legacy single-partner keys are migrated on first read.

  /**
   * Migrate legacy single-partner KeyStore keys to the multi-partner format.
   * Runs once — after migration the old keys are removed.
   */
  async function migrateLegacyPairing() {
    const legacy = await secureGet('relay_partner_id');
    if (!legacy) return; // nothing to migrate

    const sharedKey = await secureGet('relay_shared_key');
    const channelName = await secureGet('relay_channel_name');
    if (!sharedKey || !channelName) {
      // Incomplete legacy data — just clean up.
      await secureDelete('relay_partner_id');
      await secureDelete('relay_shared_key');
      await secureDelete('relay_channel_name');
      return;
    }

    const id = await primitives.generateUUID();
    const entry = { id, partnerId: legacy, channelName };

    await secureSet('relay_pairings', JSON.stringify([entry]));
    await secureSet(`pairing_key_${id}`, sharedKey);
    await secureSet('relay_active_partner', id);

    await secureDelete('relay_partner_id');
    await secureDelete('relay_shared_key');
    await secureDelete('relay_channel_name');
  }

  /**
   * Get all stored pairings.
   * @returns {Promise<Array<{ id: string, partnerId: string, channelName: string }>>}
   */
  async function getStoredPairings() {
    await migrateLegacyPairing();
    const raw = await secureGet('relay_pairings');
    if (!raw) return [];
    try {
      return JSON.parse(raw);
    } catch {
      return [];
    }
  }

  /**
   * Get the active partner ID (the one currently connected to relay).
   * @returns {Promise<string|null>}
   */
  async function getActivePartnerId() {
    return secureGet('relay_active_partner');
  }

  /**
   * Set the active partner by pairing ID.
   * @param {string} pairingId
   */
  async function setActivePartnerId(pairingId) {
    await secureSet('relay_active_partner', pairingId);
  }

  /**
   * Retrieve the shared (root) key for a specific pairing.
   * @param {string} pairingId
   * @returns {Promise<string|null>}
   */
  async function getSharedKey(pairingId) {
    return secureGet(`pairing_key_${pairingId}`);
  }

  /**
   * Backwards-compatible: get the single active pairing (or null).
   * @returns {Promise<{ partnerId: string, sharedKey: string, channelName: string } | null>}
   */
  async function getStoredPairing() {
    const pairings = await getStoredPairings();
    if (pairings.length === 0) return null;

    const activeId = await getActivePartnerId();
    const active = activeId ? pairings.find((p) => p.id === activeId) : pairings[0];

    if (!active) return null;

    const sharedKey = await getSharedKey(active.id);
    if (!sharedKey) return null;

    return { partnerId: active.partnerId, sharedKey, channelName: active.channelName };
  }

  /**
   * Store a new pairing after a successful handshake AND the out-of-band SAS
   * confirmation. Appends to the pairings list and sets it active.
   *
   * NOTE (dropped app coupling): the app also, on re-pair rotation, purged the
   * relay offline queue and the double-ratchet chain state under both the old
   * and new channel (so ciphertext queued under the old root can't be silently
   * dropped), and best-effort registered the pairing server-side for premium
   * propagation. Those are relay/transport concerns outside this crypto core; a
   * consumer that also runs the ratchet must clear its state on rotation.
   *
   * @param {string} partnerId - remote user ID
   * @param {string} sharedKey - base64 shared (root) secret
   * @param {string} channelName - relay channel name
   * @returns {Promise<string>} the pairing ID
   */
  async function storePairing(partnerId, sharedKey, channelName) {
    const id = await primitives.generateUUID();

    const pairings = await getStoredPairings();
    // Prevent duplicate pairings with the same partner.
    const existing = pairings.find((p) => p.partnerId === partnerId);
    if (existing) {
      // TODO(app coupling): re-pair rotation — clear the relay message queue and
      // ratchet state for existing.channelName AND channelName BEFORE rotating
      // the key. Dropped here (no ratchet/queue in this crypto core).
      await secureSet(`pairing_key_${existing.id}`, sharedKey);
      existing.channelName = channelName;
      await secureSet('relay_pairings', JSON.stringify(pairings));
      await setActivePartnerId(existing.id);
      return existing.id;
    }

    pairings.push({ id, partnerId, channelName });
    await secureSet('relay_pairings', JSON.stringify(pairings));
    await secureSet(`pairing_key_${id}`, sharedKey);
    await setActivePartnerId(id);
    return id;
  }

  /**
   * Persist the resolved dynamic id onto a stored pairing record.
   * @param {string} pairingId
   * @param {string} dynamicId
   */
  async function setPairingDynamicId(pairingId, dynamicId) {
    const pairings = await getStoredPairings();
    const rec = pairings.find((p) => p.id === pairingId);
    if (!rec) return;
    rec.dynamicId = dynamicId;
    await secureSet('relay_pairings', JSON.stringify(pairings));
  }

  /**
   * Update the nickname for a stored pairing.
   * @param {string} pairingId
   * @param {string|null} nickname
   */
  async function updatePairingNickname(pairingId, nickname) {
    const pairings = await getStoredPairings();
    const entry = pairings.find((p) => p.id === pairingId);
    if (!entry) return;
    entry.nickname = nickname || null;
    await secureSet('relay_pairings', JSON.stringify(pairings));
  }

  /**
   * Remove a specific pairing.
   *
   * NOTE (dropped app coupling): the app also best-effort unregistered the
   * pairing server-side and cleared the ratchet state for the channel. Those are
   * relay/transport concerns outside this crypto core.
   *
   * @param {string} pairingId
   */
  async function removePairing(pairingId) {
    const pairings = await getStoredPairings();
    const updated = pairings.filter((p) => p.id !== pairingId);
    await secureSet('relay_pairings', JSON.stringify(updated));
    await secureDelete(`pairing_key_${pairingId}`);

    // If we removed the active partner, switch to the next available.
    const activeId = await getActivePartnerId();
    if (activeId === pairingId) {
      if (updated.length > 0) {
        await setActivePartnerId(updated[0].id);
      } else {
        await secureDelete('relay_active_partner');
      }
    }
  }

  /**
   * Clear ALL pairing data from the KeyStore.
   *
   * NOTE (dropped app coupling): the app also cleared the stored relay keypair,
   * the per-channel last-seen cursor, and the ratchet state. Those live in the
   * relay/transport layer, not this crypto core.
   */
  async function clearPairing() {
    const pairings = await getStoredPairings();
    for (const p of pairings) {
      await secureDelete(`pairing_key_${p.id}`);
    }
    await secureDelete('relay_pairings');
    await secureDelete('relay_active_partner');

    // Also clean up any remaining legacy keys.
    await secureDelete('relay_partner_id');
    await secureDelete('relay_shared_key');
    await secureDelete('relay_channel_name');
  }

  return {
    // Pure helpers (also exported standalone above).
    generatePairingCode,
    buildRelayChannelName,
    // Handshake.
    initiatePairing,
    joinPairing,
    cancelActiveHandshake,
    // Stored pairing data (root key via the KeyStore).
    storePairing,
    getStoredPairings,
    getStoredPairing,
    getSharedKey,
    getActivePartnerId,
    setActivePartnerId,
    setPairingDynamicId,
    updatePairingNickname,
    removePairing,
    clearPairing,
  };
}
