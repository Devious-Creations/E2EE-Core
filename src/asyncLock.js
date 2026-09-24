// asyncLock.js — a tiny promise-chain mutex, factored out of the pattern
// `ratchet.js` already uses for its per-channel chain-state lock
// (`withLock`, keyed by channel there). This module gives any other seam in
// the package the same shape without copy-pasting it: `createLock()` returns
// a single-key `withLock(fn)` — there is no `lockKey` argument because a
// caller that only ever has ONE shared resource (e.g. `pairing.js`'s single
// `relay_pairings` blob) doesn't need a Map of keys, just one running chain.
// If a future caller needs multiple independent keys, keep `ratchet.js`'s
// own Map-based `withLock` as the pattern to copy — this file intentionally
// does not generalize to that case.

/**
 * @returns {(fn: () => Promise<any>) => Promise<any>} withLock — chains `fn`
 *   onto whatever is currently running so callers never interleave a
 *   read-modify-write of the same resource. An `fn` that throws/rejects does
 *   not wedge the lock for the next caller (the rejection is swallowed only
 *   for chaining purposes; the caller of `withLock` still sees its own
 *   rejection via the returned promise).
 */
export function createLock() {
  let tail = Promise.resolve();
  return function withLock(fn) {
    const next = tail.then(fn, fn);
    tail = next.catch(() => {});
    return next;
  };
}
