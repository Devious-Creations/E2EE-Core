// memoryTransport.js — an in-process pub/sub pair implementing the Transport
// contract, so the pairing handshake can run entirely in one process for tests,
// demos, and audit review.
//
// `createMemoryTransportPair()` returns two endpoints wired to each other: a
// message `send()` on one is delivered to the other's `on()` handlers (never
// echoed back to the sender — mirroring the app's `broadcast: { self: false }`).
// This is deliberately a dumb, untrusted pipe: the whole point of the handshake
// + SAS is that security does NOT depend on this transport.

/** @returns {[import('../src/interfaces.js').Transport, import('../src/interfaces.js').Transport]} */
export function createMemoryTransportPair() {
  const handlers = [new Map(), new Map()]; // per-endpoint: event -> Set<handler>
  let open = true;

  const endpoint = (self, peer) => ({
    send(event, payload) {
      if (!open) return;
      const set = handlers[peer].get(event);
      if (!set) return;
      // Deliver asynchronously so send() never re-enters a handler synchronously,
      // matching a real broadcast channel's next-tick delivery.
      const frozen = JSON.parse(JSON.stringify(payload));
      Promise.resolve().then(() => {
        if (!open) return;
        for (const h of set) h(frozen);
      });
    },
    on(event, handler) {
      if (!handlers[self].has(event)) handlers[self].set(event, new Set());
      handlers[self].get(event).add(handler);
    },
    close() {
      open = false;
    },
  });

  return [endpoint(0, 1), endpoint(1, 0)];
}
