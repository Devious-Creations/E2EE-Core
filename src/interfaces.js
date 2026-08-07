// interfaces.js — the two platform seams this package is parameterised over.
//
// In the app these are backed by `expo-secure-store` (KeyStore) and
// Supabase Realtime broadcast channels (Transport). The crypto core knows
// NOTHING about either — you inject an implementation. That is the whole reason
// the encryption layer is auditable in isolation: swap in the in-memory
// adapters (see ../adapters) and every protocol runs with zero platform deps.

/**
 * Persistent, ideally hardware-backed secret storage. Keys and small secrets
 * (the wrapped DEK, ratchet state, pairing roots) are stored here as strings.
 *
 * The app implementation is the device keychain / keystore via expo-secure-store.
 * Values are opaque strings (this package base64-encodes any bytes before
 * handing them over).
 *
 * @typedef {Object} KeyStore
 * @property {(key: string) => Promise<string|null>} getItem  Resolve to the stored
 *   value, or `null` if the slot is genuinely absent. A `null` resolution is a
 *   POSITIVE answer — "keystore reachable, slot absent" — never a stand-in for
 *   a read failure. Any failure to determine the true state of the slot
 *   (locked keystore, an invalidated hardware-backed key, a platform error)
 *   MUST throw/reject instead of resolving `null`; callers rely on this to
 *   distinguish "nothing stored" from "couldn't read" (see
 *   `docs/subsystems/key-hierarchy.md`, the store-then-read-back invariant in
 *   `dynamicKeys.js`).
 * @property {(key: string, value: string) => Promise<void>} setItem  Store/overwrite.
 *   MUST throw/reject on write failure — a caller that awaits `setItem` and
 *   sees it resolve is entitled to assume the write was accepted.
 * @property {(key: string) => Promise<void>} removeItem  Delete (no-op if absent).
 *   MUST throw/reject on delete failure — the crypto-shred paths
 *   (`cryptoShredDynamic`, `clearDEK`, `clearAllDynamicKeys`) report success
 *   on the strength of a resolved `removeItem`; a silent failure there means
 *   a shred that reports done while the key is still on the device.
 */

/**
 * A best-effort, ordered-ish message transport used ONLY for the interactive
 * pairing handshake (ephemeral X25519 exchange + SAS). It carries public
 * handshake messages between two devices that don't yet share a key — so it is
 * explicitly UNTRUSTED. Confidentiality and authenticity of the final pairing
 * come from the handshake + the out-of-band Short Authentication String, not
 * from the transport.
 *
 * The app implementation is a Supabase Realtime broadcast channel scoped to the
 * pairing code.
 *
 * @typedef {Object} Transport
 * @property {(event: string, payload: object) => Promise<void>|void} send  Broadcast
 *   a handshake message to the other party (not echoed back to the sender).
 * @property {(event: string, handler: (payload: object) => void) => void} on  Subscribe
 *   to inbound messages of `event`.
 * @property {() => Promise<void>|void} close  Tear the channel down.
 * @property {(handler: (message?: string) => void) => void} [onError]  OPTIONAL:
 *   register a handler for fatal connection loss. A transport that can detect
 *   it (e.g. a Realtime channel's error status) should call the handler so an
 *   in-flight handshake fails immediately instead of waiting out its timeout.
 */

export {};
