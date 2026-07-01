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
 *   value, or null if absent.
 * @property {(key: string, value: string) => Promise<void>} setItem  Store/overwrite.
 * @property {(key: string) => Promise<void>} removeItem  Delete (no-op if absent).
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
 */

export {};
