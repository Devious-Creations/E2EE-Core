// index.js — public API of the end-to-end-encryption core.
//
// Two flavours of export:
//   - Namespaced modules (primitives.*, keyVault.*, ...) for browsing/auditing.
//   - The factory functions at top level for ergonomic use.
//
// The `pairing` module is exported lazily-friendly: it and `ratchet` are the two
// pieces parameterised over the Transport / KeyStore seams (see ./interfaces.js).

export * as primitives from './primitives.js';
export * as keyVault from './keyVault.js';
export * as sealing from './sealing.js';
export * as dynamicKeys from './dynamicKeys.js';
export * as ratchet from './ratchet.js';
export * as pairing from './pairing.js';

// Factories (bind the injected KeyStore / Transport).
export { createKeyVault } from './keyVault.js';
export { createDynamicKeys } from './dynamicKeys.js';
export { createRatchet } from './ratchet.js';
export { createPairing } from './pairing.js';
