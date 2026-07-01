// adapters/index.js — in-memory implementations of the two platform seams.
// For tests, demos, and audit review only; a production deployment supplies its
// own KeyStore (OS keychain) and Transport (a real message channel).

export { createMemoryKeyStore } from './memoryKeyStore.js';
export { createMemoryTransportPair } from './memoryTransport.js';
