// memoryKeyStore.js — an in-memory KeyStore for tests, demos, and audit review.
// NOT for production: a real deployment must back this with the OS keychain /
// secure enclave (the app uses expo-secure-store). This just satisfies the
// KeyStore contract so the crypto core runs with no platform dependency.

/** @returns {import('../src/interfaces.js').KeyStore} */
export function createMemoryKeyStore() {
  const map = new Map();
  return {
    async getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async setItem(key, value) {
      map.set(key, value);
    },
    async removeItem(key) {
      map.delete(key);
    },
  };
}
