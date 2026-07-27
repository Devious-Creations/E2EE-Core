// demo.js — an end-to-end walk-through of every protocol in this package, in one
// process, against the in-memory adapters. Run with `npm run demo`.
//
// It follows two users, Alice and Bob, from account creation through pairing, a
// shared relationship, a relayed message, a sealed proof image, and finally a
// crypto-shred that renders the shared data permanently unreadable.

import * as P from '../src/primitives.js';
import * as keyVault from '../src/keyVault.js';
import * as sealing from '../src/sealing.js';
import { createDynamicKeys } from '../src/dynamicKeys.js';
import { createRatchet } from '../src/ratchet.js';
import { createPairing } from '../src/pairing.js';
import { createMemoryKeyStore } from '../adapters/memoryKeyStore.js';
import { createMemoryTransportPair } from '../adapters/memoryTransport.js';

const line = (s = '') => console.log(s);
const step = (n, s) => console.log(`\n── ${n}. ${s} ${'─'.repeat(Math.max(0, 58 - s.length))}`);
const show = (label, v) => console.log(`   ${label}: ${v}`);
const clip = (s, n = 44) => (s.length > n ? `${s.slice(0, n)}…` : s);

const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';

// Each device has its own secret store (the OS keychain in production).
const aliceStore = createMemoryKeyStore();
const bobStore = createMemoryKeyStore();
const aliceVault = keyVault.createKeyVault(aliceStore);
const bobVault = keyVault.createKeyVault(bobStore);

line('e2ee-core — end-to-end demo (all against in-memory adapters)\n');

// ── 1. Account: password → KEK → DEK, wrapped for the server ────────────────
step(1, 'Alice creates an account (password → scrypt KEK → wrapped DEK)');
const password = 'correct horse battery staple';
const salt = await P.randomBytes(32);
const kek = await keyVault.deriveKEK(password, salt); // scrypt N=2^16,r=8,p=1
const dek = await keyVault.generateDEK(); // random 32B — encrypts Alice's backup
const wrapped = await keyVault.wrapDEK(dek, kek); // this is what the SERVER stores
await aliceVault.storeDEK(await P.encodeBase64(dek)); // device caches the unwrapped DEK
const recoveryCodes = await keyVault.generateRecoveryCodes();
const recoveryEntries = await keyVault.buildRecoveryEntries(dek, recoveryCodes);
show('server stores only the WRAPPED dek', clip(wrapped.wrappedDek));
show('recovery codes (shown once)', recoveryCodes.slice(0, 2).join('  ') + '  …');

// ── 2. Encrypted backup under the DEK ───────────────────────────────────────
step(2, "Alice's data is backed up as ciphertext (sealed under the DEK)");
const dekB64 = await aliceVault.loadDEK();
const backup = { profile: { name: 'Alice' }, prefs: { theme: 'dark' } };
const sealedBackup = await sealing.encryptDataWithKey(backup, dekB64);
show('server stores only ciphertext', clip(sealedBackup.ciphertext));
const restored = await sealing.decryptDataWithKey(sealedBackup.ciphertext, sealedBackup.nonce, dekB64);
show('device decrypts it back', JSON.stringify(restored));

// ── 3. New device recovers the DEK via a recovery code ──────────────────────
step(3, 'Alice signs in on a NEW device using a recovery code');
const { dek: recoveredDek } = await keyVault.unwrapWithRecoveryCode(recoveryCodes[3], recoveryEntries);
show('recovered DEK matches', String(Buffer.compare(Buffer.from(recoveredDek), Buffer.from(dek)) === 0));

// ── 4. Pairing: X25519 handshake + SAS ──────────────────────────────────────
step(4, 'Alice and Bob pair (X25519 handshake, out-of-band SAS)');
const [tA, tB] = createMemoryTransportPair();
const alicePairing = createPairing({ keyStore: aliceStore, transport: tA });
const bobPairing = createPairing({ keyStore: bobStore, transport: tB });
const code = 'WOLF-7392';
const joinP = bobPairing.joinPairing(code, BOB, () => {});
await new Promise((r) => setTimeout(r, 0)); // let the joiner subscribe first
const initP = alicePairing.initiatePairing(code, ALICE, () => {});
const [rB, rA] = await Promise.all([joinP, initP]);
show("Alice's SAS", rA.sas);
show("Bob's SAS  ", rB.sas);
show('SAS matches (humans compare out-of-band)', String(rA.sas === rB.sas));
if (rA.sas !== rB.sas) throw new Error('SAS mismatch — a machine-in-the-middle would be caught here');
// Users confirmed the SAS matches → persist the pairing on each device.
await alicePairing.storePairing(rA.partnerId, rA.sharedKey, rA.channelName);
await bobPairing.storePairing(rB.partnerId, rB.sharedKey, rB.channelName);
const kPair = rA.sharedKey; // the shared root key (both derived it independently)
show('both derived the SAME root K_pair', String(rA.sharedKey === rB.sharedKey));

// ── 5. Provision a shared relationship key (K_shared), AAD-bound ─────────────
step(5, 'They provision a shared relationship key K_shared (delivered under K_pair)');
// Bob is also a signed-in user with his own master DEK (his account creation is
// identical to Alice's step 1, elided here). Each member wraps K_shared under
// their OWN DEK, so shredding the relationship never touches either master key.
await bobVault.storeDEK(await P.encodeBase64(await keyVault.generateDEK()));
const aliceDyn = createDynamicKeys(aliceVault);
const bobDyn = createDynamicKeys(bobVault);
const DYN = 'dyn-alice-bob';
const { delivery } = await aliceDyn.provisionDynamic(DYN, kPair); // Alice = creator
await bobDyn.acceptDynamicGrant(DYN, delivery, kPair); // Bob = accepter
const aliceKShared = await aliceVault.loadDynamicSharedKey(DYN);
const bobKShared = await bobVault.loadDynamicSharedKey(DYN);
show('both members hold the SAME K_shared', String(aliceKShared === bobKShared));
// The delivery is AAD-bound: it cannot be accepted under a different relationship id.
let swapRejected = false;
try {
  await bobDyn.acceptDynamicGrant('some-other-dyn', delivery, kPair);
} catch {
  swapRejected = true;
}
show('a server swapping the grant into another dynamic is REJECTED', String(swapRejected));

// ── 6. Shared data plane sealed under K_shared ──────────────────────────────
step(6, 'Shared relationship data is sealed under K_shared');
const sharedNote = { title: 'Our plan', body: 'meet at dawn' };
const sealedNote = await sealing.encryptDataWithKey(sharedNote, aliceKShared);
show('server stores only ciphertext', clip(sealedNote.ciphertext));
const bobReadsNote = await sealing.decryptDataWithKey(sealedNote.ciphertext, sealedNote.nonce, bobKShared);
show('Bob decrypts it', JSON.stringify(bobReadsNote));

// ── 7. A relayed message via the ratchet ────────────────────────────────────
step(7, 'Alice sends Bob a relayed message (symmetric-key ratchet over K_pair)');
const aliceRatchet = createRatchet(aliceStore);
const bobRatchet = createRatchet(bobStore);
const aliceSession = { sharedKey: kPair, channelName: rA.channelName, selfId: ALICE };
const bobSession = { sharedKey: kPair, channelName: rB.channelName, selfId: BOB };
const wire = await aliceRatchet.ratchetEncrypt({ text: 'on my way' }, aliceSession);
show('on the wire (ciphertext + counter)', `ctr=${wire.ctr} ct=${clip(wire.ciphertext, 28)}`);
const bobReceives = await bobRatchet.ratchetDecrypt(wire, bobSession);
show('Bob decrypts', JSON.stringify(bobReceives));

// ── 8. A proof image sealed under K_shared ──────────────────────────────────
step(8, 'A proof image is sealed under K_shared before it leaves the device');
const fakeImage = await P.encodeBase64(await P.randomBytes(64)); // stand-in for JPEG bytes
const sealedImage = await sealing.sealBytes(fakeImage, aliceKShared); // Uint8Array: nonce||ciphertext
show('object storage holds only these bytes', `${sealedImage.length} bytes of ciphertext`);
const openedImage = await sealing.openBytes(await P.encodeBase64(sealedImage), bobKShared);
show('Bob downloads + decrypts it', String(openedImage === fakeImage));

// ── 9. Crypto-shred: delete K_shared → the data is unrecoverable ────────────
step(9, 'The relationship is killed — both members crypto-shred K_shared');
await aliceDyn.shredDynamicLocal(DYN);
await bobDyn.shredDynamicLocal(DYN);
show('K_shared is gone on both devices', String((await aliceVault.loadDynamicSharedKey(DYN)) === null));
line('   The ciphertext that remains on the server (the note, the proof image) is');
line('   now cryptographically unreachable — nobody holds the key.');

line('\n✓ demo complete — every value the server ever saw was ciphertext.\n');
