process.env.SERVER_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('hex');
const { encryptAtRest, decryptAtRest } = require('./crypto');

const original = { iv: 'abc123==', ct: 'def456==', ts: Date.now(), from: 'client-xyz' };

const blob = encryptAtRest(original);
console.log('Encrypted blob (safe to store):', blob);

if (blob.ct === JSON.stringify(original)) {
  throw new Error('FAIL: ciphertext should not resemble plaintext');
}

const restored = decryptAtRest(blob);
console.log('Decrypted back:', restored);

if (JSON.stringify(restored) !== JSON.stringify(original)) {
  throw new Error('FAIL: round-trip mismatch');
}

// Tamper check: flipping a byte in the ciphertext must cause decryption to fail
const tampered = { ...blob, ct: blob.ct.slice(0, -4) + 'AAAA' };
let tamperCaught = false;
try {
  decryptAtRest(tampered);
} catch (e) {
  tamperCaught = true;
}
if (!tamperCaught) {
  throw new Error('FAIL: tampered ciphertext should have thrown');
}

console.log('\nAll crypto self-tests passed: round-trip works, tamper detection works.');
