// Server-side "at rest" encryption layer.
//
// This is separate from — and on top of — the client-side end-to-end
// encryption. Messages arrive here already encrypted with a key derived
// from the room's passphrase (the server never sees that key or the
// plaintext message). This layer wraps the already-encrypted message one
// more time with a key that only the server holds, before it touches
// MongoDB. That way, a leaked database backup alone doesn't give an
// attacker even the E2E ciphertext — they'd also need SERVER_ENCRYPTION_KEY.

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LENGTH = 12; // recommended for GCM

function getKey() {
  const keyHex = process.env.SERVER_ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error(
      'SERVER_ENCRYPTION_KEY is not set. Generate one with `npm run gen-key` and put it in your .env file.'
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error(
      'SERVER_ENCRYPTION_KEY must be a 64-character hex string (32 bytes). Generate one with `npm run gen-key`.'
    );
  }
  return Buffer.from(keyHex, 'hex');
}

/**
 * Encrypts a plain JS object for storage. Returns base64 fields safe to
 * store directly as MongoDB document fields.
 */
function encryptAtRest(plainObject) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const json = Buffer.from(JSON.stringify(plainObject), 'utf8');
  const encrypted = Buffer.concat([cipher.update(json), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    v: 1, // format/key version, in case you rotate keys later
    iv: iv.toString('base64'),
    ct: encrypted.toString('base64'),
    tag: authTag.toString('base64'),
  };
}

/**
 * Reverses encryptAtRest. Throws if the key is wrong or the data was
 * tampered with (GCM auth tag check fails).
 */
function decryptAtRest({ iv, ct, tag }) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGO, key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ct, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString('utf8'));
}

module.exports = { encryptAtRest, decryptAtRest };
