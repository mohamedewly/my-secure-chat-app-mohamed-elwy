process.env.JWT_SECRET = 'test-secret-do-not-use-in-prod';
const { hashPassword, verifyPassword, signToken, verifyToken, validateUsername, validatePassword } = require('./auth');

// --- password hashing ---
const hash = hashPassword('correct horse battery staple');
if (!verifyPassword('correct horse battery staple', hash)) throw new Error('FAIL: correct password rejected');
if (verifyPassword('wrong password', hash)) throw new Error('FAIL: wrong password accepted');
console.log('Password hashing: OK (correct accepted, wrong rejected)');

// two hashes of the same password should differ (random salt)
const hash2 = hashPassword('correct horse battery staple');
if (hash === hash2) throw new Error('FAIL: salts should differ between hashes');
console.log('Password salting: OK (two hashes of same password differ)');

// --- JWT ---
const token = signToken({ sub: 'user123', username: 'mohamed' });
const decoded = verifyToken(token);
if (decoded.sub !== 'user123' || decoded.username !== 'mohamed') throw new Error('FAIL: JWT payload mismatch');
console.log('JWT sign/verify: OK');

let rejected = false;
try { verifyToken(token + 'tampered'); } catch (e) { rejected = true; }
if (!rejected) throw new Error('FAIL: tampered JWT should be rejected');
console.log('JWT tamper detection: OK');

// --- validators ---
const usernameCases = [['bob', true], ['ab', false], ['has space', false], ['valid_name-99', true], ['x'.repeat(30), false]];
for (const [u, expected] of usernameCases) {
  if (validateUsername(u) !== expected) throw new Error(`FAIL: validateUsername(${JSON.stringify(u)}) expected ${expected}`);
}
console.log('Username validation: OK');

const passwordCases = [['short', false], ['longenough1', true]];
for (const [p, expected] of passwordCases) {
  if (validatePassword(p) !== expected) throw new Error(`FAIL: validatePassword(${JSON.stringify(p)}) expected ${expected}`);
}
console.log('Password validation: OK');

console.log('\nAll auth self-tests passed.');
