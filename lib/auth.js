// Password hashing uses Node's built-in scrypt (no native dependencies,
// no separate library needed). JWTs are used for stateless session auth.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const SCRYPT_KEYLEN = 64;
const USERNAME_RE = /^[a-zA-Z0-9_-]{3,24}$/;

function validateUsername(username) {
  return typeof username === 'string' && USERNAME_RE.test(username);
}

function validatePassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 200;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  return `${salt}:${derivedKey.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [salt, keyHex] = String(stored || '').split(':');
  if (!salt || !keyHex) return false;
  const derivedKey = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== derivedKey.length) return false;
  return crypto.timingSafeEqual(keyBuffer, derivedKey);
}

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not set.');
  return secret;
}

function signToken(payload) {
  return jwt.sign(payload, getJwtSecret(), { expiresIn: '30d' });
}

function verifyToken(token) {
  return jwt.verify(token, getJwtSecret()); // throws if invalid/expired
}

// Express middleware: requires "Authorization: Bearer <token>"
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing auth token.' });
  try {
    const decoded = verifyToken(token);
    req.userId = decoded.sub;
    req.username = decoded.username;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

module.exports = {
  validateUsername,
  validatePassword,
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken,
  requireAuth,
};
