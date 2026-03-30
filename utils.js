const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SALT_ROUNDS = 12;

/**
 * Hash a plain text password
 * @param {string} password
 * @param {number} rounds - bcrypt salt rounds (default 12)
 * @returns {Promise<string>} hashed password
 */
async function hashPassword(password, rounds = SALT_ROUNDS) {
  return bcrypt.hash(password, rounds);
}

/**
 * Compare plain text password with hashed password
 * @param {string} password - plain text
 * @param {string} hash - bcrypt hash
 * @returns {Promise<boolean>}
 */
async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

/**
 * Generate a JWT token
 * @param {object} payload - data to encode
 * @param {string} secret - signing secret
 * @param {object} options - { expiresIn: '7d' }
 * @returns {string} JWT token
 */
function generateToken(payload, secret, options = {}) {
  return jwt.sign(payload, secret, {
    expiresIn: options.expiresIn || '7d',
    ...options,
  });
}

/**
 * Verify and decode a JWT token
 * @param {string} token
 * @param {string} secret
 * @returns {object|null} decoded payload or null
 */
function verifyToken(token, secret) {
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
}

module.exports = {
  hashPassword,
  comparePassword,
  generateToken,
  verifyToken,
};
