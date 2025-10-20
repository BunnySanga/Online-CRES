const crypto = require('crypto');

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  const salt = process.env.TOKEN_SALT || 'default_salt';
  return crypto.createHash('sha256').update(token + salt).digest('hex');
}

function genBallotId() {
  return crypto.randomBytes(16).toString('hex'); // 32 hex chars
}

module.exports = { genToken, hashToken, genBallotId };
