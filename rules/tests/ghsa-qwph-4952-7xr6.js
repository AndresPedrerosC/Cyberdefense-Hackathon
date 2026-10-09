const jwt = require('jsonwebtoken')

function verifyLoose (token, publicKey, cb) {
  // ruleid: ghsa-qwph-4952-7xr6-jsonwebtoken-verify-no-algorithms
  jwt.verify(token, publicKey, (err, decoded) => cb(err, decoded))
}

function verifyLooseOpts (token, publicKey) {
  // ruleid: ghsa-qwph-4952-7xr6-jsonwebtoken-verify-no-algorithms
  return jwt.verify(token, publicKey, { ignoreExpiration: false })
}

function verifyStrict (token, publicKey) {
  // ok: ghsa-qwph-4952-7xr6-jsonwebtoken-verify-no-algorithms
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] })
}

module.exports = { verifyLoose, verifyLooseOpts, verifyStrict }
