const expressJwt = require('express-jwt')
const publicKey = process.env.JWT_PUBLIC_KEY

// ruleid: ghsa-6g6m-m6h5-w9gf-express-jwt-missing-algorithms
const isAuthorized = () => expressJwt({ secret: publicKey })

// ok: ghsa-6g6m-m6h5-w9gf-express-jwt-missing-algorithms
const isAuthorizedStrict = () => expressJwt({ secret: publicKey, algorithms: ['RS256'] })

module.exports = { isAuthorized, isAuthorizedStrict }
