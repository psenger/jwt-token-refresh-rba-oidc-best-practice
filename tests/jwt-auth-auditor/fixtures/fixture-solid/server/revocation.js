const redis = require('./redisClient')

// Denylist model per the OWASP JWT Cheat Sheet: a refresh token is valid if its
// signature verifies AND its jti has not been revoked. Revoked jtis are stored
// with a TTL matching the token's remaining life, so entries self-evict.

async function revokeJti(jti, exp) {
    const ttl = Math.max(1, exp - Math.floor(Date.now() / 1000))
    await redis.set(`revoked:jti:${jti}`, '1', { EX: ttl })
}

async function isJtiRevoked(jti) {
    const value = await redis.get(`revoked:jti:${jti}`)
    return value !== null
}

async function revokeFamily(family, ttlSeconds) {
    await redis.set(`revoked:family:${family}`, '1', { EX: ttlSeconds })
}

async function isFamilyRevoked(family) {
    const value = await redis.get(`revoked:family:${family}`)
    return value !== null
}

// Per-user revocation watermark: on a password change (or any "sign out
// everywhere" event) we record a cutoff timestamp. Any refresh token issued at
// or before the cutoff is rejected, so every session across every device dies,
// not just the one that presented the request.
async function revokeUserBefore(sub, ttlSeconds) {
    await redis.set(`revoked:user:${sub}`, Math.floor(Date.now() / 1000), { EX: ttlSeconds })
}

async function issuedBeforeUserRevocation(sub, iat) {
    const cutoff = await redis.get(`revoked:user:${sub}`)
    return cutoff !== null && iat <= parseInt(cutoff, 10)
}

module.exports = { revokeJti, isJtiRevoked, revokeFamily, isFamilyRevoked, revokeUserBefore, issuedBeforeUserRevocation }
