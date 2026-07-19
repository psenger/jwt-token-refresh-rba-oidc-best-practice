const { SignJWT, jwtVerify } = require('jose')
const crypto = require('crypto')
const config = require('./config')

const secret = new TextEncoder().encode(config.signingKey)

async function mintAccessToken(userId) {
    return new SignJWT({ token_use: 'access' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer(config.issuer)
        .setAudience(config.audience)
        .setSubject(String(userId))
        .setIssuedAt()
        .setExpirationTime(`${config.accessTtlSeconds}s`)
        .sign(secret)
}

async function mintRefreshToken(userId, family) {
    return new SignJWT({ token_use: 'refresh', family })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer(config.issuer)
        .setAudience(config.audience)
        .setSubject(String(userId))
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(`${config.refreshTtlSeconds}s`)
        .sign(secret)
}

async function verifyAccessToken(token) {
    const { payload } = await jwtVerify(token, secret, {
        algorithms: ['HS256'],
        issuer: config.issuer,
        audience: config.audience,
        clockTolerance: 30
    })
    if (payload.token_use !== 'access') {
        throw new Error('wrong token type')
    }
    return payload
}

async function verifyRefreshToken(token) {
    const { payload } = await jwtVerify(token, secret, {
        algorithms: ['HS256'],
        issuer: config.issuer,
        audience: config.audience,
        clockTolerance: 30
    })
    if (payload.token_use !== 'refresh') {
        throw new Error('wrong token type')
    }
    return payload
}

module.exports = { mintAccessToken, mintRefreshToken, verifyAccessToken, verifyRefreshToken }
