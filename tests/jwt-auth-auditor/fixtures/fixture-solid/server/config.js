function requireKey(name, minBytes = 32) {
    const value = process.env[name]
    if (!value) {
        throw new Error(`${name} is required and was not set`)
    }
    if (Buffer.from(value, 'hex').length < minBytes) {
        throw new Error(`${name} must be at least ${minBytes} random bytes (hex). Generate with: openssl rand -hex ${minBytes}`)
    }
    return value
}

function requirePositiveInt(name) {
    const value = parseInt(process.env[name], 10)
    if (!Number.isInteger(value) || value <= 0) {
        throw new Error(`${name} must be a positive integer`)
    }
    return value
}

// Validated at boot: a bad deploy must fail loudly at startup, not mint broken tokens at 3am.
module.exports = {
    signingKey: requireKey('AUTH_JWT_SIGNING_KEY'),
    accessTtlSeconds: requirePositiveInt('AUTH_ACCESS_TOKEN_TTL_SECONDS'),
    refreshTtlSeconds: requirePositiveInt('AUTH_REFRESH_TOKEN_TTL_SECONDS'),
    issuer: 'api.ledgerly.example',
    audience: 'ledgerly-web'
}
