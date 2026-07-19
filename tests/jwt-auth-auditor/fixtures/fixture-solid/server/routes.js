const express = require('express')
const crypto = require('crypto')
const config = require('./config')
const tokens = require('./tokens')
const revocation = require('./revocation')
const { findUserByCredentials, findActiveUserById, updatePassword } = require('./users')

const router = express.Router()

function setAuthCookies(res, accessToken, refreshToken) {
    res.setHeader('Cache-Control', 'no-store')
    res.cookie('accessToken', accessToken, {
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: config.accessTtlSeconds * 1000
    })
    res.cookie('refreshToken', refreshToken, {
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: config.refreshTtlSeconds * 1000
    })
}

router.post('/open/login', async (req, res) => {
    const user = await findUserByCredentials(req.body.email, req.body.password)
    if (!user) {
        return res.status(401).json({ error: 'Authentication failed' })
    }
    const family = crypto.randomUUID()
    const accessToken = await tokens.mintAccessToken(user.id)
    const refreshToken = await tokens.mintRefreshToken(user.id, family)
    setAuthCookies(res, accessToken, refreshToken)
    res.json({ ok: true })
})

router.post('/open/refresh', async (req, res) => {
    try {
        const presented = req.cookies.refreshToken
        if (!presented) {
            return res.status(401).json({ error: 'Authentication failed' })
        }
        const payload = await tokens.verifyRefreshToken(presented)

        // Fail closed: any store error rejects the refresh rather than skipping the check.
        if (await revocation.isFamilyRevoked(payload.family)) {
            return res.status(401).json({ error: 'Authentication failed' })
        }
        // Reject any token issued before a user-wide revocation (e.g. password change).
        if (await revocation.issuedBeforeUserRevocation(payload.sub, payload.iat)) {
            return res.status(401).json({ error: 'Authentication failed' })
        }
        if (await revocation.isJtiRevoked(payload.jti)) {
            // Reuse of a rotated token: assume theft, kill every descendant.
            console.warn('refresh token reuse detected', { family: payload.family, sub: payload.sub })
            await revocation.revokeFamily(payload.family, config.refreshTtlSeconds)
            return res.status(401).json({ error: 'Authentication failed' })
        }

        const user = await findActiveUserById(payload.sub)
        if (!user) {
            return res.status(401).json({ error: 'Authentication failed' })
        }

        // Rotation: burn the presented token before minting its replacement.
        await revocation.revokeJti(payload.jti, payload.exp)
        const accessToken = await tokens.mintAccessToken(user.id)
        const refreshToken = await tokens.mintRefreshToken(user.id, payload.family)
        setAuthCookies(res, accessToken, refreshToken)
        res.json({ ok: true })
    } catch (err) {
        return res.status(401).json({ error: 'Authentication failed' })
    }
})

router.post('/secure/logout', async (req, res) => {
    try {
        const presented = req.cookies.refreshToken
        if (presented) {
            const payload = await tokens.verifyRefreshToken(presented)
            await revocation.revokeFamily(payload.family, config.refreshTtlSeconds)
        }
    } catch (err) {
        // fall through: still clear cookies
    }
    res.clearCookie('accessToken', { path: '/' })
    res.clearCookie('refreshToken', { path: '/' })
    res.setHeader('Cache-Control', 'no-store')
    res.json({ ok: true })
})

router.post('/secure/password', async (req, res) => {
    await updatePassword(req.user.sub, req.body.newPassword)
    // The account may be compromised: revoke every session across every device,
    // not just the one making this request. The user-wide watermark covers
    // families minted from other logins that this request never sees.
    await revocation.revokeUserBefore(req.user.sub, config.refreshTtlSeconds)
    res.clearCookie('accessToken', { path: '/' })
    res.clearCookie('refreshToken', { path: '/' })
    res.setHeader('Cache-Control', 'no-store')
    res.json({ ok: true, message: 'Please sign in again' })
})

module.exports = router
