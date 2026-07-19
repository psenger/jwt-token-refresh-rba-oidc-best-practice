const express = require('express')
const cookieParser = require('cookie-parser')
const routes = require('./routes')
const { verifyAccessToken } = require('./tokens')

const app = express()
app.use(express.json())
app.use(cookieParser())

// Every /api/secure route requires a valid access token; protection is structural,
// not per-route.
app.use('/api/secure', async (req, res, next) => {
    try {
        if (!req.cookies || !req.cookies.accessToken) {
            return res.status(401).json({ error: 'Authentication failed' })
        }
        req.user = await verifyAccessToken(req.cookies.accessToken)
        next()
    } catch (err) {
        return res.status(401).json({ error: 'Authentication failed' })
    }
})

app.use('/api', routes)

app.listen(3000, () => console.log('ledgerly api on :3000'))
