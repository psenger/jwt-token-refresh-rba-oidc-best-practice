const express = require('express')
const bodyParser = require('body-parser')
const { signToken, verifyToken } = require('./auth')
const { findUserByCredentials } = require('./users')

const app = express()
app.use(bodyParser.json())

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body
    const user = await findUserByCredentials(email, password)
    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' })
    }
    const token = signToken(user.id, user.role)
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } })
})

app.post('/api/logout', (req, res) => {
    // Client discards the token; nothing to do server-side since JWTs are stateless.
    res.json({ ok: true })
})

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.replace('Bearer ', '')
    const payload = verifyToken(token)
    if (!payload) {
        return res.status(401).json({ error: 'Token expired or invalid' })
    }
    req.user = payload
    next()
}

app.get('/api/tasks', requireAuth, (req, res) => {
    res.json({ tasks: [], owner: req.user.sub })
})

app.listen(3000, () => console.log('taskboard api on :3000'))
