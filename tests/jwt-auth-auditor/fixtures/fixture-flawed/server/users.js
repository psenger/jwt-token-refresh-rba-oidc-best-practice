const bcrypt = require('bcryptjs')

const users = [
    { id: 1, email: 'ada@example.com', name: 'Ada', role: 'admin', passwordHash: '$2a$10$abcdefghijklmnopqrstuv' },
    { id: 2, email: 'lin@example.com', name: 'Lin', role: 'member', passwordHash: '$2a$10$abcdefghijklmnopqrstuv' }
]

async function findUserByCredentials(email, password) {
    const user = users.find((u) => u.email === email)
    if (!user) return null
    const ok = await bcrypt.compare(password, user.passwordHash)
    return ok ? user : null
}

module.exports = { findUserByCredentials }
