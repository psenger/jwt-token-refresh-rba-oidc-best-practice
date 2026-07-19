const bcrypt = require('bcryptjs')
const db = require('./db')

async function findUserByCredentials(email, password) {
    const user = await db.users.findByEmail(email)
    if (!user) return null
    const ok = await bcrypt.compare(password, user.passwordHash)
    return ok ? user : null
}

async function findActiveUserById(id) {
    const user = await db.users.findById(id)
    if (!user || user.status !== 'active') return null
    return user
}

async function updatePassword(id, newPassword) {
    const hash = await bcrypt.hash(newPassword, 12)
    await db.users.setPasswordHash(id, hash)
}

module.exports = { findUserByCredentials, findActiveUserById, updatePassword }
