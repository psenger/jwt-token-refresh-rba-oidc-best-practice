// Thin data-access stub; the real implementation is a Postgres pool.
module.exports = {
    users: {
        findByEmail: async (email) => null,
        findById: async (id) => null,
        setPasswordHash: async (id, hash) => undefined
    }
}
