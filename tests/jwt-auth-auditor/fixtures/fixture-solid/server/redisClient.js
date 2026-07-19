const { createClient } = require('redis')

const client = createClient({ url: process.env.REDIS_URL })
client.on('error', (err) => console.error('redis error', err))

module.exports = client
