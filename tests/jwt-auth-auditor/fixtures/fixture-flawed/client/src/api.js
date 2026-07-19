import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 10000 })

api.interceptors.request.use((config) => {
    const token = localStorage.getItem('taskboard_token')
    if (token) {
        config.headers.Authorization = `Bearer ${token}`
    }
    return config
})

export async function login(email, password) {
    const { data } = await api.post('/login', { email, password })
    localStorage.setItem('taskboard_token', data.token)
    localStorage.setItem('taskboard_user', JSON.stringify(data.user))
    return data.user
}

export async function logout() {
    await api.post('/logout')
    localStorage.removeItem('taskboard_token')
    localStorage.removeItem('taskboard_user')
}

export default api
