import axios, { InternalAxiosRequestConfig } from 'axios'
import { navigationEvents } from './navigation'
import { queryClient } from './queryClient'

interface ExtendedAxiosRequestConfig extends InternalAxiosRequestConfig {
    _retry?: boolean
}

export const secureApi = axios.create({
    baseURL: '/api/secure',
    timeout: 10000,
    withCredentials: true
})

export const openApi = axios.create({
    baseURL: '/api/open',
    timeout: 10000,
    withCredentials: true
})

let refreshPromise: Promise<void> | null = null

function refreshOnce(): Promise<void> {
    if (!refreshPromise) {
        refreshPromise = openApi
            .post('/refresh')
            .then(() => undefined)
            .finally(() => {
                refreshPromise = null
            })
    }
    return refreshPromise
}

function onSessionExpired(): void {
    queryClient.clear()
    navigationEvents.emit({ route: '/login', replace: true })
}

secureApi.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config as ExtendedAxiosRequestConfig | undefined
        if (!originalRequest) {
            return Promise.reject(error)
        }
        if (error.response?.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true
            try {
                await refreshOnce()
            } catch (refreshError) {
                onSessionExpired()
                return Promise.reject(refreshError)
            }
            return secureApi(originalRequest)
        }
        return Promise.reject(error)
    }
)

export async function signOut(): Promise<void> {
    await secureApi.post('/logout')
    queryClient.clear()
    navigationEvents.emit({ route: '/login', replace: true })
}
