type NavigationEvent = { route: string; replace?: boolean }
type Handler = (event: NavigationEvent) => void

const handlers: Handler[] = []

export const navigationEvents = {
    on(handler: Handler): void {
        handlers.push(handler)
    },
    emit(event: NavigationEvent): void {
        handlers.forEach((h) => h(event))
    }
}
