import http from './index'
import type { Event } from '../types'

export function fetchEvents(params: Record<string, unknown> = {}): Promise<{ items: Event[]; total: number }> {
  return http.get('/events', { params })
}

export function fetchEventsByIds(ids: string[]): Promise<{ items: Event[] }> {
  return http.post('/events/batch', { ids })
}
