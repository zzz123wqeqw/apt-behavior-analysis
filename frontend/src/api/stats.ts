import http from './index'
import type { Stats } from '../types'

export function fetchStats(): Promise<Stats> {
  return http.get('/stats')
}
