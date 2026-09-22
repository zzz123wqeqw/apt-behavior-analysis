import http from './index'
import type { Report } from '../types'

export function fetchReports(params: Record<string, unknown> = {}): Promise<{ items: Report[]; total: number }> {
  return http.get('/reports', { params })
}

export function fetchReport(reportId: string): Promise<Report> {
  return http.get(`/reports/${reportId}`)
}
