import http from './index'
import type { Case } from '../types'

export function fetchCases(params: Record<string, unknown> = {}): Promise<{ items: Case[]; total: number }> {
  return http.get('/cases', { params })
}

export function fetchCase(caseId: string): Promise<Case> {
  return http.get(`/cases/${caseId}`)
}
