import http from './index'

export function verifyReport(reportId: string): Promise<{ valid: boolean; recomputed: string }> {
  return http.get(`/verify/${reportId}`)
}
