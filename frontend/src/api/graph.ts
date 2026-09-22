import http from './index'
import type { KnowledgeGraph } from '../types'

export function fetchGraph(reportId?: string): Promise<KnowledgeGraph> {
  return http.get('/graph', { params: reportId ? { report_id: reportId } : {} })
}
