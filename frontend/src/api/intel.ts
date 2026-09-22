import http from './index'
import type { Enrichment } from '../types'

/** 单点情报查询（聚合 VT/微步） */
export function queryIntel(ioc: string, iocType = 'ip'): Promise<unknown> {
  return http.get('/intel', { params: { ioc, ioc_type: iocType } })
}

/** 对报告 IOC 批量增强 */
export function enrichReport(reportId: string, force = false): Promise<{ items: Enrichment[] }> {
  return http.post('/enrich', { report_id: reportId, force })
}

/** FOFA 资产扩线 */
export function expandIoc(ioc: string, iocType: string, limit = 10): Promise<{ items: unknown[] }> {
  return http.post('/expand', { ioc, ioc_type: iocType, limit })
}

/** 查询增强/扩线结果 */
export function fetchEnrichments(params: Record<string, unknown> = {}): Promise<{ items: Enrichment[] }> {
  return http.get('/enrichments', { params })
}
