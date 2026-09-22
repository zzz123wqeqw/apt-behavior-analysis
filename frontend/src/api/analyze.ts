import http from './index'

export interface AnalyzeResult {
  report_ids: string[]
}

/** 触发全流程研判（骨架） */
export function runAnalyze(payload: { scene?: string; data_file?: string; use_intel?: boolean }): Promise<AnalyzeResult> {
  return http.post('/analyze', payload)
}
