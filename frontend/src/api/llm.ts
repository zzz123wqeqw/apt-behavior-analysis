import http from './index'

export interface LLMCaseBrief {
  case_id: string
  host: string
  window_start: string
  hit_rules: string[]
}

export interface LLMAnalyzeResult {
  mode: 'api' | 'fallback'
  llm_available: boolean
  event_count: number
  case_count: number
  cases: LLMCaseBrief[]
  answer: string
}

export function llmAnalyze(payload: {
  data_file?: string
  scene?: string
  question: string
}): Promise<LLMAnalyzeResult> {
  return http.post('/llm/analyze', payload, { timeout: 180000 })
}
