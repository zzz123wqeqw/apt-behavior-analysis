import http from './index'

export interface SettingsStatus {
  keys: { llm_api_key: boolean; vt_api_key: boolean; threatbook_api_key: boolean; fofa_api_key: boolean; api_token: boolean }
  llm: { available: boolean; model: string; mode: 'api' | 'fallback' }
  intel: { virustotal: boolean; threatbook: boolean; fofa: boolean }
}

export function fetchSettings(): Promise<SettingsStatus> {
  return http.get('/settings')
}

export function saveKeys(payload: {
  deepseek_api_key?: string
  vt_api_key?: string
  threatbook_api_key?: string
  fofa_api_key?: string
}): Promise<Record<string, boolean>> {
  return http.post('/settings/keys', payload)
}
