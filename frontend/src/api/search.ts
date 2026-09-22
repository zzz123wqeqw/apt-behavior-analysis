import http from './index'

export function searchAll(keyword: string, params: Record<string, unknown> = {}): Promise<unknown> {
  return http.post('/search', { keyword, ...params })
}
