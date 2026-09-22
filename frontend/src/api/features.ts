import http from './index'

export function fetchFeatures(): Promise<Record<string, unknown>> {
  return http.get('/features')
}

export function updateFeatures(payload: Record<string, unknown>): Promise<unknown> {
  return http.put('/features', payload)
}
