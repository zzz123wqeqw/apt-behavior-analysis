import http from './index'

export interface DataSource {
  id: string
  name: string
  type: 'sim' | 'real' | 'upload'
  path: string
  count: number
  size_kb: number
  desc: string
}

export function fetchSources(): Promise<{ items: DataSource[]; total: number }> {
  return http.get('/data/sources')
}

export function uploadFile(file: File): Promise<DataSource> {
  const form = new FormData()
  form.append('file', file)
  return http.post('/data/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  })
}
