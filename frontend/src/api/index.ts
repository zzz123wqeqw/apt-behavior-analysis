import axios from 'axios'

// axios 实例（骨架）：统一 baseURL / 超时 / Token 注入
const http = axios.create({
  baseURL: '/api',
  timeout: 60000,
})

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('api_token') || 'dev-token'
  config.headers.Authorization = `Bearer ${token}`
  return config
})

http.interceptors.response.use(
  // 后端统一 {code, message, data} 封装：此处解包，业务代码直接拿 data
  (resp) => (resp.data && typeof resp.data === 'object' && 'code' in resp.data ? resp.data.data : resp.data),
  (err) => Promise.reject(err),
)

export default http
