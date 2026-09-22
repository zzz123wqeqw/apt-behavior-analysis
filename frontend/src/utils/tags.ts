// 统一标签/颜色映射工具（F4）：风险等级、行为类型、状态、事件类型
// 避免各页面重复定义导致样式不一致

export type TagType = 'primary' | 'success' | 'warning' | 'danger' | 'info'

export const BEHAVIOR_TAG: Record<string, TagType> = {
  lateral_movement: 'danger',
  hidden_channel: 'warning',
  long_term_latency: 'info',
  trace_cleaning: 'primary',
}

export const BEHAVIOR_NAME: Record<string, string> = {
  lateral_movement: '内网横向移动',
  hidden_channel: '隐蔽数据传输',
  long_term_latency: '长期潜伏',
  trace_cleaning: '痕迹清理',
}

export function behaviorTag(t: string): TagType {
  return BEHAVIOR_TAG[t] || 'info'
}

export function riskTag(r: string): TagType {
  if (r === '严重' || r === '高') return 'danger'
  if (r === '中') return 'warning'
  return 'info'
}

export function statusTag(s: string): TagType {
  if (s === '确认') return 'danger'
  if (s === '待复核') return 'warning'
  return 'info'
}

export function eventTypeTag(t: string): TagType {
  const map: Record<string, TagType> = { flow: 'primary', dns: 'warning', process: 'danger', file: 'success', auth: 'info' }
  return map[t] || 'info'
}

// 情报判定（后端返回中文：恶意/可疑/正常/未知）
export function verdictTag(v: string): TagType {
  const map: Record<string, TagType> = { 恶意: 'danger', 可疑: 'warning', 正常: 'success' }
  return map[v] || 'info'
}

export function confidenceTag(c: number): TagType {
  return c >= 0.7 ? 'success' : 'warning'
}
