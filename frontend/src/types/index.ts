// 全局类型定义（与后端 models 对齐，骨架）

export interface Event {
  event_id: string
  ts: string
  type: 'flow' | 'process' | 'file' | 'dns' | 'auth'
  src_ip?: string
  src_port?: number
  dst_ip?: string
  dst_port?: number
  domain?: string
  process?: string
  parent_process?: string
  file_path?: string
  file_hash?: string
  action?: string
  user?: string
  host?: string
  scene?: string
  label?: string
}

export interface Case {
  case_id: string
  host: string
  window_start: string
  window_end: string
  events: string[]
  suspicious_score: number
  hit_rules: string[]
  final_status?: string
}

export interface Behavior {
  type: string
  name: string
  confidence: number
  evidence: string[]
  description: string
}

export interface Attribution {
  org: string
  org_confidence: number
  path: string[]
  entry: string
  intent: string
  reasoning: string
}

export interface Enrichment {
  enrichment_id: string
  report_id?: string
  ioc: string
  ioc_type: string
  platform: string
  verdict: string
  score: number
  family?: string
  tags: string
  detail: string
  source_url: string
  queried_at: string
  cited: boolean
}

export interface Report {
  report_id: string
  created_at: string
  case_id: string
  host?: string
  org?: string
  behaviors: Behavior[]
  attribution?: Attribution
  risk_level: string
  scope: unknown[]
  timeline: any[]
  status: string
  recommendations?: Record<string, string[]>
  enrichments?: Enrichment[]
}

export interface GraphNode {
  id: string
  label: string
  type: string
  props?: Record<string, unknown>
}

export interface GraphEdge {
  source: string
  target: string
  relation: string
  weight: number
}

export interface KnowledgeGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface Stats {
  total: number
  behavior_dist: Record<string, number>
  risk_dist: Record<string, number>
  trend: Array<{ date: string; count: number }>
  top_orgs: Array<{ org: string; count: number }>
}
