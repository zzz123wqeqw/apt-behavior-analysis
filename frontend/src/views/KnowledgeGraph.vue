<template>
  <div class="graph-page">
    <!-- 工具栏 -->
    <el-card shadow="never" class="graph-bar">
      <div class="bar-row">
        <el-select v-model="reportId" placeholder="全部报告（全局图谱）" clearable filterable style="width: 320px" @change="loadGraph">
          <el-option v-for="r in reportList" :key="r.report_id" :value="r.report_id" :label="r.report_id" />
        </el-select>
        <el-radio-group v-model="nodeFilter" @change="applyFilter">
          <el-radio-button value="">全部</el-radio-button>
          <el-radio-button value="apt">组织</el-radio-button>
          <el-radio-button value="behavior">行为</el-radio-button>
          <el-radio-button value="ttp">TTP</el-radio-button>
          <el-radio-button value="ioc">IOC</el-radio-button>
          <el-radio-button value="asset">资产</el-radio-button>
        </el-radio-group>
        <el-button @click="loadGraph">刷新</el-button>
        <el-button type="primary" plain :disabled="!graphData" @click="exportPng">导出 PNG</el-button>
      </div>
    </el-card>

    <el-card shadow="never" class="graph-card">
      <div ref="container" class="graph-container" v-loading="loading">
        <div v-if="!graphData" class="empty-tip">暂无图谱数据，请先在概览页触发研判</div>
      </div>
      <!-- 图例 -->
      <div class="legend">
        <span v-for="l in legend" :key="l.type" class="legend-item">
          <i :style="{ background: l.color, borderRadius: l.shape === 'circle' ? '50%' : '4px' }"></i>
          {{ l.label }}
        </span>
      </div>
    </el-card>

    <!-- 节点详情 -->
    <el-drawer v-model="drawer" :title="selected?.label || '节点详情'" size="360px">
      <el-descriptions :column="1" border size="small" v-if="selected">
        <el-descriptions-item label="类型">
          <el-tag size="small">{{ typeLabel(selected.type) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item v-for="(v, k) in selected.props || {}" :key="String(k)" :label="String(k)">
          {{ typeof v === 'object' ? JSON.stringify(v) : v }}
        </el-descriptions-item>
      </el-descriptions>
      <el-empty v-else description="点击图节点查看详情" />
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { ElMessage } from 'element-plus'
import G6 from '@antv/g6'
import { fetchGraph } from '../api/graph'
import { fetchReports } from '../api/reports'
import type { KnowledgeGraph, GraphNode } from '../types'

const container = ref<HTMLElement>()
const reportId = ref('')
const reportList = ref<any[]>([])
const graphData = ref<KnowledgeGraph | null>(null)
const loading = ref(false)
const nodeFilter = ref('')
const drawer = ref(false)
const selected = ref<GraphNode | null>(null)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let graph: any = null

const legend = [
  { type: 'apt', label: '攻击组织', color: '#f56c6c', shape: 'circle' },
  { type: 'behavior', label: '攻击行为', color: '#e6a23c', shape: 'rect' },
  { type: 'ttp', label: 'TTP 手法', color: '#409eff', shape: 'rect' },
  { type: 'ioc', label: '恶意 IOC', color: '#67c23a', shape: 'rect' },
  { type: 'case', label: '攻击案例', color: '#909399', shape: 'circle' },
  { type: 'asset', label: '受影响资产', color: '#b37feb', shape: 'rect' },
]

const NODE_COLOR: Record<string, string> = {
  apt: '#f56c6c', behavior: '#e6a23c', ttp: '#409eff',
  ioc: '#67c23a', case: '#909399', asset: '#b37feb',
  target: '#fa8c16', ip: '#52c41a', domain: '#13c2c2', host: '#b37feb',
}

function typeLabel(t: string) {
  return { apt: '攻击组织', behavior: '攻击行为', ttp: 'TTP 手法', ioc: '恶意 IOC', case: '攻击案例', asset: '受影响资产', ip: 'IP', domain: '域名', host: '主机' }[t] || t
}

async function loadGraph() {
  loading.value = true
  try {
    const data: any = await fetchGraph(reportId.value || undefined)
    graphData.value = { nodes: data.nodes || [], edges: data.edges || [] }
    render()
  } catch (e) {
    ElMessage.error('加载图谱失败')
  } finally {
    loading.value = false
  }
}

function render() {
  if (!container.value || !graphData.value) return
  graph?.destroy()
  const data = graphData.value
  const width = container.value.clientWidth || 900
  const height = container.value.clientHeight || 640

  graph = new G6.Graph({
    container: container.value,
    width, height,
    fitView: true,
    fitViewPadding: 24,
    modes: { default: ['drag-canvas', 'zoom-canvas', 'drag-node', 'click-select'] },
    layout: { type: 'force', linkDistance: 130, nodeStrength: 120, preventOverlap: true, nodeSize: 40 },
    defaultNode: {
      size: 34,
      labelCfg: { style: { fontSize: 11, fill: '#333' } },
      style: { stroke: '#fff', lineWidth: 1.5 },
    },
    defaultEdge: {
      style: { stroke: '#c0c4cc', endArrow: { path: G6.Arrow.triangle(6, 8, 0), fill: '#c0c4cc' } },
      labelCfg: { style: { fontSize: 10, fill: '#606266' } },
    },
  })

  graph.data({
    nodes: (data.nodes || []).map((n) => ({
      id: n.id, label: n.label,
      type: n.type === 'case' ? 'circle' : 'rect',
      style: { fill: NODE_COLOR[n.type] || '#909399' },
      props: n.props,
      rawType: n.type,
    })),
    edges: (data.edges || []).map((e) => ({
      source: e.source, target: e.target,
      label: e.relation, weight: e.weight || 1,
    })),
  })
  graph.render()
  graph.on('node:click', (ev: any) => {
    const model = ev.item?.getModel()
    if (model) {
      selected.value = { id: model.id, label: model.label, type: model.rawType || model.type || '', props: model.props }
      drawer.value = true
    }
  })
}

// F6: 导出图谱为 PNG（G6 Canvas 截图）
function exportPng() {
  if (!graph) return
  try {
    const canvas = graph.get('canvas')?.get('el')
    if (!canvas) return
    const url = canvas.toDataURL('image/png')
    const a = document.createElement('a')
    a.href = url
    a.download = `apt-graph-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.png`
    a.click()
    ElMessage.success('图谱已导出')
  } catch {
    ElMessage.warning('导出失败，请重试')
  }
}

function applyFilter() {
  if (!graphData.value) return
  if (!nodeFilter.value) {
    render()
    return
  }
  const keepTypes = nodeFilter.value === 'ioc' ? ['ioc', 'ip', 'domain'] : [nodeFilter.value]
  const nodes = graphData.value.nodes.filter((n) => keepTypes.includes(n.type))
  const ids = new Set(nodes.map((n) => n.id))
  const edges = graphData.value.edges.filter((e) => ids.has(e.source) && ids.has(e.target))
  graph?.destroy()
  if (!container.value) return
  const width = container.value.clientWidth || 900
  const height = container.value.clientHeight || 640
  graph = new G6.Graph({
    container: container.value, width, height, fitView: true, fitViewPadding: 24,
    modes: { default: ['drag-canvas', 'zoom-canvas', 'drag-node'] },
    layout: { type: 'force', linkDistance: 120, preventOverlap: true },
  })
  graph.data({
    nodes: nodes.map((n) => ({ id: n.id, label: n.label, style: { fill: NODE_COLOR[n.type] || '#909399' } })),
    edges: edges.map((e) => ({ source: e.source, target: e.target, label: e.relation })),
  })
  graph.render()
}

onMounted(async () => {
  const res: any = await fetchReports({ limit: 50 })
  reportList.value = res.items || []
  await loadGraph()
})

onBeforeUnmount(() => graph?.destroy())
</script>

<style scoped>
.graph-bar { margin-bottom: 16px; }
.bar-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.graph-card { position: relative; }
.graph-container { height: 640px; }
.empty-tip { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--el-text-color-secondary); }
.legend { display: flex; gap: 14px; flex-wrap: wrap; padding: 10px 4px 0; }
.legend-item { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; color: var(--el-text-color-secondary); }
.legend-item i { display: inline-block; width: 12px; height: 12px; }
</style>
