<template>
  <div class="dashboard">
    <!-- 顶部操作区 -->
    <el-card shadow="never" class="toolbar">
      <div class="toolbar-row">
        <div>
          <h2 class="page-title">APT 攻击研判总览</h2>
          <p class="page-sub">基于 LLM 的行为特征识别 · 溯源 · 误报过滤 · 知识图谱</p>
        </div>
        <div class="toolbar-actions">
          <el-select v-model="scene" placeholder="场景" style="width: 130px">
            <el-option label="全部场景" value="" />
            <el-option label="场景 A（钓鱼+C2 潜伏）" value="A" />
            <el-option label="场景 B（横向移动）" value="B" />
            <el-option label="场景 C（DNS 隧道+清痕）" value="C" />
          </el-select>
          <el-button type="primary" :loading="analyzing" @click="handleAnalyze">
            {{ analyzing ? '研判中…' : '一键全流程研判' }}
          </el-button>
          <el-button @click="loadAll">刷新</el-button>
        </div>
      </div>
    </el-card>

    <!-- 统计卡片 -->
    <div class="stat-grid">
      <StatCard title="研判报告" :value="stats.report_count" icon="Document" color="#409EFF" />
      <StatCard title="可疑案例" :value="stats.case_count" icon="Files" color="#E6A23C" />
      <StatCard title="高危 / 确认报告" :value="stats.high_count" icon="Warning" color="#F56C6C" />
      <StatCard title="识别行为数" :value="totalBehaviors" icon="TrendCharts" color="#67C23A" />
    </div>

    <!-- 图表区 -->
    <div class="chart-grid">
      <el-card shadow="never" header="攻击行为分布">
        <div ref="behaviorRef" class="chart" />
      </el-card>
      <el-card shadow="never" header="风险等级分布">
        <div ref="riskRef" class="chart" />
      </el-card>
    </div>

    <!-- 报告列表 -->
    <el-card shadow="never" header="近期研判报告">
      <el-table :data="reports" stripe style="width: 100%">
        <el-table-column prop="report_id" label="报告编号" min-width="260" show-overflow-tooltip />
        <el-table-column prop="host" label="主机" width="120" />
        <el-table-column prop="org" label="归因组织" width="140" />
        <el-table-column label="行为" min-width="220">
          <template #default="{ row }">
            <el-tag v-for="b in row.behaviors" :key="b.type" size="small" class="mr4" :type="behaviorTag(b.type)">
              {{ b.name }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="风险" width="100">
          <template #default="{ row }">
            <el-tag :type="riskTag(row.risk_level)" effect="dark">{{ row.risk_level }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="110" />
        <el-table-column prop="created_at" label="时间" width="170" />
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button link type="primary" @click="goDetail(row.report_id)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatCard from '../components/StatCard.vue'
import { fetchStats } from '../api/stats'
import { fetchReports } from '../api/reports'
import { runAnalyze } from '../api/analyze'
import { behaviorTag, riskTag } from '../utils/tags'
import type { Report } from '../types'

const router = useRouter()
const scene = ref('')
const analyzing = ref(false)
const reports = ref<Report[]>([])
const stats = ref<any>({ report_count: 0, case_count: 0, high_count: 0, behavior_dist: {}, risk_dist: {} })
const behaviorRef = ref<HTMLElement>()
const riskRef = ref<HTMLElement>()
let behaviorChart: echarts.ECharts | null = null
let riskChart: echarts.ECharts | null = null

const totalBehaviors = computed(() =>
  Object.values(stats.value.behavior_dist || {}).reduce((a: number, b: any) => a + Number(b), 0),
)

async function loadAll() {
  try {
    const [s, r] = await Promise.all([fetchStats(), fetchReports({ limit: 10 })])
    stats.value = s
    reports.value = (r as any).items || []
    await nextTick()
    renderCharts()
  } catch (e) {
    ElMessage.error('加载数据失败，请确认后端已启动')
  }
}

async function handleAnalyze() {
  // 全流程研判会清空旧数据重建，先确认（F1）
  try {
    await ElMessageBox.confirm(
      '一键研判将重建全部案例与报告（覆盖现有数据），是否继续？',
      '确认研判',
      { type: 'warning', confirmButtonText: '开始研判', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  analyzing.value = true
  try {
    const res = await runAnalyze({ scene: scene.value || undefined, use_intel: false })
    ElMessage.success(`研判完成，生成 ${(res as any).report_ids?.length || 0} 份报告`)
    await loadAll()
  } catch (e) {
    ElMessage.error('研判失败：' + (e as Error).message)
  } finally {
    analyzing.value = false
  }
}

function renderCharts() {
  if (!behaviorRef.value || !riskRef.value) return
  behaviorChart = echarts.init(behaviorRef.value)
  riskChart = echarts.init(riskRef.value)
  const bd = stats.value.behavior_dist || {}
  behaviorChart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: ['40%', '68%'],
      data: Object.entries(bd).map(([k, v]) => ({ name: k, value: v })),
      label: { formatter: '{b}\n{c}' },
    }],
  })
  const rd = stats.value.risk_dist || {}
  riskChart.setOption({
    tooltip: {},
    xAxis: { type: 'category', data: Object.keys(rd) },
    yAxis: { type: 'value' },
    series: [{
      type: 'bar', barWidth: 48,
      data: Object.values(rd),
      itemStyle: { color: (p: any) => ['高', '中', '低'].includes(p.name || '') ? '#F56C6C' : '#409EFF' },
    }],
  })
}

function tagType(t: string) {
  return behaviorTag(t)
}
function riskType(r: string) {
  return riskTag(r)
}
function goDetail(id: string) {
  router.push({ path: '/reports', query: { id } })
}

onMounted(loadAll)
onBeforeUnmount(() => {
  behaviorChart?.dispose()
  riskChart?.dispose()
})
</script>

<style scoped>
.toolbar-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
.page-title { margin: 0; font-size: 20px; }
.page-sub { margin: 4px 0 0; color: var(--el-text-color-secondary); font-size: 13px; }
.toolbar-actions { display: flex; gap: 8px; }
.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 16px 0; }
.chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
.chart { height: 300px; }
.mr4 { margin-right: 4px; }
@media (max-width: 900px) {
  .stat-grid { grid-template-columns: repeat(2, 1fr); }
  .chart-grid { grid-template-columns: 1fr; }
}
</style>
