<template>
  <div class="report-page">
    <!-- 报告选择 -->
    <el-card shadow="never" class="pick-bar">
      <div class="pick-row">
        <el-select v-model="reportId" placeholder="选择研判报告" filterable style="width: 420px" @change="loadReport">
          <el-option v-for="r in reportList" :key="r.report_id" :value="r.report_id" :label="`${r.report_id}（${r.org} / ${r.risk_level}）`" />
        </el-select>
        <el-button type="primary" :loading="enriching" @click="handleEnrich">情报增强</el-button>
        <el-button @click="handleVerify">完整性校验</el-button>
        <span v-if="verifyResult" class="verify-hint" :class="verifyResult.valid ? 'ok' : 'fail'">
          {{ verifyResult.valid ? '✓ 校验通过（HMAC 签名一致）' : '✗ 校验失败（报告被篡改）' }}
        </span>
      </div>
    </el-card>

    <div v-if="report" class="detail-grid">
      <!-- 左侧：行为识别 + 溯源 -->
      <div class="left">
        <el-card shadow="never" header="行为识别结果">
          <div v-for="b in report.behaviors" :key="b.type" class="behavior-card">
            <div class="behavior-head">
              <el-tag :type="behaviorTag(b.type)" effect="dark">{{ b.name }}</el-tag>
              <el-tag size="small" :type="confidenceTag(b.confidence)">置信度 {{ (b.confidence * 100).toFixed(0) }}%</el-tag>
            </div>
            <p class="behavior-desc">{{ b.description }}</p>
            <EvidenceList :evidence-ids="b.evidence" />
          </div>
          <el-empty v-if="!report.behaviors?.length" description="未识别到攻击行为" />
        </el-card>

        <el-card shadow="never" header="APT 溯源研判" class="mt16">
          <template v-if="report.attribution">
            <div class="attr-row"><label>攻击组织</label><el-tag type="danger" effect="dark">{{ report.attribution.org }}</el-tag>
              <span class="dim">（置信度 {{ (report.attribution.org_confidence * 100).toFixed(0) }}%）</span></div>
            <div class="attr-row"><label>攻击路径</label><span>{{ report.attribution.path.join(' → ') }}</span></div>
            <div class="attr-row"><label>入侵入口</label><span>{{ report.attribution.entry }}</span></div>
            <div class="attr-row"><label>目标意图</label><span>{{ report.attribution.intent }}</span></div>
            <div class="attr-row"><label>推理依据</label><span class="reasoning">{{ report.attribution.reasoning }}</span></div>
          </template>
          <el-empty v-else description="无溯源信息" />
        </el-card>
      </div>

      <!-- 右侧：范围 + 处置 + 情报 + 时间线 -->
      <div class="right">
        <el-card shadow="never">
          <template #header>
            <div class="card-head">
              <span>研判报告</span>
              <div>
                <el-tag :type="riskTag(report.risk_level)" effect="dark" class="mr4">风险：{{ report.risk_level }}</el-tag>
                <el-tag :type="statusTag(report.status)">{{ report.status }}</el-tag>
              </div>
            </div>
          </template>
          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item label="报告编号">{{ report.report_id }}</el-descriptions-item>
            <el-descriptions-item label="案例">{{ report.case_id }}</el-descriptions-item>
            <el-descriptions-item label="生成时间">{{ report.created_at }}</el-descriptions-item>
          </el-descriptions>
        </el-card>

        <el-card shadow="never" header="影响范围" class="mt16">
          <el-table :data="report.scope || []" size="small">
            <el-table-column prop="type" label="类型" width="80" />
            <el-table-column prop="value" label="对象" show-overflow-tooltip />
          </el-table>
        </el-card>

        <el-card shadow="never" header="应急处置指引" class="mt16">
          <div v-for="(items, key) in report.recommendations" :key="key" class="rec-block">
            <div class="rec-title">{{ recTitle(key) }}</div>
            <ul>
              <li v-for="(it, i) in items" :key="i">{{ it }}</li>
            </ul>
          </div>
        </el-card>

        <!-- 攻击链时间线（补展示） -->
        <el-card v-if="report.timeline?.length" shadow="never" header="攻击链时间线" class="mt16">
          <el-timeline v-for="(t, i) in report.timeline" :key="i">
            <el-timeline-item :timestamp="t.ts" placement="top" :type="i < 3 ? 'danger' : 'primary'">
              <div class="tl-row">
                <el-tag size="small" :type="behaviorTag(t.type)" v-if="t.type">{{ t.type }}</el-tag>
                <span class="dim">{{ t.process || t.action || '' }}</span>
                <span v-if="t.dst_ip" class="mono">→ {{ t.dst_ip }}:{{ t.dst_port || '-' }}</span>
                <span v-if="t.domain" class="mono">（{{ t.domain }}）</span>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-card>

        <el-card v-if="report.enrichments?.length" shadow="never" header="威胁情报增强" class="mt16">
          <el-table :data="report.enrichments" size="small">
            <el-table-column prop="ioc" label="IOC" min-width="160" show-overflow-tooltip />
            <el-table-column prop="ioc_type" label="类型" width="80" />
            <el-table-column prop="platform" label="平台" width="90" />
            <el-table-column prop="verdict" label="判定" width="100">
              <template #default="{ row }">
                <el-tag size="small" :type="verdictTag(row.verdict)">{{ row.verdict }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="detail" label="详情" min-width="200" show-overflow-tooltip />
          </el-table>
        </el-card>
      </div>
    </div>

    <el-empty v-else description="请选择报告" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import EvidenceList from '../components/EvidenceList.vue'
import { fetchReports, fetchReport } from '../api/reports'
import { enrichReport } from '../api/intel'
import { verifyReport } from '../api/verify'
import { behaviorTag, confidenceTag, riskTag, statusTag, verdictTag } from '../utils/tags'
import type { Report } from '../types'

const route = useRoute()
const reportList = ref<Report[]>([])
const reportId = ref('')
const report = ref<Report | null>(null)
const enriching = ref(false)
const verifyResult = ref<{ valid: boolean } | null>(null)

async function loadReport() {
  if (!reportId.value) return
  try {
    const r: any = await fetchReport(reportId.value)
    report.value = r
    verifyResult.value = null
  } catch (e) {
    ElMessage.error('加载报告失败')
  }
}

async function handleEnrich() {
  if (!reportId.value) return
  enriching.value = true
  try {
    await enrichReport(reportId.value, true)
    ElMessage.success('情报增强完成')
    await loadReport()
  } catch (e) {
    ElMessage.warning('情报增强未生效（未配置平台 API Key 时跳过）')
  } finally {
    enriching.value = false
  }
}

async function handleVerify() {
  if (!reportId.value) return
  try {
    verifyResult.value = await verifyReport(reportId.value)
  } catch (e) {
    ElMessage.error('校验失败')
  }
}

function recTitle(k: string) {
  return { block: '阻断建议', clean: '清除建议', trace: '溯源建议' }[k] || k
}

onMounted(async () => {
  const res: any = await fetchReports({ limit: 50 })
  reportList.value = res.items || []
  const qid = route.query.id as string
  if (qid && reportList.value.some((r) => r.report_id === qid)) {
    reportId.value = qid
    await loadReport()
  } else if (reportList.value.length) {
    reportId.value = reportList.value[0].report_id
    await loadReport()
  }
})
</script>

<style scoped>
.pick-bar { margin-bottom: 16px; }
.pick-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.verify-hint.ok { color: #67c23a; font-size: 13px; }
.verify-hint.fail { color: #f56c6c; font-size: 13px; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
.behavior-card { border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 12px; margin-bottom: 12px; }
.behavior-head { display: flex; gap: 8px; align-items: center; }
.behavior-desc { font-size: 13px; color: var(--el-text-color-secondary); margin: 8px 0; }
.attr-row { display: flex; gap: 10px; padding: 6px 0; font-size: 14px; border-bottom: 1px dashed var(--el-border-color-lighter); }
.attr-row label { width: 76px; color: var(--el-text-color-secondary); flex-shrink: 0; }
.reasoning { color: var(--el-text-color-secondary); font-size: 13px; }
.mt16 { margin-top: 16px; }
.mr4 { margin-right: 4px; }
.card-head { display: flex; justify-content: space-between; align-items: center; }
.rec-block { margin-bottom: 10px; }
.rec-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
.rec-block li { font-size: 13px; line-height: 1.8; }
.tl-row { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.mono { font-family: Consolas, monospace; }
.dim { color: var(--el-text-color-secondary); }
@media (max-width: 1000px) { .detail-grid { grid-template-columns: 1fr; } }
</style>
