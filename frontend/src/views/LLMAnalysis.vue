<template>
  <div class="llm-page">
    <el-card shadow="never">
      <template #header>
        <div class="card-head">
          <span>大模型深度分析</span>
          <el-tag :type="mode === 'api' ? 'success' : 'warning'" size="small">
            {{ mode === 'api' ? `LLM 已启用（${model}）` : '规则兜底模式（未配置 Key）' }}
          </el-tag>
        </div>
      </template>

      <!-- 输入区 -->
      <div class="input-grid">
        <el-select v-model="dataFile" placeholder="选择数据源（默认内置模拟数据）" clearable filterable style="width: 100%">
          <el-option v-for="s in sources" :key="s.id" :value="s.path" :label="`${s.name}（${s.count >= 0 ? s.count + ' 条' : '大文件'}）`" />
        </el-select>
        <el-input
          v-model="question" type="textarea" :rows="3" placeholder="输入你的分析问题，例如：这批数据存在哪些 APT 攻击行为？攻击组织可能是谁？如何处置？"
          maxlength="500" show-word-limit
        />
        <div class="action-row">
          <el-button type="primary" :loading="loading" @click="run">开始分析</el-button>
          <el-button @click="loadStatus">刷新状态</el-button>
        </div>
      </div>

      <!-- 数据概况 -->
      <div v-if="result" class="overview">
        <el-statistic title="事件总数" :value="result.event_count" />
        <el-statistic title="可疑案例" :value="result.case_count" />
        <el-statistic title="分析模式" :value="result.mode === 'api' ? 'LLM' : '规则'" />
      </div>

      <!-- 分析结论 -->
      <div v-if="result" class="answer-box">
        <div class="answer-title">分析结论</div>
        <div class="answer-md" v-html="renderedAnswer"></div>
      </div>

      <!-- 案例摘要 -->
      <div v-if="result && result.cases.length" class="case-box">
        <div class="answer-title">预筛可疑案例（{{ result.cases.length }}）</div>
        <el-table :data="result.cases" size="small" border>
          <el-table-column prop="case_id" label="案例编号" min-width="240" show-overflow-tooltip />
          <el-table-column prop="host" label="主机" width="120" />
          <el-table-column prop="window_start" label="窗口开始" width="170" />
          <el-table-column label="命中规则" min-width="220">
            <template #default="{ row }">
              <el-tag v-for="r in row.hit_rules" :key="r" size="small" class="mr4">{{ r }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchSources, type DataSource } from '../api/data'
import { llmAnalyze, type LLMAnalyzeResult } from '../api/llm'
import { fetchSettings } from '../api/settings'

const sources = ref<DataSource[]>([])
const dataFile = ref('')
const question = ref('请综合分析这批数据的攻击行为、攻击组织与处置建议')
const loading = ref(false)
const result = ref<LLMAnalyzeResult | null>(null)
const mode = ref('')
const model = ref('')

// F3: 轻量 Markdown 渲染（先转义 HTML 防 XSS，再解析标题/粗体/列表/代码块）
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function renderMarkdown(src: string): string {
  const esc = escapeHtml(src)
  const lines = esc.split('\n')
  const out: string[] = []
  let inList = false
  let inCode = false
  let codeBuf: string[] = []
  const closeList = () => {
    if (inList) { out.push('</ul>'); inList = false }
  }
  for (const raw of lines) {
    const line = raw.trimEnd()
    // 代码块 ``` 或 ```
    if (/^```/.test(line)) {
      if (inCode) {
        out.push(`<pre class="md-code">${codeBuf.join('\n')}</pre>`)
        codeBuf = []; inCode = false
      } else {
        closeList(); inCode = true
      }
      continue
    }
    if (inCode) { codeBuf.push(line); continue }
    // 标题 ## / ###
    const h = line.match(/^(#{1,4})\s+(.*)$/)
    if (h) {
      closeList()
      const lv = Math.min(h[1].length + 1, 4)
      out.push(`<h${lv} class="md-h">${h[2].replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')}</h${lv}>`)
      continue
    }
    // 列表项 - / * / 1.
    const li = line.match(/^([-*]|\d+\.)\s+(.*)$/)
    if (li) {
      if (!inList) { out.push('<ul class="md-ul">'); inList = true }
      out.push(`<li>${li[2].replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')}</li>`)
      continue
    }
    closeList()
    if (line.trim() === '') { out.push('<div class="md-gap"></div>'); continue }
    out.push(`<p class="md-p">${line.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')}</p>`)
  }
  closeList()
  if (inCode) out.push(`<pre class="md-code">${codeBuf.join('\n')}</pre>`)
  return out.join('\n')
}

const renderedAnswer = computed(() => (result.value?.answer ? renderMarkdown(result.value.answer) : ''))

async function loadStatus() {
  try {
    const s: any = await fetchSettings()
    mode.value = s.llm.mode
    model.value = s.llm.model
  } catch { /* 忽略 */ }
}

async function run() {
  if (!question.value.trim()) {
    ElMessage.warning('请输入分析问题')
    return
  }
  loading.value = true
  try {
    result.value = await llmAnalyze({ data_file: dataFile.value || undefined, question: question.value })
    mode.value = result.value.mode
  } catch (e) {
    ElMessage.error('分析失败：' + (e as Error).message)
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadStatus()
  try {
    const res: any = await fetchSources()
    sources.value = res.items || []
  } catch { /* 忽略 */ }
})
</script>

<style scoped>
.card-head { display: flex; justify-content: space-between; align-items: center; }
.input-grid { display: grid; gap: 12px; max-width: 860px; }
.action-row { display: flex; gap: 8px; }
.overview { display: flex; gap: 48px; margin: 20px 0 8px; padding: 14px 18px; background: var(--el-fill-color-lighter); border-radius: 8px; }
.answer-box { margin-top: 14px; border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 14px 16px; }
.answer-title { font-weight: 600; font-size: 14px; margin-bottom: 8px; }
.answer-md { font-size: 13px; line-height: 1.8; color: var(--el-text-color-primary); }
.answer-md .md-h { margin: 10px 0 6px; font-size: 14px; }
.answer-md .md-p { margin: 6px 0; }
.answer-md .md-ul { margin: 6px 0; padding-left: 20px; }
.answer-md .md-gap { height: 6px; }
.answer-md .md-code { background: #f5f7fa; border-radius: 6px; padding: 10px 12px; font-family: Consolas, monospace; font-size: 12px; overflow-x: auto; }
.case-box { margin-top: 16px; }
.mr4 { margin-right: 4px; }
</style>
