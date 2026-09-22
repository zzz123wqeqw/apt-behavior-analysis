<template>
  <div class="evidence">
    <div v-if="evRows.length" class="evidence-title">证据事件（{{ evRows.length }}）</div>
    <el-table v-if="evRows.length" :data="evRows" size="small" border>
      <el-table-column prop="ts" label="时间" width="150" />
      <el-table-column prop="type" label="类型" width="70" />
      <el-table-column label="摘要" min-width="220" show-overflow-tooltip>
        <template #default="{ row }">
          <span>{{ row.summary }}</span>
        </template>
      </el-table-column>
    </el-table>
    <div v-else class="no-evidence">无证据事件</div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { fetchEventsByIds } from '../api/events'
import type { Event } from '../types'

const props = defineProps<{ evidenceIds: string[] }>()
const evMap = ref<Record<string, Event>>({})

function summarize(e: Event): string {
  if (e.type === 'flow') return `${e.src_ip} → ${e.dst_ip}:${e.dst_port} ${e.domain ? '(' + e.domain + ')' : ''} [${e.action}]`
  if (e.type === 'dns') return `DNS 查询 ${e.domain} [${e.action}]`
  if (e.type === 'process') return `${e.process} ← ${e.parent_process || '-'} [${e.action}]`
  if (e.type === 'file') return `${e.file_path || '-'} [${e.action}]`
  return `${e.user || '-'} [${e.action}]`
}

const evRows = computed(() =>
  props.evidenceIds.map((id) => evMap.value[id]).filter(Boolean).map((e) => ({
    event_id: e.event_id, ts: e.ts, type: e.type, summary: summarize(e),
  })),
)

onMounted(async () => {
  const ids = props.evidenceIds
  if (!ids.length) return
  try {
    // 按证据 ID 精确批量拉取（替代全表扫描）
    const res: any = await fetchEventsByIds(ids)
    for (const e of res.items || []) evMap.value[e.event_id] = e
  } catch {
    /* 证据加载失败时静默 */
  }
})
</script>

<style scoped>
.evidence-title { font-size: 12px; color: var(--el-text-color-secondary); margin: 8px 0 6px; }
.no-evidence { font-size: 12px; color: var(--el-text-color-placeholder); }
</style>
