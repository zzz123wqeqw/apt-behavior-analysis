<template>
  <el-timeline>
    <el-timeline-item v-for="ev in events" :key="ev.event_id" :timestamp="ev.ts" placement="top">
      <div class="case-line">
        <el-tag size="small" :type="ev.label === 'attack' ? 'danger' : 'info'">{{ ev.type }}</el-tag>
        <span>{{ summary(ev) }}</span>
      </div>
    </el-timeline-item>
  </el-timeline>
</template>

<script setup lang="ts">
import type { Event } from '../types'

defineProps<{ events: Event[] }>()

function summary(e: Event): string {
  if (e.type === 'flow') return `${e.src_ip} → ${e.dst_ip}:${e.dst_port} ${e.domain ? '(' + e.domain + ')' : ''}`
  if (e.type === 'dns') return `DNS ${e.domain}`
  if (e.type === 'process') return `${e.process} [${e.action}]`
  if (e.type === 'file') return `${e.file_path} [${e.action}]`
  return `${e.user} [${e.action}]`
}
</script>

<style scoped>
.case-line { display: flex; gap: 8px; align-items: center; font-size: 13px; }
</style>
