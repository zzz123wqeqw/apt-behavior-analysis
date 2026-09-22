<template>
  <el-card shadow="hover" class="stat-card">
    <div class="stat-inner">
      <div class="stat-icon" :style="{ background: color + '1a', color }">
        <el-icon :size="24"><component :is="icon" /></el-icon>
      </div>
      <div>
        <div class="stat-value">{{ value }}</div>
        <div class="stat-title">{{ title }}</div>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { Document, Files, Warning, TrendCharts } from '@element-plus/icons-vue'

const props = withDefaults(defineProps<{
  title: string
  value: number | string
  icon?: string
  color?: string
}>(), { icon: 'Document', color: '#409EFF' })

const iconMap: Record<string, any> = { Document, Files, Warning, TrendCharts }
</script>

<style scoped>
.stat-card { border-radius: 10px; }
.stat-inner { display: flex; align-items: center; gap: 14px; }
.stat-icon { width: 52px; height: 52px; border-radius: 12px; display: flex; align-items: center; justify-content: center; }
.stat-value { font-size: 26px; font-weight: 700; line-height: 1.2; }
.stat-title { font-size: 13px; color: var(--el-text-color-secondary); }
</style>
